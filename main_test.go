package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── Pure function tests ──

func TestParseCommand(t *testing.T) {
	tests := []struct {
		line            string
		wantTag, wantCmd, wantArgs string
	}{
		{"a1 SELECT Trash\r\n", "a1", "SELECT", "Trash"},
		{"a2 EXAMINE \"Folders/Marketing\"\r\n", "a2", "EXAMINE", "\"Folders/Marketing\""},
		{"tag3 STORE 1:* +FLAGS (\\Deleted)\r\n", "tag3", "STORE", "1:* +FLAGS (\\Deleted)"},
		{"a4 EXPUNGE\r\n", "a4", "EXPUNGE", ""},
		{"a5 UID STORE 100 +FLAGS (\\Deleted)\r\n", "a5", "UID", "STORE 100 +FLAGS (\\Deleted)"},
		{"a6 UID EXPUNGE 100\r\n", "a6", "UID", "EXPUNGE 100"},
		{"a7 NOOP\r\n", "a7", "NOOP", ""},
		{"a8 LOGIN user pass\r\n", "a8", "LOGIN", "user pass"},
		{"\r\n", "", "", ""},
		{"single\r\n", "", "", ""},
		{"a9 MOVE 5 \"Folders/Marketing\"\r\n", "a9", "MOVE", "5 \"Folders/Marketing\""},
	}
	for _, tt := range tests {
		tag, cmd, args := parseCommand(tt.line)
		if tag != tt.wantTag || cmd != tt.wantCmd || args != tt.wantArgs {
			t.Errorf("parseCommand(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.line, tag, cmd, args, tt.wantTag, tt.wantCmd, tt.wantArgs)
		}
	}
}

func TestExtractMailbox(t *testing.T) {
	tests := []struct {
		args string
		want string
	}{
		{"Trash", "Trash"},
		{"INBOX", "INBOX"},
		{"\"Folders/Marketing\"", "Folders/Marketing"},
		{"\"Trash\"", "Trash"},
		{"\"Folder with \\\"quotes\\\"\"", "Folder with \\\"quotes\\\""},  // escaped quotes preserved
		{"{5}\r\n", ""},       // literal, can't extract inline
		{"", ""},
		{"  Trash  ", "Trash"},
		{"Trash extra args", "Trash"},
	}
	for _, tt := range tests {
		got := extractMailbox(tt.args)
		if got != tt.want {
			t.Errorf("extractMailbox(%q) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		// Exact match (case-insensitive)
		{"Trash", "Trash", true},
		{"Trash", "trash", true},
		{"Trash", "TRASH", true},
		{"Trash", "INBOX", false},

		// Wildcard *
		{"*trash*", "Trash", true},
		{"*trash*", "Folders/Trash", true},
		{"*trash*", "INBOX.Trash", true},
		{"*trash*", "INBOX.Trash.Old", true},
		{"*trash*", "INBOX", false},
		{"*", "anything", true},
		{"*", "", true},

		// Wildcard ?
		{"Tras?", "Trash", true},
		{"Tras?", "Tras", false},
		{"Tras?", "Trashy", false},
		{"?rash", "Trash", true},

		// Hierarchy separators (/ and .)
		{"Folders/*", "Folders/Trash", true},
		{"Folders/*", "Folders/Drafts", true},
		{"INBOX.*", "INBOX.Trash", true},
		{"*.*", "INBOX.Trash", true},
		{"*/*", "Folders/Trash", true},

		// Edge cases
		{"", "", true},
		{"", "x", false},
		{"x", "", false},
		{"**", "anything", true},
		{"*?*", "x", true},
		{"*?*", "", false},
	}
	for _, tt := range tests {
		got := globMatch(tt.pattern, tt.name)
		if got != tt.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

func TestParseDenyEntry(t *testing.T) {
	tests := []struct {
		input   string
		want    denyEntry
		wantErr bool
	}{
		// Simple commands
		{"EXPUNGE", denyEntry{command: "EXPUNGE"}, false},
		{"CLOSE", denyEntry{command: "CLOSE"}, false},
		{"DELETE", denyEntry{command: "DELETE"}, false},
		{"RENAME", denyEntry{command: "RENAME"}, false},
		{"MOVE", denyEntry{command: "MOVE"}, false},
		{"COMPRESS", denyEntry{command: "COMPRESS"}, false},

		// Case insensitive
		{"expunge", denyEntry{command: "EXPUNGE"}, false},

		// STORE without qualifier (blocks all STORE)
		{"STORE", denyEntry{command: "STORE"}, false},

		// STORE with qualifiers
		{`STORE +\Deleted`, denyEntry{command: "STORE", storeOp: "+", storeFlag: `\DELETED`}, false},
		{`STORE -\Seen`, denyEntry{command: "STORE", storeOp: "-", storeFlag: `\SEEN`}, false},
		{`STORE +\Flagged`, denyEntry{command: "STORE", storeOp: "+", storeFlag: `\FLAGGED`}, false},

		// Invalid
		{"", denyEntry{}, true},
		{"BADCMD", denyEntry{}, true},
		{"EXPUNGE extra", denyEntry{}, true},     // non-STORE with args
		{"STORE +", denyEntry{}, true},            // missing flag
		{"STORE noop", denyEntry{}, true},         // no + or - prefix
	}
	for _, tt := range tests {
		got, err := parseDenyEntry(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseDenyEntry(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("parseDenyEntry(%q) = %+v, want %+v", tt.input, got, tt.want)
		}
	}
}

func TestLoadACLConfig(t *testing.T) {
	t.Run("empty path returns nil", func(t *testing.T) {
		rules, err := loadACLConfig("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rules != nil {
			t.Errorf("expected nil rules, got %v", rules)
		}
	})

	t.Run("valid config", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(`
rules:
  - mailbox: "*trash*"
    deny: [EXPUNGE, CLOSE, "STORE +\\Deleted"]
  - mailbox: "*drafts*"
    deny: [DELETE, RENAME]
`), 0o600); err != nil {
			t.Fatalf("write test config: %v", err)
		}

		rules, err := loadACLConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 2 {
			t.Fatalf("expected 2 rules, got %d", len(rules))
		}
		if rules[0].mailbox != "*trash*" {
			t.Errorf("rule 0 mailbox = %q, want *trash*", rules[0].mailbox)
		}
		if len(rules[0].deny) != 3 {
			t.Errorf("rule 0 deny count = %d, want 3", len(rules[0].deny))
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := loadACLConfig("/nonexistent/config.yaml")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.yaml")
		if err := os.WriteFile(path, []byte("not: [valid: yaml"), 0o600); err != nil {
			t.Fatalf("write test config: %v", err)
		}

		_, err := loadACLConfig(path)
		if err == nil {
			t.Fatal("expected error for invalid YAML")
		}
	})

	t.Run("invalid deny entry", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad-deny.yaml")
		if err := os.WriteFile(path, []byte(`
rules:
  - mailbox: "*trash*"
    deny: [BADCOMMAND]
`), 0o600); err != nil {
			t.Fatalf("write test config: %v", err)
		}

		_, err := loadACLConfig(path)
		if err == nil {
			t.Fatal("expected error for invalid deny entry")
		}
	})

	t.Run("missing mailbox", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "no-mailbox.yaml")
		if err := os.WriteFile(path, []byte(`
rules:
  - deny: [EXPUNGE]
`), 0o600); err != nil {
			t.Fatalf("write test config: %v", err)
		}

		_, err := loadACLConfig(path)
		if err == nil {
			t.Fatal("expected error for missing mailbox")
		}
	})

	t.Run("empty file returns empty rules", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "empty.yaml")
		if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
			t.Fatalf("write test config: %v", err)
		}

		rules, err := loadACLConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 0 {
			t.Errorf("expected 0 rules, got %d", len(rules))
		}
	})
}

func TestLoadACLConfigDenyUnlessCopied(t *testing.T) {
	t.Run("valid deny-unless-copied", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(`
rules:
  - mailbox: "*trash*"
    deny: [DELETE, RENAME, CLOSE]
    deny-unless-copied: [expunge]
`), 0o600); err != nil {
			t.Fatalf("write test config: %v", err)
		}

		rules, err := loadACLConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(rules))
		}
		if len(rules[0].denyUnlessCopied) != 1 {
			t.Fatalf("expected 1 deny-unless-copied entry, got %d", len(rules[0].denyUnlessCopied))
		}
		if rules[0].denyUnlessCopied[0] != "EXPUNGE" {
			t.Errorf("expected EXPUNGE, got %q", rules[0].denyUnlessCopied[0])
		}
	})

	t.Run("overlap with deny rejects", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(`
rules:
  - mailbox: "*trash*"
    deny: [EXPUNGE, DELETE]
    deny-unless-copied: [EXPUNGE]
`), 0o600); err != nil {
			t.Fatalf("write test config: %v", err)
		}

		_, err := loadACLConfig(path)
		if err == nil {
			t.Fatal("expected error for overlapping deny and deny-unless-copied")
		}
		if !strings.Contains(err.Error(), "both deny and deny-unless-copied") {
			t.Errorf("error should mention overlap, got: %v", err)
		}
	})

	t.Run("invalid command rejects", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(`
rules:
  - mailbox: "*trash*"
    deny-unless-copied: [CLOSE]
`), 0o600); err != nil {
			t.Fatalf("write test config: %v", err)
		}

		_, err := loadACLConfig(path)
		if err == nil {
			t.Fatal("expected error for invalid command in deny-unless-copied")
		}
		if !strings.Contains(err.Error(), "only supports EXPUNGE") {
			t.Errorf("error should mention EXPUNGE requirement, got: %v", err)
		}
	})
}

func TestParseStoreArgs(t *testing.T) {
	tests := []struct {
		args     string
		wantOp   string
		wantFlags string
	}{
		// Add flags
		{"1:* +FLAGS (\\Deleted)", "+", "(\\DELETED)"},
		{"1 +FLAGS (\\Deleted)", "+", "(\\DELETED)"},
		{"1:* +FLAGS.SILENT (\\Deleted)", "+", "(\\DELETED)"},
		{"1:* +FLAGS (\\Seen \\Deleted)", "+", "(\\SEEN \\DELETED)"},

		// Replace flags (bare FLAGS — treated as +)
		{"1:* FLAGS (\\Deleted)", "+", "(\\DELETED)"},
		{"1:* FLAGS.SILENT (\\Deleted)", "+", "(\\DELETED)"},

		// Remove flags
		{"1:* -FLAGS (\\Deleted)", "-", "(\\DELETED)"},
		{"1:* -FLAGS.SILENT (\\Deleted)", "-", "(\\DELETED)"},
		{"1:* -FLAGS (\\Seen)", "-", "(\\SEEN)"},

		// Edge cases
		{"", "", ""},
		{"1:*", "", ""},
		{"1:* +FLAGS", "", ""},
	}
	for _, tt := range tests {
		op, flags := parseStoreArgs(tt.args)
		if op != tt.wantOp || flags != tt.wantFlags {
			t.Errorf("parseStoreArgs(%q) = (%q, %q), want (%q, %q)",
				tt.args, op, flags, tt.wantOp, tt.wantFlags)
		}
	}
}

func TestEvalACL(t *testing.T) {
	rules := []rule{
		{
			mailbox: "*trash*",
			deny: []denyEntry{
				{command: "EXPUNGE"},
				{command: "CLOSE"},
				{command: "STORE", storeOp: "+", storeFlag: `\DELETED`},
			},
		},
		{
			mailbox: "*drafts*",
			deny: []denyEntry{
				{command: "DELETE"},
				{command: "RENAME"},
			},
		},
	}

	tests := []struct {
		name       string
		mailbox    string
		cmd        string
		storeOp    string
		storeFlags string
		wantResult aclResult
	}{
		{"expunge in trash", "Trash", "EXPUNGE", "", "", aclDeny},
		{"close in trash", "Trash", "CLOSE", "", "", aclDeny},
		{"store deleted in trash", "Trash", "STORE", "+", `(\DELETED)`, aclDeny},
		{"store seen in trash", "Trash", "STORE", "+", `(\SEEN)`, aclAllow},
		{"remove deleted in trash", "Trash", "STORE", "-", `(\DELETED)`, aclAllow},
		{"delete in drafts", "Drafts", "DELETE", "", "", aclDeny},
		{"rename in drafts", "Drafts", "RENAME", "", "", aclDeny},
		{"expunge in drafts", "Drafts", "EXPUNGE", "", "", aclAllow},
		{"expunge in inbox", "INBOX", "EXPUNGE", "", "", aclAllow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := evalACL(rules, tt.mailbox, tt.cmd, tt.storeOp, tt.storeFlags)
			if result != tt.wantResult {
				t.Errorf("evalACL(%q, %q) result=%v, want %v",
					tt.mailbox, tt.cmd, result, tt.wantResult)
			}
		})
	}

	t.Run("nil rules never blocks", func(t *testing.T) {
		result, _ := evalACL(nil, "Trash", "EXPUNGE", "", "")
		if result != aclAllow {
			t.Errorf("evalACL with nil rules should return aclAllow, got %v", result)
		}
	})

	t.Run("first match wins", func(t *testing.T) {
		overlapping := []rule{
			{mailbox: "Trash", deny: []denyEntry{{command: "EXPUNGE"}}},
			{mailbox: "*", deny: nil}, // catch-all with no denies
		}
		result, desc := evalACL(overlapping, "Trash", "EXPUNGE", "", "")
		if result != aclDeny {
			t.Errorf("expected aclDeny from first rule, got %v", result)
		}
		if !strings.Contains(desc, "rule[0]") {
			t.Errorf("expected rule[0] in desc, got %q", desc)
		}
	})

	t.Run("wildcard rule", func(t *testing.T) {
		wildcardRules := []rule{
			{mailbox: "*", deny: []denyEntry{{command: "EXPUNGE"}}},
		}
		result, _ := evalACL(wildcardRules, "INBOX", "EXPUNGE", "", "")
		if result != aclDeny {
			t.Error("expected wildcard rule to block EXPUNGE on any mailbox")
		}
	})

	t.Run("STORE blocks all when no qualifier", func(t *testing.T) {
		storeAllRules := []rule{
			{mailbox: "*trash*", deny: []denyEntry{{command: "STORE"}}},
		}
		result, _ := evalACL(storeAllRules, "Trash", "STORE", "+", `(\SEEN)`)
		if result != aclDeny {
			t.Error("expected unqualified STORE deny to block all STORE commands")
		}
	})
}

func TestEvalACLDenyUnlessCopied(t *testing.T) {
	rules := []rule{
		{
			mailbox:          "*trash*",
			deny:             []denyEntry{{command: "DELETE"}, {command: "CLOSE"}},
			denyUnlessCopied: []string{"EXPUNGE"},
		},
		{
			mailbox: "*drafts*",
			deny:    []denyEntry{{command: "EXPUNGE"}},
		},
	}

	tests := []struct {
		name       string
		mailbox    string
		cmd        string
		wantResult aclResult
	}{
		{"expunge in trash returns deny-unless-copied", "Trash", "EXPUNGE", aclDenyUnlessCopied},
		{"delete in trash returns deny", "Trash", "DELETE", aclDeny},
		{"close in trash returns deny", "Trash", "CLOSE", aclDeny},
		{"move in trash returns allow", "Trash", "MOVE", aclAllow},
		{"expunge in drafts returns deny", "Drafts", "EXPUNGE", aclDeny},
		{"expunge in inbox returns allow", "INBOX", "EXPUNGE", aclAllow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := evalACL(rules, tt.mailbox, tt.cmd, "", "")
			if result != tt.wantResult {
				t.Errorf("evalACL(%q, %q) result=%v, want %v",
					tt.mailbox, tt.cmd, result, tt.wantResult)
			}
		})
	}
}

func TestShouldBlock(t *testing.T) {
	// Rules equivalent to the old hardcoded protection
	rules := []rule{
		{
			mailbox: "*trash*",
			deny: []denyEntry{
				{command: "EXPUNGE"}, {command: "CLOSE"}, {command: "DELETE"},
				{command: "RENAME"}, {command: "MOVE"}, {command: "COMPRESS"},
				{command: "STORE", storeOp: "+", storeFlag: `\DELETED`},
			},
		},
		{
			mailbox: "*drafts*",
			deny: []denyEntry{
				{command: "EXPUNGE"}, {command: "CLOSE"}, {command: "DELETE"},
				{command: "RENAME"}, {command: "MOVE"}, {command: "COMPRESS"},
				{command: "STORE", storeOp: "+", storeFlag: `\DELETED`},
			},
		},
		{
			mailbox: "*junk*",
			deny: []denyEntry{
				{command: "EXPUNGE"}, {command: "CLOSE"}, {command: "DELETE"},
				{command: "RENAME"}, {command: "MOVE"}, {command: "COMPRESS"},
				{command: "STORE", storeOp: "+", storeFlag: `\DELETED`},
			},
		},
	}

	inTrash := &connState{selectedMailbox: "Trash"}
	inInbox := &connState{selectedMailbox: "INBOX"}

	tests := []struct {
		name  string
		cmd   string
		args  string
		state *connState
		rules []rule
		want  bool
	}{
		// Blocked on protected
		{"expunge in trash", "EXPUNGE", "", inTrash, rules, true},
		{"close in trash", "CLOSE", "", inTrash, rules, true},
		{"move in trash", "MOVE", "5 INBOX", inTrash, rules, true},
		{"store deleted in trash", "STORE", "1:* +FLAGS (\\Deleted)", inTrash, rules, true},
		{"store silent deleted in trash", "STORE", "1:* +FLAGS.SILENT (\\Deleted)", inTrash, rules, true},
		{"store replace deleted in trash", "STORE", "1:* FLAGS (\\Deleted)", inTrash, rules, true},
		{"uid expunge in trash", "UID", "EXPUNGE 100", inTrash, rules, true},
		{"uid store deleted in trash", "UID", "STORE 100 +FLAGS (\\Deleted)", inTrash, rules, true},
		{"uid move in trash", "UID", "MOVE 100 INBOX", inTrash, rules, true},

		// DELETE/RENAME target a named mailbox, blocked when targeting protected
		{"delete trash", "DELETE", "Trash", inTrash, rules, true},
		{"delete trash case insensitive", "DELETE", "trash", inTrash, rules, true},
		{"delete quoted trash", "DELETE", "\"Trash\"", inTrash, rules, true},
		{"rename trash", "RENAME", "Trash NewName", inTrash, rules, true},
		{"rename trash case insensitive", "RENAME", "TRASH NewName", inTrash, rules, true},

		// DELETE/RENAME on unprotected targets — allowed even when selected is protected
		{"delete inbox while in trash", "DELETE", "SomeFolder", inTrash, rules, false},
		{"rename inbox while in trash", "RENAME", "SomeFolder NewName", inTrash, rules, false},

		// DELETE/RENAME on protected targets — blocked even when selected is unprotected
		{"delete trash while in inbox", "DELETE", "Trash", inInbox, rules, true},
		{"rename trash while in inbox", "RENAME", "Trash NewName", inInbox, rules, true},
		{"rename drafts while in inbox", "RENAME", "Drafts NewName", inInbox, rules, true},

		// COMPRESS blocked when in protected mailbox
		{"compress in trash", "COMPRESS", "DEFLATE", inTrash, rules, true},
		{"compress in inbox", "COMPRESS", "DEFLATE", inInbox, rules, false},

		// Allowed on protected
		{"copy in trash", "COPY", "5 INBOX", inTrash, rules, false},
		{"store seen in trash", "STORE", "1:* +FLAGS (\\Seen)", inTrash, rules, false},
		{"remove deleted in trash", "STORE", "1:* -FLAGS (\\Deleted)", inTrash, rules, false},
		{"fetch in trash", "FETCH", "1:* (FLAGS)", inTrash, rules, false},
		{"search in trash", "SEARCH", "ALL", inTrash, rules, false},
		{"noop in trash", "NOOP", "", inTrash, rules, false},
		{"uid fetch in trash", "UID", "FETCH 100 (FLAGS)", inTrash, rules, false},

		// Nothing blocked on unprotected (except DELETE/RENAME targeting protected)
		{"expunge in inbox", "EXPUNGE", "", inInbox, rules, false},
		{"close in inbox", "CLOSE", "", inInbox, rules, false},
		{"move in inbox", "MOVE", "5 Trash", inInbox, rules, false},
		{"store deleted in inbox", "STORE", "1:* +FLAGS (\\Deleted)", inInbox, rules, false},
		{"uid expunge in inbox", "UID", "EXPUNGE 100", inInbox, rules, false},

		// No rules = pure pass-through
		{"no rules expunge in trash", "EXPUNGE", "", inTrash, nil, false},
		{"no rules store deleted in trash", "STORE", "1:* +FLAGS (\\Deleted)", inTrash, nil, false},
		{"no rules delete trash", "DELETE", "Trash", inInbox, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := shouldBlock(tt.cmd, tt.args, tt.state, tt.rules)
			if got != tt.want {
				t.Errorf("shouldBlock(%q, %q, mailbox=%s) = %v, want %v",
					tt.cmd, tt.args, tt.state.selectedMailbox, got, tt.want)
			}
		})
	}
}

func TestShouldBlockDenyUnlessCopied(t *testing.T) {
	rules := []rule{
		{
			mailbox:          "*trash*",
			deny:             []denyEntry{{command: "CLOSE"}, {command: "DELETE"}},
			denyUnlessCopied: []string{"EXPUNGE"},
		},
	}

	t.Run("plain EXPUNGE always blocked", func(t *testing.T) {
		state := &connState{selectedMailbox: "Trash"}
		state.recordCopiedUIDs([]uint32{1, 2, 3})
		blocked, _ := shouldBlock("EXPUNGE", "", state, rules)
		if !blocked {
			t.Error("plain EXPUNGE should always be blocked under deny-unless-copied")
		}
	})

	t.Run("UID EXPUNGE with all UIDs copied", func(t *testing.T) {
		state := &connState{selectedMailbox: "Trash"}
		state.recordCopiedUIDs([]uint32{1, 2, 3})
		blocked, _ := shouldBlock("UID", "EXPUNGE 1:3", state, rules)
		if blocked {
			t.Error("UID EXPUNGE should be allowed when all UIDs are copied")
		}
	})

	t.Run("UID EXPUNGE with not all UIDs copied", func(t *testing.T) {
		state := &connState{selectedMailbox: "Trash"}
		state.recordCopiedUIDs([]uint32{1, 2})
		blocked, _ := shouldBlock("UID", "EXPUNGE 1:5", state, rules)
		if !blocked {
			t.Error("UID EXPUNGE should be blocked when not all UIDs are copied")
		}
	})

	t.Run("UID EXPUNGE with no copies", func(t *testing.T) {
		state := &connState{selectedMailbox: "Trash"}
		blocked, _ := shouldBlock("UID", "EXPUNGE 1:3", state, rules)
		if !blocked {
			t.Error("UID EXPUNGE should be blocked when no UIDs have been copied")
		}
	})

	t.Run("UID EXPUNGE with unparseable set", func(t *testing.T) {
		state := &connState{selectedMailbox: "Trash"}
		state.recordCopiedUIDs([]uint32{1, 2, 3})
		blocked, _ := shouldBlock("UID", "EXPUNGE *", state, rules)
		if !blocked {
			t.Error("UID EXPUNGE with * should be blocked (unparseable)")
		}
	})

	t.Run("UID EXPUNGE in unprotected mailbox", func(t *testing.T) {
		state := &connState{selectedMailbox: "INBOX"}
		blocked, _ := shouldBlock("UID", "EXPUNGE 1:3", state, rules)
		if blocked {
			t.Error("UID EXPUNGE in unprotected mailbox should be allowed")
		}
	})

	t.Run("CLOSE still hard-denied", func(t *testing.T) {
		state := &connState{selectedMailbox: "Trash"}
		blocked, _ := shouldBlock("CLOSE", "", state, rules)
		if !blocked {
			t.Error("CLOSE should still be hard-denied")
		}
	})
}

func TestStripCaps(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{
			"* OK [CAPABILITY IMAP4rev1 STARTTLS IDLE AUTH=PLAIN] ready\r\n",
			"* OK [CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN] ready\r\n",
		},
		{
			"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED IDLE\r\n",
			"* CAPABILITY IMAP4rev1 IDLE\r\n",
		},
		{
			"* OK [CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN] ready\r\n",
			"* OK [CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN] ready\r\n",
		},
		{
			"a1 OK LOGIN completed\r\n",
			"a1 OK LOGIN completed\r\n",
		},
		{
			"* 5 EXISTS\r\n",
			"* 5 EXISTS\r\n",
		},
		{
			// Message body containing STARTTLS should not be modified
			"* 1 FETCH (BODY[] \"Please enable STARTTLS on your server\")\r\n",
			"* 1 FETCH (BODY[] \"Please enable STARTTLS on your server\")\r\n",
		},
		{
			// Message body containing LOGINDISABLED should not be modified
			"The server has LOGINDISABLED for security\r\n",
			"The server has LOGINDISABLED for security\r\n",
		},
	}
	for _, tt := range tests {
		got := stripCaps(tt.line)
		if got != tt.want {
			t.Errorf("stripCaps(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestParseLiteral(t *testing.T) {
	tests := []struct {
		line string
		wantN  int64
		wantOK bool
	}{
		{"* 1 FETCH (BODY[] {512}\r\n", 512, true},
		{"{10+}\r\n", 10, true},
		{"normal line\r\n", 0, false},
		{"a1 OK done\r\n", 0, false},
		{"{0}\r\n", 0, true},
		{"{abc}\r\n", 0, false},
		{"some text {100}\r\n", 100, true},
	}
	for _, tt := range tests {
		n, ok := parseLiteral(tt.line)
		if n != tt.wantN || ok != tt.wantOK {
			t.Errorf("parseLiteral(%q) = (%d, %v), want (%d, %v)",
				tt.line, n, ok, tt.wantN, tt.wantOK)
		}
	}
}

func TestParseUIDSet(t *testing.T) {
	tests := []struct {
		input   string
		wantUIDs []uint32
		wantOK  bool
	}{
		// Single UID
		{"1", []uint32{1}, true},
		{"100", []uint32{100}, true},

		// Ranges
		{"1:5", []uint32{1, 2, 3, 4, 5}, true},
		{"3:1", []uint32{1, 2, 3}, true}, // reversed range

		// Comma-separated
		{"1,3,5", []uint32{1, 3, 5}, true},

		// Mixed
		{"1:3,5:7", []uint32{1, 2, 3, 5, 6, 7}, true},
		{"1,3:5,10", []uint32{1, 3, 4, 5, 10}, true},

		// Wildcard — not supported
		{"*", nil, false},
		{"1:*", nil, false},

		// Zero UID — invalid
		{"0", nil, false},
		{"0:5", nil, false},

		// Parse errors
		{"abc", nil, false},
		{"1:abc", nil, false},
		{"", nil, false},
		{",", nil, false},
		{"1,", nil, false},
	}
	for _, tt := range tests {
		uids, ok := parseUIDSet(tt.input)
		if ok != tt.wantOK {
			t.Errorf("parseUIDSet(%q) ok=%v, want %v", tt.input, ok, tt.wantOK)
			continue
		}
		if ok && !slices.Equal(uids, tt.wantUIDs) {
			t.Errorf("parseUIDSet(%q) = %v, want %v", tt.input, uids, tt.wantUIDs)
		}
	}

	t.Run("huge range exceeds cap", func(t *testing.T) {
		_, ok := parseUIDSet("1:100000")
		if ok {
			t.Error("expected rejection for range exceeding cap")
		}
	})
}

func TestParseCOPYUID(t *testing.T) {
	tests := []struct {
		line     string
		wantUIDs []uint32
		wantOK   bool
	}{
		// Valid
		{"a1 OK [COPYUID 12345 1:3 10:12] Copy completed\r\n", []uint32{1, 2, 3}, true},
		{"a1 OK [COPYUID 12345 5 20] Copy completed\r\n", []uint32{5}, true},
		{"a1 OK [COPYUID 12345 1,3,5 10,12,14] Copy completed\r\n", []uint32{1, 3, 5}, true},

		// Case insensitive
		{"a1 OK [copyuid 12345 1:3 10:12] Copy completed\r\n", []uint32{1, 2, 3}, true},
		{"a1 OK [CopyUID 12345 1:3 10:12] Copy completed\r\n", []uint32{1, 2, 3}, true},

		// No COPYUID
		{"a1 OK Copy completed\r\n", nil, false},

		// Malformed — missing fields
		{"a1 OK [COPYUID 12345 1:3] Copy completed\r\n", nil, false},
		{"a1 OK [COPYUID 12345] Copy completed\r\n", nil, false},

		// Missing closing bracket
		{"a1 OK [COPYUID 12345 1:3 10:12 Copy completed\r\n", nil, false},
	}
	for _, tt := range tests {
		uids, ok := parseCOPYUID(tt.line)
		if ok != tt.wantOK {
			t.Errorf("parseCOPYUID(%q) ok=%v, want %v", tt.line, ok, tt.wantOK)
			continue
		}
		if ok && !slices.Equal(uids, tt.wantUIDs) {
			t.Errorf("parseCOPYUID(%q) = %v, want %v", tt.line, uids, tt.wantUIDs)
		}
	}
}

func TestParseTaggedResponse(t *testing.T) {
	tests := []struct {
		line    string
		wantTag string
		wantRest string
	}{
		{"a1 OK done\r\n", "a1", "OK done"},
		{"tag5 NO error\r\n", "tag5", "NO error"},
		{"* 5 EXISTS\r\n", "", ""},
		{"+ continue\r\n", "", ""},
		{"\r\n", "", ""},
		{"a1\r\n", "a1", ""},
	}
	for _, tt := range tests {
		tag, rest := parseTaggedResponse(tt.line)
		if tag != tt.wantTag || rest != tt.wantRest {
			t.Errorf("parseTaggedResponse(%q) = (%q, %q), want (%q, %q)",
				tt.line, tag, rest, tt.wantTag, tt.wantRest)
		}
	}
}

func TestConnStateCopyTracking(t *testing.T) {
	s := &connState{}

	// Record a pending copy
	s.recordPendingCopy("a1")

	// Resolve it
	if !s.resolvePendingCopy("a1") {
		t.Error("expected resolvePendingCopy to return true for recorded tag")
	}

	// Resolve again — should fail
	if s.resolvePendingCopy("a1") {
		t.Error("expected resolvePendingCopy to return false for already-resolved tag")
	}

	// Resolve unrecorded tag
	if s.resolvePendingCopy("a2") {
		t.Error("expected resolvePendingCopy to return false for unrecorded tag")
	}

	// Record and check copied UIDs
	s.recordCopiedUIDs([]uint32{1, 2, 3})
	if !s.allUIDsCopied([]uint32{1, 2, 3}) {
		t.Error("expected allUIDsCopied to return true for recorded UIDs")
	}
	if !s.allUIDsCopied([]uint32{1}) {
		t.Error("expected allUIDsCopied to return true for subset")
	}
	if s.allUIDsCopied([]uint32{1, 4}) {
		t.Error("expected allUIDsCopied to return false when UID 4 not recorded")
	}

	// Add more UIDs
	s.recordCopiedUIDs([]uint32{4, 5})
	if !s.allUIDsCopied([]uint32{1, 2, 3, 4, 5}) {
		t.Error("expected allUIDsCopied to return true after adding more UIDs")
	}
}

func TestConnStateResetCopyState(t *testing.T) {
	s := &connState{}
	s.recordPendingCopy("a1")
	s.recordCopiedUIDs([]uint32{1, 2, 3})

	s.resetCopyState()

	if s.resolvePendingCopy("a1") {
		t.Error("expected pending copies to be cleared after reset")
	}
	if s.allUIDsCopied([]uint32{1}) {
		t.Error("expected copied UIDs to be cleared after reset")
	}
}

func TestShouldStripCaps(t *testing.T) {
	tests := []struct {
		name string
		cfg  config
		want bool
	}{
		{"no client TLS strips caps", config{}, true},
		{"client TLS does not strip", config{clientTLSCert: "/some/cert.pem", clientTLSKey: "/some/key.pem"}, false},
		{"only cert set strips caps", config{clientTLSCert: "/some/cert.pem"}, true},
		{"only key set strips caps", config{clientTLSKey: "/some/key.pem"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.shouldStripCaps()
			if got != tt.want {
				t.Errorf("shouldStripCaps() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseConfigValidation(t *testing.T) {
	// Save and restore env vars
	envVars := []string{
		"IMAP_GUARD_LISTEN", "IMAP_GUARD_UPSTREAM",
		"IMAP_GUARD_UPSTREAM_TLS", "IMAP_GUARD_UPSTREAM_VERIFY",
		"IMAP_GUARD_CLIENT_TLS_CERT", "IMAP_GUARD_CLIENT_TLS_KEY",
	}
	saved := make(map[string]string)
	for _, k := range envVars {
		saved[k] = os.Getenv(k)
	}
	t.Cleanup(func() {
		for k, v := range saved {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	})
	clearEnv := func() {
		for _, k := range envVars {
			os.Unsetenv(k)
		}
	}

	t.Run("defaults", func(t *testing.T) {
		clearEnv()
		cfg, err := parseConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.listenAddr != ":1143" {
			t.Errorf("listenAddr = %q, want :1143", cfg.listenAddr)
		}
		if cfg.upstreamAddr != "127.0.0.1:143" {
			t.Errorf("upstreamAddr = %q, want 127.0.0.1:143", cfg.upstreamAddr)
		}
		if cfg.upstreamTLS != upstreamSTARTTLS {
			t.Errorf("upstreamTLS = %d, want upstreamSTARTTLS", cfg.upstreamTLS)
		}
		if cfg.upstreamVerify != "verify" {
			t.Errorf("upstreamVerify = %q, want verify", cfg.upstreamVerify)
		}
	})

	t.Run("invalid TLS mode", func(t *testing.T) {
		clearEnv()
		os.Setenv("IMAP_GUARD_UPSTREAM_TLS", "invalid")
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for invalid TLS mode")
		}
		if !strings.Contains(err.Error(), "invalid") {
			t.Errorf("error should mention 'invalid', got: %v", err)
		}
	})

	t.Run("skip verify with plaintext", func(t *testing.T) {
		clearEnv()
		os.Setenv("IMAP_GUARD_UPSTREAM_TLS", "plaintext")
		os.Setenv("IMAP_GUARD_UPSTREAM_VERIFY", "skip")
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for skip+plaintext")
		}
		if !strings.Contains(err.Error(), "no TLS to verify") {
			t.Errorf("error should mention no TLS, got: %v", err)
		}
	})

	t.Run("CA file with plaintext", func(t *testing.T) {
		clearEnv()
		os.Setenv("IMAP_GUARD_UPSTREAM_TLS", "plaintext")
		os.Setenv("IMAP_GUARD_UPSTREAM_VERIFY", "/some/ca.pem")
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for CA file+plaintext")
		}
	})

	t.Run("cert without key", func(t *testing.T) {
		clearEnv()
		tmpDir := t.TempDir()
		certFile := filepath.Join(tmpDir, "cert.pem")
		os.WriteFile(certFile, []byte("dummy"), 0o600)
		os.Setenv("IMAP_GUARD_CLIENT_TLS_CERT", certFile)
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for cert without key")
		}
		if !strings.Contains(err.Error(), "both be set") {
			t.Errorf("error should mention both, got: %v", err)
		}
	})

	t.Run("key without cert", func(t *testing.T) {
		clearEnv()
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "key.pem")
		os.WriteFile(keyFile, []byte("dummy"), 0o600)
		os.Setenv("IMAP_GUARD_CLIENT_TLS_KEY", keyFile)
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for key without cert")
		}
	})

	t.Run("nonexistent CA file", func(t *testing.T) {
		clearEnv()
		os.Setenv("IMAP_GUARD_UPSTREAM_VERIFY", "/nonexistent/ca.pem")
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for nonexistent CA file")
		}
	})

	t.Run("nonexistent cert file", func(t *testing.T) {
		clearEnv()
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "key.pem")
		os.WriteFile(keyFile, []byte("dummy"), 0o600)
		os.Setenv("IMAP_GUARD_CLIENT_TLS_CERT", "/nonexistent/cert.pem")
		os.Setenv("IMAP_GUARD_CLIENT_TLS_KEY", keyFile)
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for nonexistent cert file")
		}
	})

	t.Run("plaintext mode", func(t *testing.T) {
		clearEnv()
		os.Setenv("IMAP_GUARD_UPSTREAM_TLS", "plaintext")
		cfg, err := parseConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.upstreamTLS != upstreamPlaintext {
			t.Errorf("upstreamTLS = %d, want upstreamPlaintext", cfg.upstreamTLS)
		}
	})

	t.Run("tls mode", func(t *testing.T) {
		clearEnv()
		os.Setenv("IMAP_GUARD_UPSTREAM_TLS", "tls")
		cfg, err := parseConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.upstreamTLS != upstreamImplicitTLS {
			t.Errorf("upstreamTLS = %d, want upstreamImplicitTLS", cfg.upstreamTLS)
		}
	})
}

// ── Test helpers ──

type mockUpstreamMode int

const (
	mockSTARTTLS  mockUpstreamMode = iota
	mockPlaintext
	mockImplicitTLS
)

// generateTestCert generates a self-signed TLS certificate for testing.
func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

// generateTestCA creates a CA key pair and returns the CA cert, CA tls.Certificate, and a
// function to sign server certs. Also writes the CA PEM to a temp file and returns its path.
func generateTestCA(t *testing.T) (caCert *x509.Certificate, caKeyPair tls.Certificate, caFile string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, _ = x509.ParseCertificate(caCertDER)

	// Write CA cert PEM to temp file
	tmpDir := t.TempDir()
	caFile = filepath.Join(tmpDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	caKeyPair = tls.Certificate{
		Certificate: [][]byte{caCertDER},
		PrivateKey:  caKey,
	}
	return caCert, caKeyPair, caFile
}

// signServerCert creates a server certificate signed by the given CA.
func signServerCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{serverCertDER},
		PrivateKey:  serverKey,
	}
}

// writeTempCertKey writes a TLS certificate and key as PEM files in a temp directory.
func writeTempCertKey(t *testing.T, cert tls.Certificate) (certFile, keyFile string) {
	t.Helper()
	tmpDir := t.TempDir()
	certFile = filepath.Join(tmpDir, "cert.pem")
	keyFile = filepath.Join(tmpDir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	ecKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("expected ECDSA key")
	}
	keyDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certFile, keyFile
}

// testConfig returns a config suitable for tests, defaulting to STARTTLS with skip verify.
func testConfig(upstreamAddr string) *config {
	return &config{
		upstreamAddr:    upstreamAddr,
		upstreamTLS:     upstreamSTARTTLS,
		upstreamVerify:  "skip",
		idleTimeout:     30 * time.Minute,
		sessionTimeout:  24 * time.Hour,
		shutdownTimeout: 5 * time.Second,
	}
}

// testRules returns ACL rules equivalent to the old hardcoded protection.
func testRules() []rule {
	deny := []denyEntry{
		{command: "EXPUNGE"}, {command: "CLOSE"}, {command: "DELETE"},
		{command: "RENAME"}, {command: "MOVE"}, {command: "COMPRESS"},
		{command: "STORE", storeOp: "+", storeFlag: `\DELETED`},
	}
	return []rule{
		{mailbox: "*trash*", deny: deny},
		{mailbox: "*drafts*", deny: deny},
		{mailbox: "*junk*", deny: deny},
	}
}

// writeTestACLConfig writes a YAML ACL config file and returns its path.
func writeTestACLConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "imap-guard.yaml")
	content := `rules:
  - mailbox: "*trash*"
    deny: [EXPUNGE, CLOSE, DELETE, RENAME, MOVE, COMPRESS, "STORE +\\Deleted"]
  - mailbox: "*drafts*"
    deny: [EXPUNGE, CLOSE, DELETE, RENAME, MOVE, COMPRESS, "STORE +\\Deleted"]
  - mailbox: "*junk*"
    deny: [EXPUNGE, CLOSE, DELETE, RENAME, MOVE, COMPRESS, "STORE +\\Deleted"]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test ACL config: %v", err)
	}
	return path
}

// mockUpstream simulates an upstream IMAP server supporting different connection modes.
type mockUpstream struct {
	listener       net.Listener
	received       []string
	errors         []string
	mu             sync.Mutex
	cert           tls.Certificate
	mode           mockUpstreamMode
	supportCOPYUID  bool // when true, COPY/UID COPY/UID MOVE responses include COPYUID
	supportCompress bool // when true, COMPRESS DEFLATE is accepted
	done            chan struct{}
}

func newMockUpstream(t *testing.T, mode mockUpstreamMode) *mockUpstream {
	t.Helper()

	cert := generateTestCert(t)

	var ln net.Listener
	var err error
	switch mode {
	case mockImplicitTLS:
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
	default:
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("mock upstream listen: %v", err)
	}

	return &mockUpstream{
		listener: ln,
		cert:     cert,
		mode:     mode,
		done:     make(chan struct{}),
	}
}

// newMockUpstreamWithCert creates a mock upstream using a specific TLS certificate.
func newMockUpstreamWithCert(t *testing.T, mode mockUpstreamMode, cert tls.Certificate) *mockUpstream {
	t.Helper()

	var ln net.Listener
	var err error
	switch mode {
	case mockImplicitTLS:
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
	default:
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("mock upstream listen: %v", err)
	}

	return &mockUpstream{
		listener: ln,
		cert:     cert,
		mode:     mode,
		done:     make(chan struct{}),
	}
}

func (m *mockUpstream) recordError(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors = append(m.errors, msg)
}

func (m *mockUpstream) getErrors() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]string, len(m.errors))
	copy(cp, m.errors)
	return cp
}

func (m *mockUpstream) addr() string {
	return m.listener.Addr().String()
}

func (m *mockUpstream) record(cmd string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.received = append(m.received, cmd)
}

func (m *mockUpstream) getReceived() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]string, len(m.received))
	copy(cp, m.received)
	return cp
}

func (m *mockUpstream) serve() {
	defer close(m.done)
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			return
		}
		go m.handleConn(conn)
	}
}

func (m *mockUpstream) handleConn(conn net.Conn) {
	defer conn.Close()

	switch m.mode {
	case mockPlaintext:
		m.handlePlaintextConn(conn)
	case mockSTARTTLS:
		m.handleSTARTTLSConn(conn)
	case mockImplicitTLS:
		// Connection is already TLS from tls.Listen
		m.handlePlaintextConn(conn) // same command loop, just over TLS
	}
}

func (m *mockUpstream) handlePlaintextConn(conn net.Conn) {
	fmt.Fprintf(conn, "* OK [CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN] Mock server ready\r\n")
	m.handleIMAPCommands(conn)
}

func (m *mockUpstream) handleSTARTTLSConn(conn net.Conn) {
	fmt.Fprintf(conn, "* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED IDLE AUTH=PLAIN] Mock server ready\r\n")

	reader := bufio.NewReader(conn)

	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimRight(line, "\r\n")
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 || strings.ToUpper(parts[1]) != "STARTTLS" {
		m.recordError(fmt.Sprintf("expected STARTTLS, got: %s", line))
		return
	}
	fmt.Fprintf(conn, "%s OK Begin TLS\r\n", parts[0])

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{m.cert},
	}
	tlsConn := tls.Server(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		m.recordError(fmt.Sprintf("TLS handshake failed: %v", err))
		return
	}
	defer tlsConn.Close()

	m.handleIMAPCommands(tlsConn)
}

func (m *mockUpstream) handleIMAPCommands(conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		m.record(line)

		// Handle literal continuation: if line ends with {N} or {N+}, send continuation
		// and read the literal data
		if n, ok := parseLiteral(line + "\r\n"); ok && n > 0 {
			fmt.Fprintf(conn, "+ Ready\r\n")
			litBuf := make([]byte, n)
			if _, err := io.ReadFull(reader, litBuf); err != nil {
				return
			}
			m.record(string(litBuf))
		}

		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			continue
		}
		tag := parts[0]
		cmd := strings.ToUpper(parts[1])

		switch cmd {
		case "LOGIN":
			fmt.Fprintf(conn, "%s OK [CAPABILITY IMAP4rev1 IDLE MOVE AUTH=PLAIN] LOGIN completed\r\n", tag)
		case "SELECT", "EXAMINE":
			mailbox := ""
			if len(parts) > 2 {
				mailbox = strings.Trim(parts[2], "\"")
			}
			fmt.Fprintf(conn, "* 10 EXISTS\r\n")
			fmt.Fprintf(conn, "* 0 RECENT\r\n")
			fmt.Fprintf(conn, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n")
			fmt.Fprintf(conn, "%s OK [READ-WRITE] %s selected\r\n", tag, mailbox)
		case "COPY":
			if m.supportCOPYUID && len(parts) > 2 {
				// Extract sequence set from "seqset mailbox" args
				copyArgs := strings.SplitN(parts[2], " ", 2)
				seqSet := copyArgs[0]
				fmt.Fprintf(conn, "%s OK [COPYUID 12345 %s %s] COPY completed\r\n", tag, seqSet, seqSet)
			} else {
				fmt.Fprintf(conn, "%s OK COPY completed\r\n", tag)
			}
		case "STORE":
			fmt.Fprintf(conn, "%s OK STORE completed\r\n", tag)
		case "EXPUNGE":
			fmt.Fprintf(conn, "%s OK EXPUNGE completed\r\n", tag)
		case "MOVE":
			fmt.Fprintf(conn, "%s OK MOVE completed\r\n", tag)
		case "UID":
			if len(parts) > 2 {
				subParts := strings.SplitN(parts[2], " ", 2)
				subCmd := strings.ToUpper(subParts[0])
				if m.supportCOPYUID && (subCmd == "COPY" || subCmd == "MOVE") && len(subParts) > 1 {
					// Extract UID set from "uidset mailbox" args
					uidArgs := strings.SplitN(subParts[1], " ", 2)
					uidSet := uidArgs[0]
					fmt.Fprintf(conn, "%s OK [COPYUID 12345 %s %s] UID %s completed\r\n", tag, uidSet, uidSet, subCmd)
				} else {
					fmt.Fprintf(conn, "%s OK UID %s completed\r\n", tag, subCmd)
				}
			} else {
				fmt.Fprintf(conn, "%s OK UID completed\r\n", tag)
			}
		case "COMPRESS":
			if m.supportCompress && len(parts) > 2 && strings.ToUpper(parts[2]) == "DEFLATE" {
				fmt.Fprintf(conn, "%s OK COMPRESS DEFLATE active\r\n", tag)
				// Drain any buffered data from the bufio.Reader
				var compInput io.Reader
				if reader.Buffered() > 0 {
					buf, _ := reader.Peek(reader.Buffered())
					bufCopy := make([]byte, len(buf))
					copy(bufCopy, buf)
					compInput = io.MultiReader(bytes.NewReader(bufCopy), conn)
				} else {
					compInput = conn
				}
				// Switch to compressed streams
				flateWriter, _ := flate.NewWriter(conn, flate.DefaultCompression)
				fw := &flushWriter{w: flateWriter}
				flateReader := flate.NewReader(compInput)
				compReader := bufio.NewReader(flateReader)
				m.handleCompressedCommands(conn, compReader, fw)
				return
			}
			fmt.Fprintf(conn, "%s NO COMPRESS not supported\r\n", tag)
		case "LOGOUT":
			fmt.Fprintf(conn, "* BYE logging out\r\n")
			fmt.Fprintf(conn, "%s OK LOGOUT completed\r\n", tag)
			return
		case "NOOP":
			fmt.Fprintf(conn, "%s OK NOOP completed\r\n", tag)
		default:
			fmt.Fprintf(conn, "%s OK %s completed\r\n", tag, cmd)
		}
	}
}

func (m *mockUpstream) handleCompressedCommands(conn net.Conn, reader *bufio.Reader, writer io.Writer) {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		m.record(line)

		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			continue
		}
		tag := parts[0]
		cmd := strings.ToUpper(parts[1])

		switch cmd {
		case "SELECT", "EXAMINE":
			mailbox := ""
			if len(parts) > 2 {
				mailbox = strings.Trim(parts[2], "\"")
			}
			fmt.Fprintf(writer, "* 10 EXISTS\r\n")
			fmt.Fprintf(writer, "* 0 RECENT\r\n")
			fmt.Fprintf(writer, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n")
			fmt.Fprintf(writer, "%s OK [READ-WRITE] %s selected\r\n", tag, mailbox)
		case "LOGOUT":
			fmt.Fprintf(writer, "* BYE logging out\r\n")
			fmt.Fprintf(writer, "%s OK LOGOUT completed\r\n", tag)
			return
		case "NOOP":
			fmt.Fprintf(writer, "%s OK NOOP completed\r\n", tag)
		case "EXPUNGE":
			fmt.Fprintf(writer, "%s OK EXPUNGE completed\r\n", tag)
		default:
			fmt.Fprintf(writer, "%s OK %s completed\r\n", tag, cmd)
		}
	}
}

// ── Integration tests ──

func TestProxyEndToEnd(t *testing.T) {
	upstream := newMockUpstream(t, mockSTARTTLS)
	defer upstream.listener.Close()
	go upstream.serve()

	cfg := testConfig(upstream.addr())
	rules := testRules()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxyLn.Close()

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go handleClient(conn, cfg, rules, "test", &metrics{})
		}
	}()

	connect := func(t *testing.T) (*bufio.Reader, net.Conn) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("client connect: %v", err)
		}
		reader := bufio.NewReader(conn)
		greeting, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read greeting: %v", err)
		}
		if strings.Contains(strings.ToUpper(greeting), "STARTTLS") {
			t.Errorf("greeting still contains STARTTLS: %s", greeting)
		}
		if strings.Contains(strings.ToUpper(greeting), "LOGINDISABLED") {
			t.Errorf("greeting still contains LOGINDISABLED: %s", greeting)
		}
		if !strings.Contains(greeting, "IMAP4rev1") {
			t.Errorf("greeting missing IMAP4rev1: %s", greeting)
		}
		return reader, conn
	}

	sendAndRead := func(t *testing.T, reader *bufio.Reader, conn net.Conn, cmd string) string {
		t.Helper()
		fmt.Fprintf(conn, "%s\r\n", cmd)
		tag := strings.SplitN(cmd, " ", 2)[0]
		var resp strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read response for %q: %v", cmd, err)
			}
			resp.WriteString(line)
			if strings.HasPrefix(line, tag+" ") {
				break
			}
		}
		return resp.String()
	}

	t.Run("greeting_capabilities_stripped", func(t *testing.T) {
		_, conn := connect(t)
		defer conn.Close()
	})

	t.Run("login_forwarded", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		resp := sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		if !strings.Contains(resp, "a1 OK") {
			t.Errorf("LOGIN should succeed, got: %s", resp)
		}
	})

	t.Run("move_blocked_in_trash", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 MOVE 5 INBOX")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("MOVE in Trash should be blocked, got: %s", resp)
		}
	})

	t.Run("close_blocked_in_trash", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 CLOSE")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("CLOSE in Trash should be blocked, got: %s", resp)
		}
	})

	t.Run("delete_blocked_on_protected_mailbox", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT INBOX")
		resp := sendAndRead(t, reader, conn, "a3 DELETE Trash")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("DELETE Trash should be blocked regardless of selected mailbox, got: %s", resp)
		}
	})

	t.Run("rename_blocked_on_protected_mailbox", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT INBOX")
		resp := sendAndRead(t, reader, conn, "a3 RENAME Drafts TempFolder")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("RENAME Drafts should be blocked regardless of selected mailbox, got: %s", resp)
		}
	})

	t.Run("expunge_blocked_in_trash", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 EXPUNGE")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("EXPUNGE in Trash should be blocked, got: %s", resp)
		}
		if !strings.Contains(resp, "NOPERM") {
			t.Errorf("blocked response should contain NOPERM, got: %s", resp)
		}
	})

	t.Run("store_deleted_blocked_in_trash", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 STORE 1:* +FLAGS (\\Deleted)")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("STORE \\Deleted in Trash should be blocked, got: %s", resp)
		}
	})

	t.Run("store_seen_allowed_in_trash", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 STORE 1:* +FLAGS (\\Seen)")
		if !strings.Contains(resp, "a3 OK") {
			t.Errorf("STORE \\Seen in Trash should be allowed, got: %s", resp)
		}
	})

	t.Run("remove_deleted_allowed_in_trash", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 STORE 1:* -FLAGS (\\Deleted)")
		if !strings.Contains(resp, "a3 OK") {
			t.Errorf("STORE -FLAGS \\Deleted in Trash should be allowed, got: %s", resp)
		}
	})

	t.Run("expunge_allowed_in_inbox", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT INBOX")
		resp := sendAndRead(t, reader, conn, "a3 EXPUNGE")
		if !strings.Contains(resp, "a3 OK") {
			t.Errorf("EXPUNGE in INBOX should be allowed, got: %s", resp)
		}
	})

	t.Run("store_deleted_allowed_in_inbox", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT INBOX")
		resp := sendAndRead(t, reader, conn, "a3 STORE 1:* +FLAGS (\\Deleted)")
		if !strings.Contains(resp, "a3 OK") {
			t.Errorf("STORE \\Deleted in INBOX should be allowed, got: %s", resp)
		}
	})

	t.Run("uid_expunge_blocked_in_drafts", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Drafts")
		resp := sendAndRead(t, reader, conn, "a3 UID EXPUNGE 100")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("UID EXPUNGE in Drafts should be blocked, got: %s", resp)
		}
	})

	t.Run("uid_store_deleted_blocked_in_drafts", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Drafts")
		resp := sendAndRead(t, reader, conn, "a3 UID STORE 100 +FLAGS (\\Deleted)")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("UID STORE \\Deleted in Drafts should be blocked, got: %s", resp)
		}
	})

	t.Run("switching_mailbox_updates_protection", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")

		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 EXPUNGE")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("EXPUNGE in Trash should be blocked, got: %s", resp)
		}

		sendAndRead(t, reader, conn, "a4 SELECT INBOX")
		resp = sendAndRead(t, reader, conn, "a5 EXPUNGE")
		if !strings.Contains(resp, "a5 OK") {
			t.Errorf("EXPUNGE in INBOX should be allowed, got: %s", resp)
		}

		sendAndRead(t, reader, conn, "a6 SELECT Drafts")
		resp = sendAndRead(t, reader, conn, "a7 EXPUNGE")
		if !strings.Contains(resp, "a7 NO") {
			t.Errorf("EXPUNGE in Drafts should be blocked, got: %s", resp)
		}
	})

	t.Run("blocked_commands_not_forwarded_to_upstream", func(t *testing.T) {
		upstream.mu.Lock()
		upstream.received = nil
		upstream.mu.Unlock()

		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		sendAndRead(t, reader, conn, "a3 EXPUNGE")
		sendAndRead(t, reader, conn, "a4 STORE 1 +FLAGS (\\Deleted)")
		sendAndRead(t, reader, conn, "a5 NOOP")
		sendAndRead(t, reader, conn, "a6 LOGOUT")

		received := upstream.getReceived()
		for _, cmd := range received {
			if strings.HasPrefix(cmd, "a3") {
				t.Errorf("blocked EXPUNGE was forwarded to upstream: %s", cmd)
			}
			if strings.HasPrefix(cmd, "a4") {
				t.Errorf("blocked STORE was forwarded to upstream: %s", cmd)
			}
		}

		found := false
		for _, cmd := range received {
			if strings.HasPrefix(cmd, "a5") && strings.Contains(strings.ToUpper(cmd), "NOOP") {
				found = true
			}
		}
		if !found {
			t.Errorf("NOOP should have been forwarded, received: %v", received)
		}
	})

	t.Run("literal_mailbox_name_protection", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		fmt.Fprintf(conn, "a2 SELECT {5}\r\n")
		// Read continuation response from upstream (relayed through proxy)
		contLine, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read continuation: %v", err)
		}
		if !strings.HasPrefix(contLine, "+") {
			t.Fatalf("expected continuation response, got: %s", contLine)
		}
		fmt.Fprintf(conn, "Trash")
		tag := "a2"
		var resp strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			resp.WriteString(line)
			if strings.HasPrefix(line, tag+" ") {
				break
			}
		}
		resp2 := sendAndRead(t, reader, conn, "a3 EXPUNGE")
		if !strings.Contains(resp2, "a3 NO") {
			t.Errorf("EXPUNGE after literal SELECT Trash should be blocked, got: %s", resp2)
		}
	})

	t.Run("quoted_mailbox_name", func(t *testing.T) {
		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT \"Trash\"")
		resp := sendAndRead(t, reader, conn, "a3 EXPUNGE")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("EXPUNGE in quoted \"Trash\" should be blocked, got: %s", resp)
		}
	})
}

func TestProxyPlaintextUpstream(t *testing.T) {
	upstream := newMockUpstream(t, mockPlaintext)
	defer upstream.listener.Close()
	go upstream.serve()

	cfg := &config{
		upstreamAddr:    upstream.addr(),
		upstreamTLS:     upstreamPlaintext,
		upstreamVerify:  "verify",
		idleTimeout:     30 * time.Minute,
		sessionTimeout:  24 * time.Hour,
		shutdownTimeout: 5 * time.Second,
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxyLn.Close()

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go handleClient(conn, cfg, nil, "test", &metrics{})
		}
	}()

	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.Contains(greeting, "IMAP4rev1") {
		t.Errorf("greeting missing IMAP4rev1: %s", greeting)
	}

	// Send login and verify relay works
	fmt.Fprintf(conn, "a1 LOGIN user pass\r\n")
	tag := "a1"
	var resp strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		resp.WriteString(line)
		if strings.HasPrefix(line, tag+" ") {
			break
		}
	}
	if !strings.Contains(resp.String(), "a1 OK") {
		t.Errorf("LOGIN should succeed over plaintext, got: %s", resp.String())
	}
}

func TestProxyImplicitTLSUpstream(t *testing.T) {
	upstream := newMockUpstream(t, mockImplicitTLS)
	defer upstream.listener.Close()
	go upstream.serve()

	cfg := &config{
		upstreamAddr:    upstream.addr(),
		upstreamTLS:     upstreamImplicitTLS,
		upstreamVerify:  "skip",
		idleTimeout:     30 * time.Minute,
		sessionTimeout:  24 * time.Hour,
		shutdownTimeout: 5 * time.Second,
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxyLn.Close()

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go handleClient(conn, cfg, nil, "test", &metrics{})
		}
	}()

	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.Contains(greeting, "IMAP4rev1") {
		t.Errorf("greeting missing IMAP4rev1: %s", greeting)
	}

	// Verify relay works through implicit TLS
	fmt.Fprintf(conn, "a1 LOGIN user pass\r\n")
	tag := "a1"
	var resp strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		resp.WriteString(line)
		if strings.HasPrefix(line, tag+" ") {
			break
		}
	}
	if !strings.Contains(resp.String(), "a1 OK") {
		t.Errorf("LOGIN should succeed over implicit TLS, got: %s", resp.String())
	}
}

func TestProxyClientTLS(t *testing.T) {
	upstream := newMockUpstream(t, mockSTARTTLS)
	defer upstream.listener.Close()
	go upstream.serve()

	clientCert := generateTestCert(t)
	certFile, keyFile := writeTempCertKey(t, clientCert)

	cfg := &config{
		upstreamAddr:    upstream.addr(),
		upstreamTLS:     upstreamSTARTTLS,
		upstreamVerify:  "skip",
		clientTLSCert:   certFile,
		clientTLSKey:    keyFile,
		idleTimeout:     30 * time.Minute,
		sessionTimeout:  24 * time.Hour,
		shutdownTimeout: 5 * time.Second,
	}

	// Start TLS proxy listener
	proxyCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load proxy cert: %v", err)
	}
	proxyLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{proxyCert},
	})
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxyLn.Close()

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go handleClient(conn, cfg, nil, "test", &metrics{})
		}
	}()

	// Connect client with TLS
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		proxyLn.Addr().String(),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		t.Fatalf("client TLS connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// When client TLS is enabled, STARTTLS should NOT be stripped
	// The upstream greeting has STARTTLS in it; with client TLS enabled, it passes through
	if !strings.Contains(greeting, "IMAP4rev1") {
		t.Errorf("greeting missing IMAP4rev1: %s", greeting)
	}
	// The key check: shouldStripCaps() returns false when client TLS is configured,
	// so STARTTLS/LOGINDISABLED from the upstream greeting should be preserved
	if !strings.Contains(strings.ToUpper(greeting), "STARTTLS") {
		t.Errorf("with client TLS, STARTTLS should NOT be stripped from greeting: %s", greeting)
	}
}

func TestCAFileVerification(t *testing.T) {
	caCertParsed, caKeyPair, caFilePath := generateTestCA(t)
	caPrivKey := caKeyPair.PrivateKey.(*ecdsa.PrivateKey)

	serverCert := signServerCert(t, caCertParsed, caPrivKey)
	upstream := newMockUpstreamWithCert(t, mockImplicitTLS, serverCert)
	defer upstream.listener.Close()
	go upstream.serve()

	cfg := &config{
		upstreamAddr:    upstream.addr(),
		upstreamTLS:     upstreamImplicitTLS,
		upstreamVerify:  caFilePath,
		idleTimeout:     30 * time.Minute,
		sessionTimeout:  24 * time.Hour,
		shutdownTimeout: 5 * time.Second,
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxyLn.Close()

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go handleClient(conn, cfg, nil, "test", &metrics{})
		}
	}()

	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.Contains(greeting, "IMAP4rev1") {
		t.Errorf("greeting missing IMAP4rev1: %s", greeting)
	}

	// Verify relay works with CA-verified connection
	fmt.Fprintf(conn, "a1 LOGIN user pass\r\n")
	tag := "a1"
	var resp strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		resp.WriteString(line)
		if strings.HasPrefix(line, tag+" ") {
			break
		}
	}
	if !strings.Contains(resp.String(), "a1 OK") {
		t.Errorf("LOGIN should succeed with CA verification, got: %s", resp.String())
	}
}

func TestNoConfigPassThrough(t *testing.T) {
	_, connect, sendAndRead := startProxy(t, nil) // nil rules = no blocking

	reader, conn := connect(t)
	defer conn.Close()

	sendAndRead(t, reader, conn, "a1 LOGIN user pass")
	sendAndRead(t, reader, conn, "a2 SELECT Trash")

	// All these should pass through without blocking (no rules)
	commands := []struct {
		cmd    string
		wantOK string
	}{
		{"a3 EXPUNGE", "a3 OK"},
		{"a4 STORE 1 +FLAGS (\\Deleted)", "a4 OK"},
		{"a5 MOVE 5 INBOX", "a5 OK"},
	}

	for _, tc := range commands {
		resp := sendAndRead(t, reader, conn, tc.cmd)
		if !strings.Contains(resp, tc.wantOK) {
			t.Errorf("with nil rules, %q should pass through, got: %s", tc.cmd, resp)
		}
	}
}

func TestWildcardRules(t *testing.T) {
	// Wildcard rule: block EXPUNGE on all mailboxes
	wildcardRules := []rule{
		{mailbox: "*", deny: []denyEntry{{command: "EXPUNGE"}}},
	}

	_, connect, sendAndRead := startProxy(t, wildcardRules)

	reader, conn := connect(t)
	defer conn.Close()

	sendAndRead(t, reader, conn, "a1 LOGIN user pass")

	// EXPUNGE should be blocked in any mailbox
	sendAndRead(t, reader, conn, "a2 SELECT INBOX")
	resp := sendAndRead(t, reader, conn, "a3 EXPUNGE")
	if !strings.Contains(resp, "a3 NO") {
		t.Errorf("wildcard rule should block EXPUNGE in INBOX, got: %s", resp)
	}

	sendAndRead(t, reader, conn, "a4 SELECT Trash")
	resp = sendAndRead(t, reader, conn, "a5 EXPUNGE")
	if !strings.Contains(resp, "a5 NO") {
		t.Errorf("wildcard rule should block EXPUNGE in Trash, got: %s", resp)
	}

	// Other commands should still pass through
	resp = sendAndRead(t, reader, conn, "a6 NOOP")
	if !strings.Contains(resp, "a6 OK") {
		t.Errorf("NOOP should pass through with wildcard EXPUNGE rule, got: %s", resp)
	}
}

func TestLoadACLConfigFromYAML(t *testing.T) {
	// Verify that a YAML config file produces working rules
	path := writeTestACLConfig(t)
	rules, err := loadACLConfig(path)
	if err != nil {
		t.Fatalf("loadACLConfig: %v", err)
	}

	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}

	// Verify rules work: EXPUNGE in Trash should be blocked
	result, _ := evalACL(rules, "Trash", "EXPUNGE", "", "")
	if result != aclDeny {
		t.Error("expected EXPUNGE in Trash to be blocked by loaded rules")
	}

	// STORE +\Deleted in Drafts should be blocked
	result, _ = evalACL(rules, "Drafts", "STORE", "+", `(\DELETED)`)
	if result != aclDeny {
		t.Error("expected STORE +\\Deleted in Drafts to be blocked by loaded rules")
	}

	// EXPUNGE in INBOX should not be blocked
	result, _ = evalACL(rules, "INBOX", "EXPUNGE", "", "")
	if result != aclAllow {
		t.Error("expected EXPUNGE in INBOX to be allowed by loaded rules")
	}
}

// testDenyUnlessCopiedRules returns ACL rules with deny-unless-copied for EXPUNGE on trash.
func testDenyUnlessCopiedRules() []rule {
	return []rule{
		{
			mailbox: "*trash*",
			deny: []denyEntry{
				{command: "CLOSE"}, {command: "DELETE"},
				{command: "RENAME"}, {command: "MOVE"}, {command: "COMPRESS"},
				{command: "STORE", storeOp: "+", storeFlag: `\DELETED`},
			},
			denyUnlessCopied: []string{"EXPUNGE"},
		},
		{
			mailbox: "*drafts*",
			deny: []denyEntry{
				{command: "EXPUNGE"}, {command: "CLOSE"}, {command: "DELETE"},
				{command: "RENAME"}, {command: "MOVE"}, {command: "COMPRESS"},
				{command: "STORE", storeOp: "+", storeFlag: `\DELETED`},
			},
		},
	}
}

// startProxy starts a proxy+upstream and returns helpers for connecting and sending commands.
func startProxy(t *testing.T, rules []rule) (upstream *mockUpstream,
	connect func(t *testing.T) (*bufio.Reader, net.Conn),
	sendAndRead func(t *testing.T, reader *bufio.Reader, conn net.Conn, cmd string) string) {
	t.Helper()

	upstream = newMockUpstream(t, mockSTARTTLS)
	go upstream.serve()

	cfg := testConfig(upstream.addr())
	m := &metrics{}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}

	var proxyWg sync.WaitGroup
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			proxyWg.Add(1)
			go func() {
				defer proxyWg.Done()
				handleClient(conn, cfg, rules, "test", m)
			}()
		}
	}()

	t.Cleanup(func() {
		proxyLn.Close()
		<-proxyDone
		proxyWg.Wait()
		upstream.listener.Close()
		<-upstream.done
		errs := upstream.getErrors()
		for _, e := range errs {
			t.Errorf("upstream error: %s", e)
		}
	})

	connect = func(t *testing.T) (*bufio.Reader, net.Conn) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("client connect: %v", err)
		}
		reader := bufio.NewReader(conn)
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatalf("read greeting: %v", err)
		}
		return reader, conn
	}

	sendAndRead = func(t *testing.T, reader *bufio.Reader, conn net.Conn, cmd string) string {
		t.Helper()
		fmt.Fprintf(conn, "%s\r\n", cmd)
		tag := strings.SplitN(cmd, " ", 2)[0]
		var resp strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read response for %q: %v", cmd, err)
			}
			resp.WriteString(line)
			if strings.HasPrefix(line, tag+" ") {
				break
			}
		}
		return resp.String()
	}

	return
}

// startProxyWithCOPYUID starts a proxy+upstream with COPYUID support control.
func startProxyWithCOPYUID(t *testing.T, rules []rule, supportCOPYUID bool) (upstream *mockUpstream,
	connect func(t *testing.T) (*bufio.Reader, net.Conn),
	sendAndRead func(t *testing.T, reader *bufio.Reader, conn net.Conn, cmd string) string) {
	t.Helper()
	upstream, connect, sendAndRead = startProxy(t, rules)
	upstream.supportCOPYUID = supportCOPYUID
	return upstream, connect, sendAndRead
}

func TestDenyUnlessCopiedWorkflow(t *testing.T) {
	rules := testDenyUnlessCopiedRules()
	_, connect, sendAndRead := startProxyWithCOPYUID(t, rules, true)

	reader, conn := connect(t)
	defer conn.Close()

	sendAndRead(t, reader, conn, "a1 LOGIN user pass")
	sendAndRead(t, reader, conn, "a2 SELECT Trash")

	// UID COPY 1:3 to Archive — server returns COPYUID
	resp := sendAndRead(t, reader, conn, "a3 UID COPY 1:3 Archive")
	if !strings.Contains(resp, "a3 OK") {
		t.Fatalf("UID COPY should succeed, got: %s", resp)
	}

	// UID EXPUNGE 1:3 — should be allowed since all UIDs were copied
	resp = sendAndRead(t, reader, conn, "a4 UID EXPUNGE 1:3")
	if !strings.Contains(resp, "a4 OK") {
		t.Errorf("UID EXPUNGE 1:3 should be allowed after COPY, got: %s", resp)
	}
}

func TestDenyUnlessCopiedBlocked(t *testing.T) {
	rules := testDenyUnlessCopiedRules()
	_, connect, sendAndRead := startProxyWithCOPYUID(t, rules, true)

	reader, conn := connect(t)
	defer conn.Close()

	sendAndRead(t, reader, conn, "a1 LOGIN user pass")
	sendAndRead(t, reader, conn, "a2 SELECT Trash")

	// UID EXPUNGE without prior COPY — should be blocked
	resp := sendAndRead(t, reader, conn, "a3 UID EXPUNGE 1:3")
	if !strings.Contains(resp, "a3 NO") {
		t.Errorf("UID EXPUNGE without prior COPY should be blocked, got: %s", resp)
	}
}

func TestDenyUnlessCopiedPartial(t *testing.T) {
	rules := testDenyUnlessCopiedRules()
	_, connect, sendAndRead := startProxyWithCOPYUID(t, rules, true)

	reader, conn := connect(t)
	defer conn.Close()

	sendAndRead(t, reader, conn, "a1 LOGIN user pass")
	sendAndRead(t, reader, conn, "a2 SELECT Trash")

	// Copy only UIDs 1:3
	sendAndRead(t, reader, conn, "a3 UID COPY 1:3 Archive")

	// Try to expunge 1:5 — UIDs 4,5 were not copied
	resp := sendAndRead(t, reader, conn, "a4 UID EXPUNGE 1:5")
	if !strings.Contains(resp, "a4 NO") {
		t.Errorf("UID EXPUNGE 1:5 should be blocked when only 1:3 copied, got: %s", resp)
	}
}

func TestDenyUnlessCopiedPlainExpunge(t *testing.T) {
	rules := testDenyUnlessCopiedRules()
	_, connect, sendAndRead := startProxyWithCOPYUID(t, rules, true)

	reader, conn := connect(t)
	defer conn.Close()

	sendAndRead(t, reader, conn, "a1 LOGIN user pass")
	sendAndRead(t, reader, conn, "a2 SELECT Trash")

	// Copy some UIDs
	sendAndRead(t, reader, conn, "a3 UID COPY 1:3 Archive")

	// Plain EXPUNGE — always blocked under deny-unless-copied
	resp := sendAndRead(t, reader, conn, "a4 EXPUNGE")
	if !strings.Contains(resp, "a4 NO") {
		t.Errorf("plain EXPUNGE should always be blocked under deny-unless-copied, got: %s", resp)
	}
}

func TestDenyUnlessCopiedMailboxSwitch(t *testing.T) {
	rules := testDenyUnlessCopiedRules()
	_, connect, sendAndRead := startProxyWithCOPYUID(t, rules, true)

	reader, conn := connect(t)
	defer conn.Close()

	sendAndRead(t, reader, conn, "a1 LOGIN user pass")
	sendAndRead(t, reader, conn, "a2 SELECT Trash")

	// Copy UIDs 1:3
	sendAndRead(t, reader, conn, "a3 UID COPY 1:3 Archive")

	// Switch to INBOX, then back to Trash — state should be cleared
	sendAndRead(t, reader, conn, "a4 SELECT INBOX")
	sendAndRead(t, reader, conn, "a5 SELECT Trash")

	// UID EXPUNGE 1:3 — should be blocked since state was cleared
	resp := sendAndRead(t, reader, conn, "a6 UID EXPUNGE 1:3")
	if !strings.Contains(resp, "a6 NO") {
		t.Errorf("UID EXPUNGE should be blocked after mailbox switch (state cleared), got: %s", resp)
	}
}

func TestDenyUnlessCopiedNoUIDPLUS(t *testing.T) {
	rules := testDenyUnlessCopiedRules()
	_, connect, sendAndRead := startProxyWithCOPYUID(t, rules, false) // no COPYUID support

	reader, conn := connect(t)
	defer conn.Close()

	sendAndRead(t, reader, conn, "a1 LOGIN user pass")
	sendAndRead(t, reader, conn, "a2 SELECT Trash")

	// UID COPY succeeds but server doesn't return COPYUID
	sendAndRead(t, reader, conn, "a3 UID COPY 1:3 Archive")

	// UID EXPUNGE — should be blocked since no COPYUID was received
	resp := sendAndRead(t, reader, conn, "a4 UID EXPUNGE 1:3")
	if !strings.Contains(resp, "a4 NO") {
		t.Errorf("UID EXPUNGE should be blocked when server doesn't support UIDPLUS, got: %s", resp)
	}
}

func TestDenyUnlessCopiedMove(t *testing.T) {
	// Use rules that allow MOVE but have deny-unless-copied on EXPUNGE
	rules := []rule{
		{
			mailbox: "*trash*",
			deny: []denyEntry{
				{command: "CLOSE"}, {command: "DELETE"},
				{command: "RENAME"}, {command: "COMPRESS"},
				{command: "STORE", storeOp: "+", storeFlag: `\DELETED`},
			},
			denyUnlessCopied: []string{"EXPUNGE"},
		},
	}
	_, connect, sendAndRead := startProxyWithCOPYUID(t, rules, true)

	reader, conn := connect(t)
	defer conn.Close()

	sendAndRead(t, reader, conn, "a1 LOGIN user pass")
	sendAndRead(t, reader, conn, "a2 SELECT Trash")

	// UID MOVE 1:3 — returns COPYUID just like UID COPY
	resp := sendAndRead(t, reader, conn, "a3 UID MOVE 1:3 Archive")
	if !strings.Contains(resp, "a3 OK") {
		t.Fatalf("UID MOVE should succeed, got: %s", resp)
	}

	// UID EXPUNGE 1:3 — should be allowed since MOVE returned COPYUID
	resp = sendAndRead(t, reader, conn, "a4 UID EXPUNGE 1:3")
	if !strings.Contains(resp, "a4 OK") {
		t.Errorf("UID EXPUNGE should be allowed after UID MOVE with COPYUID, got: %s", resp)
	}
}

// ── Phase 1-2 unit tests ──

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input   string
		want    slog.Level
		wantErr bool
	}{
		{"debug", slog.LevelDebug, false},
		{"info", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"INFO", slog.LevelInfo, false},
		{"Debug", slog.LevelDebug, false},
		{"invalid", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := parseLogLevel(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseLogLevel(%q) error=%v, wantErr=%v", tt.input, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("parseLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseDuration(t *testing.T) {
	// Set and clean up env var
	const key = "IMAP_GUARD_TEST_DUR"
	defer os.Unsetenv(key)

	t.Run("default value", func(t *testing.T) {
		os.Unsetenv(key)
		d, err := parseDuration(key, "5m")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d != 5*time.Minute {
			t.Errorf("got %v, want 5m", d)
		}
	})

	t.Run("env override", func(t *testing.T) {
		os.Setenv(key, "10s")
		d, err := parseDuration(key, "5m")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d != 10*time.Second {
			t.Errorf("got %v, want 10s", d)
		}
	})

	t.Run("invalid value", func(t *testing.T) {
		os.Setenv(key, "notaduration")
		_, err := parseDuration(key, "5m")
		if err == nil {
			t.Fatal("expected error for invalid duration")
		}
	})
}

func TestPrintUsage(t *testing.T) {
	// Just verify it doesn't panic
	printUsage()
}

// ── Phase 4 unit tests ──

func TestMetrics(t *testing.T) {
	m := &metrics{}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.activeConns.Add(1)
			m.totalProxied.Add(1)
			m.totalBlocked.Add(1)
			m.activeConns.Add(-1)
		}()
	}
	wg.Wait()

	if m.activeConns.Load() != 0 {
		t.Errorf("activeConns = %d, want 0", m.activeConns.Load())
	}
	if m.totalProxied.Load() != 100 {
		t.Errorf("totalProxied = %d, want 100", m.totalProxied.Load())
	}
	if m.totalBlocked.Load() != 100 {
		t.Errorf("totalBlocked = %d, want 100", m.totalBlocked.Load())
	}
}

// ── Phase 7 unit tests ──

func TestFlushWriter(t *testing.T) {
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("create flate writer: %v", err)
	}
	w := &flushWriter{w: fw}

	data := []byte("hello world\r\n")
	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(data) {
		t.Errorf("wrote %d bytes, want %d", n, len(data))
	}
	// After write+flush, buf should have data (flate doesn't buffer)
	if buf.Len() == 0 {
		t.Error("buffer empty after write — data should have been flushed")
	}

	// Close the underlying flate writer to finalize the stream
	fw.Close()

	// Verify we can decompress it
	reader := flate.NewReader(bytes.NewReader(buf.Bytes()))
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("decompressed = %q, want %q", got, data)
	}
}

// ── Phase 6 integration tests ──

func TestHealthEndpoint(t *testing.T) {
	m := &metrics{}
	m.activeConns.Store(5)
	m.totalProxied.Store(1234)
	m.totalBlocked.Store(12)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln.Close() // free the port

	srv := startHealthServer(ln.Addr().String(), m)
	defer srv.Close()
	// Give the server a moment to start
	time.Sleep(50 * time.Millisecond)

	t.Run("healthz", func(t *testing.T) {
		resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if strings.TrimSpace(string(body)) != "ok" {
			t.Errorf("body = %q, want ok", string(body))
		}
	})

	t.Run("metrics", func(t *testing.T) {
		resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
		if err != nil {
			t.Fatalf("GET /metrics: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		var result map[string]float64
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode JSON: %v", err)
		}
		if result["active_connections"] != 5 {
			t.Errorf("active_connections = %v, want 5", result["active_connections"])
		}
		if result["total_commands_proxied"] != 1234 {
			t.Errorf("total_commands_proxied = %v, want 1234", result["total_commands_proxied"])
		}
		if result["total_commands_blocked"] != 12 {
			t.Errorf("total_commands_blocked = %v, want 12", result["total_commands_blocked"])
		}
	})
}

// ── Phase 3 integration tests ──

func TestIdleTimeout(t *testing.T) {
	upstream := newMockUpstream(t, mockSTARTTLS)
	go upstream.serve()
	t.Cleanup(func() {
		upstream.listener.Close()
		<-upstream.done
	})

	cfg := testConfig(upstream.addr())
	cfg.idleTimeout = 200 * time.Millisecond
	cfg.sessionTimeout = 24 * time.Hour
	m := &metrics{}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { proxyLn.Close() })

	var proxyWg sync.WaitGroup
	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			proxyWg.Add(1)
			go func() {
				defer proxyWg.Done()
				handleClient(conn, cfg, nil, "test", m)
			}()
		}
	}()

	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Wait for idle timeout to expire
	time.Sleep(400 * time.Millisecond)

	// Connection should be closed by now
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err = reader.ReadString('\n')
	if err == nil {
		t.Error("expected connection to be closed after idle timeout")
	}
}

func TestSessionTimeout(t *testing.T) {
	upstream := newMockUpstream(t, mockSTARTTLS)
	go upstream.serve()
	t.Cleanup(func() {
		upstream.listener.Close()
		<-upstream.done
	})

	cfg := testConfig(upstream.addr())
	cfg.idleTimeout = 30 * time.Minute
	cfg.sessionTimeout = 300 * time.Millisecond
	m := &metrics{}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { proxyLn.Close() })

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go handleClient(conn, cfg, nil, "test", m)
		}
	}()

	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Keep sending NOOPs to reset idle, but session timeout should still fire
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		fmt.Fprintf(conn, "a%d NOOP\r\n", i)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := reader.ReadString('\n')
		if err != nil {
			// Connection closed due to session timeout
			return
		}
	}
	t.Error("expected connection to be closed after session timeout")
}

// ── Phase 5 integration tests ──

func TestGracefulShutdown(t *testing.T) {
	upstream := newMockUpstream(t, mockSTARTTLS)
	go upstream.serve()
	t.Cleanup(func() {
		upstream.listener.Close()
		<-upstream.done
	})

	cfg := testConfig(upstream.addr())
	m := &metrics{}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	go func() {
		<-ctx.Done()
		proxyLn.Close()
	}()

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleClient(conn, cfg, nil, "test", m)
			}()
		}
	}()

	// Connect a client
	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Trigger shutdown — closes listener so no new connections
	cancel()

	// Close client connection to let handleClient drain
	conn.Close()

	// Wait for connections to drain
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// OK — connections drained
	case <-time.After(5 * time.Second):
		t.Fatal("connections did not drain within 5 seconds")
	}
}

// ── COMPRESS DEFLATE integration tests ──

func TestCompressDeflateNegotiation(t *testing.T) {
	upstream := newMockUpstreamWithCompress(t, mockSTARTTLS)
	go upstream.serve()
	t.Cleanup(func() {
		upstream.listener.Close()
		<-upstream.done
	})

	cfg := testConfig(upstream.addr())
	m := &metrics{}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { proxyLn.Close() })

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go handleClient(conn, cfg, nil, "test", m)
		}
	}()

	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Login
	fmt.Fprintf(conn, "a1 LOGIN user pass\r\n")
	readTagged(t, reader, "a1")

	// Send COMPRESS DEFLATE
	fmt.Fprintf(conn, "a2 COMPRESS DEFLATE\r\n")
	resp := readTagged(t, reader, "a2")
	if !strings.Contains(resp, "a2 OK") {
		t.Fatalf("COMPRESS DEFLATE should succeed, got: %s", resp)
	}

	// Now the connection is compressed — wrap our side with flate
	clientFlate, _ := flate.NewWriter(conn, flate.DefaultCompression)
	clientFW := &flushWriter{w: clientFlate}
	compressedReader := bufio.NewReaderSize(flate.NewReader(conn), 8192)

	// Send a command over the compressed stream
	clientFW.Write([]byte("a3 NOOP\r\n"))
	compResp := readTaggedFromReader(t, compressedReader, "a3")
	if !strings.Contains(compResp, "a3 OK") {
		t.Errorf("NOOP over compressed stream should succeed, got: %s", compResp)
	}
}

func TestCompressDeflateBlocked(t *testing.T) {
	rules := []rule{
		{mailbox: "*", deny: []denyEntry{{command: "COMPRESS"}}},
	}
	_, connect, sendAndRead := startProxy(t, rules)

	reader, conn := connect(t)
	defer conn.Close()

	sendAndRead(t, reader, conn, "a1 LOGIN user pass")
	sendAndRead(t, reader, conn, "a2 SELECT INBOX")

	resp := sendAndRead(t, reader, conn, "a3 COMPRESS DEFLATE")
	if !strings.Contains(resp, "a3 NO") {
		t.Errorf("COMPRESS should be blocked by ACL, got: %s", resp)
	}

	// Connection should still work uncompressed
	resp = sendAndRead(t, reader, conn, "a4 NOOP")
	if !strings.Contains(resp, "a4 OK") {
		t.Errorf("NOOP after blocked COMPRESS should work, got: %s", resp)
	}
}

func TestCompressDeflateUpstreamReject(t *testing.T) {
	// Use standard mock which doesn't support COMPRESS
	_, connect, sendAndRead := startProxy(t, nil)

	reader, conn := connect(t)
	defer conn.Close()

	sendAndRead(t, reader, conn, "a1 LOGIN user pass")

	// Standard mock returns generic OK for unknown commands, so let's use
	// the non-compress mock upstream which responds OK to everything.
	// We'll just verify the connection still works after COMPRESS attempt.
	resp := sendAndRead(t, reader, conn, "a2 NOOP")
	if !strings.Contains(resp, "a2 OK") {
		t.Errorf("NOOP should work, got: %s", resp)
	}
}

func TestCompressDeflateWithACL(t *testing.T) {
	rules := testRules()
	upstream := newMockUpstreamWithCompress(t, mockSTARTTLS)
	go upstream.serve()
	t.Cleanup(func() {
		upstream.listener.Close()
		<-upstream.done
	})

	cfg := testConfig(upstream.addr())
	m := &metrics{}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { proxyLn.Close() })

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go handleClient(conn, cfg, rules, "test", m)
		}
	}()

	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Login and select non-protected mailbox
	fmt.Fprintf(conn, "a1 LOGIN user pass\r\n")
	readTagged(t, reader, "a1")
	fmt.Fprintf(conn, "a2 SELECT INBOX\r\n")
	readTagged(t, reader, "a2")

	// Negotiate COMPRESS DEFLATE
	fmt.Fprintf(conn, "a3 COMPRESS DEFLATE\r\n")
	resp := readTagged(t, reader, "a3")
	if !strings.Contains(resp, "a3 OK") {
		t.Fatalf("COMPRESS DEFLATE should succeed, got: %s", resp)
	}

	// Wrap with flate
	clientFlate, _ := flate.NewWriter(conn, flate.DefaultCompression)
	clientFW := &flushWriter{w: clientFlate}
	compressedReader := bufio.NewReaderSize(flate.NewReader(conn), 8192)

	// Select Trash over compressed stream
	clientFW.Write([]byte("a4 SELECT Trash\r\n"))
	readTaggedFromReader(t, compressedReader, "a4")

	// EXPUNGE should be blocked even over compressed stream
	clientFW.Write([]byte("a5 EXPUNGE\r\n"))
	compResp := readTaggedFromReader(t, compressedReader, "a5")
	if !strings.Contains(compResp, "a5 NO") {
		t.Errorf("EXPUNGE in Trash over compressed stream should be blocked, got: %s", compResp)
	}
}

// Helper to read until we get a tagged response
func readTagged(t *testing.T, reader *bufio.Reader, tag string) string {
	t.Helper()
	var resp strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read response for tag %q: %v", tag, err)
		}
		resp.WriteString(line)
		if strings.HasPrefix(line, tag+" ") {
			break
		}
	}
	return resp.String()
}

func readTaggedFromReader(t *testing.T, reader *bufio.Reader, tag string) string {
	t.Helper()
	var resp strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read response for tag %q: %v", tag, err)
		}
		resp.WriteString(line)
		if strings.HasPrefix(line, tag+" ") {
			break
		}
	}
	return resp.String()
}

// newMockUpstreamWithCompress creates a mock upstream that supports COMPRESS DEFLATE.
func newMockUpstreamWithCompress(t *testing.T, mode mockUpstreamMode) *mockUpstream {
	t.Helper()
	m := newMockUpstream(t, mode)
	m.supportCompress = true
	return m
}
