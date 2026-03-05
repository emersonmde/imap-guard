package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
		{"EXPUNGE extra", denyEntry{}, true}, // non-STORE with args
		{"STORE +", denyEntry{}, true},       // missing flag
		{"STORE noop", denyEntry{}, true},    // no + or - prefix
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
		args      string
		wantOp    string
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
	rules := testRules()

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
