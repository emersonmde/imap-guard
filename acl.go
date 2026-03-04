package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type aclResult int

const (
	aclAllow           aclResult = iota
	aclDeny
	aclDenyUnlessCopied
)

type denyEntry struct {
	command   string // EXPUNGE, CLOSE, DELETE, RENAME, MOVE, STORE, COMPRESS
	storeOp   string // "+" (add/replace) or "-" (remove); empty for non-STORE
	storeFlag string // e.g. `\DELETED`; empty if not flag-specific
}

type rule struct {
	mailbox          string // glob pattern (case-insensitive matching)
	deny             []denyEntry
	denyUnlessCopied []string // normalized to uppercase; only "EXPUNGE" valid
}

type yamlConfig struct {
	Rules []yamlRule `yaml:"rules"`
}

type yamlRule struct {
	Mailbox          string   `yaml:"mailbox"`
	Deny             []string `yaml:"deny"`
	DenyUnlessCopied []string `yaml:"deny-unless-copied"`
}

var validDenyCommands = map[string]bool{
	"EXPUNGE": true, "CLOSE": true, "DELETE": true,
	"RENAME": true, "MOVE": true, "STORE": true, "COMPRESS": true,
}

func loadACLConfig(path string) ([]rule, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ACL config %q: %w", path, err)
	}

	var yc yamlConfig
	if err := yaml.Unmarshal(data, &yc); err != nil {
		return nil, fmt.Errorf("parse ACL config %q: %w", path, err)
	}

	var rules []rule
	for i, yr := range yc.Rules {
		if yr.Mailbox == "" {
			return nil, fmt.Errorf("rule %d: mailbox is required", i)
		}
		r := rule{mailbox: yr.Mailbox}
		for _, d := range yr.Deny {
			entry, err := parseDenyEntry(d)
			if err != nil {
				return nil, fmt.Errorf("rule %d: %w", i, err)
			}
			r.deny = append(r.deny, entry)
		}

		// Parse deny-unless-copied entries
		denySet := make(map[string]bool)
		for _, d := range r.deny {
			denySet[d.command] = true
		}
		for _, duc := range yr.DenyUnlessCopied {
			cmd := strings.ToUpper(strings.TrimSpace(duc))
			if cmd != "EXPUNGE" {
				return nil, fmt.Errorf("rule %d: deny-unless-copied only supports EXPUNGE, got %q", i, duc)
			}
			if denySet[cmd] {
				return nil, fmt.Errorf("rule %d: %q appears in both deny and deny-unless-copied", i, cmd)
			}
			r.denyUnlessCopied = append(r.denyUnlessCopied, cmd)
		}

		rules = append(rules, r)
	}

	return rules, nil
}

// parseDenyEntry parses a deny string like "EXPUNGE", "STORE", "STORE +\Deleted", "STORE -\Seen".
func parseDenyEntry(s string) (denyEntry, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return denyEntry{}, fmt.Errorf("empty deny entry")
	}

	parts := strings.SplitN(s, " ", 2)
	cmd := strings.ToUpper(parts[0])

	if !validDenyCommands[cmd] {
		return denyEntry{}, fmt.Errorf("invalid deny command %q", cmd)
	}

	if len(parts) == 1 {
		return denyEntry{command: cmd}, nil
	}

	if cmd != "STORE" {
		return denyEntry{}, fmt.Errorf("arguments only valid for STORE, got %q", cmd)
	}

	// Parse STORE qualifier: "+\Deleted", "-\Seen", etc.
	qualifier := strings.TrimSpace(parts[1])
	if len(qualifier) < 2 {
		return denyEntry{}, fmt.Errorf("invalid STORE qualifier %q", qualifier)
	}

	var op string
	var flag string
	switch qualifier[0] {
	case '+':
		op = "+"
		flag = strings.ToUpper(qualifier[1:])
	case '-':
		op = "-"
		flag = strings.ToUpper(qualifier[1:])
	default:
		return denyEntry{}, fmt.Errorf("STORE qualifier must start with + or -, got %q", qualifier)
	}

	if flag == "" {
		return denyEntry{}, fmt.Errorf("STORE qualifier missing flag name")
	}

	return denyEntry{command: "STORE", storeOp: op, storeFlag: flag}, nil
}

// globMatch matches pattern against name, case-insensitively.
// * matches any sequence of characters (including / and .).
// ? matches exactly one byte (IMAP mailbox names use modified UTF-7, which is ASCII).
func globMatch(pattern, name string) bool {
	return matchGlob(strings.ToLower(pattern), strings.ToLower(name))
}

func matchGlob(pattern, name string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// Consume consecutive *s
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true // trailing * matches everything
			}
			// Try matching the rest of the pattern at each position
			for i := 0; i <= len(name); i++ {
				if matchGlob(pattern, name[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(name) == 0 {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]
		default:
			if len(name) == 0 || pattern[0] != name[0] {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]
		}
	}
	return len(name) == 0
}

func (r *rule) matches(mailbox, cmd string, storeOp, storeFlags string) (aclResult, string) {
	if !globMatch(r.mailbox, mailbox) {
		return aclAllow, ""
	}

	for _, d := range r.deny {
		if d.command != cmd {
			continue
		}

		if d.command != "STORE" {
			desc := fmt.Sprintf("mailbox=%q deny=%s", r.mailbox, d.command)
			return aclDeny, desc
		}

		// STORE with no qualifier: blocks all STORE
		if d.storeOp == "" && d.storeFlag == "" {
			desc := fmt.Sprintf("mailbox=%q deny=STORE", r.mailbox)
			return aclDeny, desc
		}

		// Check STORE op and flag
		// +flag rules match both +FLAGS and bare FLAGS (parseStoreArgs returns "+" for both)
		if d.storeOp == "+" && storeOp == "+" && containsFlag(storeFlags, d.storeFlag) {
			desc := fmt.Sprintf("mailbox=%q deny=STORE %s%s", r.mailbox, d.storeOp, d.storeFlag)
			return aclDeny, desc
		}
		if d.storeOp == "-" && storeOp == "-" && containsFlag(storeFlags, d.storeFlag) {
			desc := fmt.Sprintf("mailbox=%q deny=STORE %s%s", r.mailbox, d.storeOp, d.storeFlag)
			return aclDeny, desc
		}
	}

	// Check deny-unless-copied entries
	for _, duc := range r.denyUnlessCopied {
		if duc == cmd {
			desc := fmt.Sprintf("mailbox=%q deny-unless-copied=%s", r.mailbox, duc)
			return aclDenyUnlessCopied, desc
		}
	}

	return aclAllow, ""
}

func evalACL(rules []rule, mailbox, cmd string, storeOp, storeFlags string) (aclResult, string) {
	if len(rules) == 0 {
		return aclAllow, ""
	}

	for i := range rules {
		if result, desc := rules[i].matches(mailbox, cmd, storeOp, storeFlags); result != aclAllow {
			return result, fmt.Sprintf("rule[%d]: %s", i, desc)
		}
	}

	return aclAllow, ""
}
