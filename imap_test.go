package main

import (
	"bufio"
	"slices"
	"strings"
	"testing"
)

func TestParseCommand(t *testing.T) {
	tests := []struct {
		line                       string
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
		{"\"Folder with \\\"quotes\\\"\"", "Folder with \"quotes\""},
		{"{5}\r\n", ""},
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
		line   string
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

func TestParseLiteralEx(t *testing.T) {
	tests := []struct {
		line     string
		wantN    int64
		wantPlus bool
		wantOK   bool
	}{
		{"a1 DELETE {5}\r\n", 5, false, true},
		{"a1 DELETE {5+}\r\n", 5, true, true},
		{"{100}\r\n", 100, false, true},
		{"{100+}\r\n", 100, true, true},
		{"normal line\r\n", 0, false, false},
		{"{abc}\r\n", 0, false, false},
		{"{0}\r\n", 0, false, true},
	}
	for _, tt := range tests {
		n, isPlus, ok := parseLiteralEx(tt.line)
		if n != tt.wantN || isPlus != tt.wantPlus || ok != tt.wantOK {
			t.Errorf("parseLiteralEx(%q) = (%d, %v, %v), want (%d, %v, %v)",
				tt.line, n, isPlus, ok, tt.wantN, tt.wantPlus, tt.wantOK)
		}
	}
}

func TestQuoteMailbox(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		wantOK bool
	}{
		{"Trash", `"Trash"`, true},
		{"INBOX", `"INBOX"`, true},
		{`Folder with "quotes"`, `"Folder with \"quotes\""`, true},
		{`Folder\Path`, `"Folder\\Path"`, true},
		{"has\rnewline", "", false},
		{"has\nnewline", "", false},
		{"has\x00null", "", false},
		{"", `""`, true},
	}
	for _, tt := range tests {
		got, ok := quoteMailbox(tt.name)
		if ok != tt.wantOK {
			t.Errorf("quoteMailbox(%q): ok = %v, want %v", tt.name, ok, tt.wantOK)
		}
		if got != tt.want {
			t.Errorf("quoteMailbox(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestParseUIDSet(t *testing.T) {
	tests := []struct {
		input    string
		wantUIDs []uint32
		wantOK   bool
	}{
		{"1", []uint32{1}, true},
		{"100", []uint32{100}, true},
		{"1:5", []uint32{1, 2, 3, 4, 5}, true},
		{"3:1", []uint32{1, 2, 3}, true},
		{"1,3,5", []uint32{1, 3, 5}, true},
		{"1:3,5:7", []uint32{1, 2, 3, 5, 6, 7}, true},
		{"1,3:5,10", []uint32{1, 3, 4, 5, 10}, true},
		{"*", nil, false},
		{"1:*", nil, false},
		{"0", nil, false},
		{"0:5", nil, false},
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
		{"a1 OK [COPYUID 12345 1:3 10:12] Copy completed\r\n", []uint32{1, 2, 3}, true},
		{"a1 OK [COPYUID 12345 5 20] Copy completed\r\n", []uint32{5}, true},
		{"a1 OK [COPYUID 12345 1,3,5 10,12,14] Copy completed\r\n", []uint32{1, 3, 5}, true},
		{"a1 OK [copyuid 12345 1:3 10:12] Copy completed\r\n", []uint32{1, 2, 3}, true},
		{"a1 OK [CopyUID 12345 1:3 10:12] Copy completed\r\n", []uint32{1, 2, 3}, true},
		{"a1 OK Copy completed\r\n", nil, false},
		{"a1 OK [COPYUID 12345 1:3] Copy completed\r\n", nil, false},
		{"a1 OK [COPYUID 12345] Copy completed\r\n", nil, false},
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
		line     string
		wantTag  string
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

func TestReadLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		maxLen  int
		want    string
		wantErr bool
	}{
		{"normal line", "hello\n", 100, "hello\n", false},
		{"crlf line", "hello\r\n", 100, "hello\r\n", false},
		{"exact limit", "abc\n", 4, "abc\n", false},
		{"over limit", "abcdef\n", 4, "", true},
		{"no newline EOF", "hello", 100, "", true},
		{"empty line", "\n", 100, "\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tt.input))
			got, err := readLine(r, tt.maxLen)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (line=%q)", got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadLineLongInput(t *testing.T) {
	// Generate input longer than the bufio internal buffer (8192) but within maxLen
	long := strings.Repeat("x", 16000) + "\n"
	r := bufio.NewReaderSize(strings.NewReader(long), 8192)
	got, err := readLine(r, 20000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != long {
		t.Errorf("got length %d, want %d", len(got), len(long))
	}

	// Same input but with a smaller max
	r = bufio.NewReaderSize(strings.NewReader(long), 8192)
	_, err = readLine(r, 1000)
	if err == nil {
		t.Error("expected error for line exceeding maxLen")
	}
}

func TestContainsFlag(t *testing.T) {
	tests := []struct {
		flagStr string
		flag    string
		want    bool
	}{
		{`(\DELETED)`, `\DELETED`, true},
		{`(\DELETED \SEEN)`, `\DELETED`, true},
		{`(\SEEN)`, `\DELETED`, false},
		{`(\DELETEDARCHIVE)`, `\DELETED`, false},
		{`\DELETED`, `\DELETED`, true},
		{`(\DELETED \SEEN \FLAGGED)`, `\SEEN`, true},
		{`()`, `\DELETED`, false},
		{``, `\DELETED`, false},
	}
	for _, tt := range tests {
		got := containsFlag(tt.flagStr, tt.flag)
		if got != tt.want {
			t.Errorf("containsFlag(%q, %q) = %v, want %v",
				tt.flagStr, tt.flag, got, tt.want)
		}
	}
}

func TestContainsFlagNoSubstringMatch(t *testing.T) {
	// Regression: ensure that a rule denying \DELETED does NOT block \DELETEDARCHIVE
	rules := []rule{
		{mailbox: "*trash*", deny: []denyEntry{
			{command: "STORE", storeOp: "+", storeFlag: `\DELETED`},
		}},
	}
	result, _ := evalACL(rules, "Trash", "STORE", "+", `(\DELETEDARCHIVE)`)
	if result != aclAllow {
		t.Error("STORE +\\DELETEDARCHIVE should be allowed, not blocked by \\DELETED rule")
	}
	result, _ = evalACL(rules, "Trash", "STORE", "+", `(\DELETED)`)
	if result != aclDeny {
		t.Error("STORE +\\DELETED should be blocked")
	}
}
