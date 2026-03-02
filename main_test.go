package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
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

func TestIsProtected(t *testing.T) {
	tests := []struct {
		mailbox string
		want    bool
	}{
		{"Trash", true},
		{"trash", true},
		{"TRASH", true},
		{"Drafts", true},
		{"drafts", true},
		{"DRAFTS", true},
		{"Junk", true},
		{"junk", true},
		{"JUNK", true},
		{"Folders/Trash", true},
		{"Folders/Drafts", true},
		{"Folders/Junk", true},
		{"INBOX.Trash", true},
		{"INBOX", false},
		{"Sent", false},
		{"Folders/Marketing", false},
		{"Archive", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isProtected(tt.mailbox)
		if got != tt.want {
			t.Errorf("isProtected(%q) = %v, want %v", tt.mailbox, got, tt.want)
		}
	}
}

func TestStoreAddsDeleted(t *testing.T) {
	tests := []struct {
		args string
		want bool
	}{
		// Should block
		{"1:* +FLAGS (\\Deleted)", true},
		{"1 +FLAGS (\\Deleted)", true},
		{"1:* +FLAGS.SILENT (\\Deleted)", true},
		{"1:* FLAGS (\\Deleted)", true},
		{"1:* FLAGS.SILENT (\\Deleted)", true},
		{"1:* +FLAGS (\\Seen \\Deleted)", true},
		{"1:* FLAGS (\\Deleted \\Seen)", true},

		// Should NOT block
		{"1:* -FLAGS (\\Deleted)", false},
		{"1:* -FLAGS.SILENT (\\Deleted)", false},
		{"1:* +FLAGS (\\Seen)", false},
		{"1:* +FLAGS (\\Flagged)", false},
		{"1:* FLAGS (\\Seen \\Flagged)", false},
		{"1:* +FLAGS.SILENT (\\Seen)", false},

		// Edge cases
		{"", false},
		{"1:*", false},
		{"1:* +FLAGS", false},
	}
	for _, tt := range tests {
		got := storeAddsDeleted(tt.args)
		if got != tt.want {
			t.Errorf("storeAddsDeleted(%q) = %v, want %v", tt.args, got, tt.want)
		}
	}
}

func TestShouldBlock(t *testing.T) {
	protected := &connState{selectedMailbox: "Trash", isProtected: true}
	unprotected := &connState{selectedMailbox: "INBOX", isProtected: false}

	tests := []struct {
		name  string
		cmd   string
		args  string
		state *connState
		want  bool
	}{
		// Blocked on protected
		{"expunge in trash", "EXPUNGE", "", protected, true},
		{"close in trash", "CLOSE", "", protected, true},
		{"move in trash", "MOVE", "5 INBOX", protected, true},
		{"store deleted in trash", "STORE", "1:* +FLAGS (\\Deleted)", protected, true},
		{"store silent deleted in trash", "STORE", "1:* +FLAGS.SILENT (\\Deleted)", protected, true},
		{"store replace deleted in trash", "STORE", "1:* FLAGS (\\Deleted)", protected, true},
		{"uid expunge in trash", "UID", "EXPUNGE 100", protected, true},
		{"uid store deleted in trash", "UID", "STORE 100 +FLAGS (\\Deleted)", protected, true},
		{"uid move in trash", "UID", "MOVE 100 INBOX", protected, true},

		// DELETE/RENAME target a named mailbox, blocked when targeting protected
		{"delete trash", "DELETE", "Trash", protected, true},
		{"delete trash case insensitive", "DELETE", "trash", protected, true},
		{"delete quoted trash", "DELETE", "\"Trash\"", protected, true},
		{"rename trash", "RENAME", "Trash NewName", protected, true},
		{"rename trash case insensitive", "RENAME", "TRASH NewName", protected, true},

		// DELETE/RENAME on unprotected targets — allowed even when selected is protected
		{"delete inbox while in trash", "DELETE", "SomeFolder", protected, false},
		{"rename inbox while in trash", "RENAME", "SomeFolder NewName", protected, false},

		// DELETE/RENAME on protected targets — blocked even when selected is unprotected
		{"delete trash while in inbox", "DELETE", "Trash", unprotected, true},
		{"rename trash while in inbox", "RENAME", "Trash NewName", unprotected, true},
		{"rename drafts while in inbox", "RENAME", "Drafts NewName", unprotected, true},

		// COMPRESS blocked when in protected mailbox (would bypass ACLs)
		{"compress in trash", "COMPRESS", "DEFLATE", protected, true},
		{"compress in inbox", "COMPRESS", "DEFLATE", unprotected, false},

		// Allowed on protected
		{"copy in trash", "COPY", "5 INBOX", protected, false},
		{"store seen in trash", "STORE", "1:* +FLAGS (\\Seen)", protected, false},
		{"remove deleted in trash", "STORE", "1:* -FLAGS (\\Deleted)", protected, false},
		{"fetch in trash", "FETCH", "1:* (FLAGS)", protected, false},
		{"search in trash", "SEARCH", "ALL", protected, false},
		{"noop in trash", "NOOP", "", protected, false},
		{"uid fetch in trash", "UID", "FETCH 100 (FLAGS)", protected, false},

		// Nothing blocked on unprotected (except DELETE/RENAME targeting protected)
		{"expunge in inbox", "EXPUNGE", "", unprotected, false},
		{"close in inbox", "CLOSE", "", unprotected, false},
		{"move in inbox", "MOVE", "5 Trash", unprotected, false},
		{"store deleted in inbox", "STORE", "1:* +FLAGS (\\Deleted)", unprotected, false},
		{"uid expunge in inbox", "UID", "EXPUNGE 100", unprotected, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldBlock(tt.cmd, tt.args, tt.state)
			if got != tt.want {
				t.Errorf("shouldBlock(%q, %q, mailbox=%s) = %v, want %v",
					tt.cmd, tt.args, tt.state.selectedMailbox, got, tt.want)
			}
		})
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

// ── Integration test with mock IMAP server ──

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

// mockUpstream simulates an upstream IMAP server with STARTTLS support.
// It records commands it receives and responds appropriately.
type mockUpstream struct {
	listener net.Listener
	received []string
	errors   []string
	mu       sync.Mutex
	cert     tls.Certificate
}

func newMockUpstream(t *testing.T) *mockUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock upstream listen: %v", err)
	}
	return &mockUpstream{
		listener: ln,
		cert:     generateTestCert(t),
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

	reader = bufio.NewReader(tlsConn)

	// Handle IMAP commands post-STARTTLS
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
		case "LOGIN":
			fmt.Fprintf(tlsConn, "%s OK [CAPABILITY IMAP4rev1 IDLE MOVE AUTH=PLAIN] LOGIN completed\r\n", tag)
		case "SELECT", "EXAMINE":
			mailbox := ""
			if len(parts) > 2 {
				mailbox = strings.Trim(parts[2], "\"")
			}
			fmt.Fprintf(tlsConn, "* 10 EXISTS\r\n")
			fmt.Fprintf(tlsConn, "* 0 RECENT\r\n")
			fmt.Fprintf(tlsConn, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n")
			fmt.Fprintf(tlsConn, "%s OK [READ-WRITE] %s selected\r\n", tag, mailbox)
		case "STORE":
			fmt.Fprintf(tlsConn, "%s OK STORE completed\r\n", tag)
		case "EXPUNGE":
			fmt.Fprintf(tlsConn, "%s OK EXPUNGE completed\r\n", tag)
		case "MOVE":
			fmt.Fprintf(tlsConn, "%s OK MOVE completed\r\n", tag)
		case "UID":
			if len(parts) > 2 {
				subParts := strings.SplitN(parts[2], " ", 2)
				subCmd := strings.ToUpper(subParts[0])
				fmt.Fprintf(tlsConn, "%s OK UID %s completed\r\n", tag, subCmd)
			} else {
				fmt.Fprintf(tlsConn, "%s OK UID completed\r\n", tag)
			}
		case "LOGOUT":
			fmt.Fprintf(tlsConn, "* BYE logging out\r\n")
			fmt.Fprintf(tlsConn, "%s OK LOGOUT completed\r\n", tag)
			return
		case "NOOP":
			fmt.Fprintf(tlsConn, "%s OK NOOP completed\r\n", tag)
		default:
			fmt.Fprintf(tlsConn, "%s OK %s completed\r\n", tag, cmd)
		}
	}
}

func TestProxyEndToEnd(t *testing.T) {
	// Start mock upstream
	upstream := newMockUpstream(t)
	defer upstream.listener.Close()
	go upstream.serve()

	// Start imap-guard proxy pointing at mock upstream
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
			go handleClient(conn, upstream.addr(), "test")
		}
	}()

	// Helper to connect a test client
	connect := func(t *testing.T) (*bufio.Reader, net.Conn) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("client connect: %v", err)
		}
		reader := bufio.NewReader(conn)
		// Read greeting
		greeting, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read greeting: %v", err)
		}
		// Verify STARTTLS and LOGINDISABLED stripped
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
		// Read all response lines until we see the tag
		tag := strings.SplitN(cmd, " ", 2)[0]
		var resp strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read response for %q: %v", cmd, err)
			}
			resp.WriteString(line)
			// Check if this is the tagged response
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

		// Start in Trash — blocked
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 EXPUNGE")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("EXPUNGE in Trash should be blocked, got: %s", resp)
		}

		// Switch to INBOX — allowed
		sendAndRead(t, reader, conn, "a4 SELECT INBOX")
		resp = sendAndRead(t, reader, conn, "a5 EXPUNGE")
		if !strings.Contains(resp, "a5 OK") {
			t.Errorf("EXPUNGE in INBOX should be allowed, got: %s", resp)
		}

		// Switch back to Drafts — blocked again
		sendAndRead(t, reader, conn, "a6 SELECT Drafts")
		resp = sendAndRead(t, reader, conn, "a7 EXPUNGE")
		if !strings.Contains(resp, "a7 NO") {
			t.Errorf("EXPUNGE in Drafts should be blocked, got: %s", resp)
		}
	})

	t.Run("blocked_commands_not_forwarded_to_upstream", func(t *testing.T) {
		// Reset received
		upstream.mu.Lock()
		upstream.received = nil
		upstream.mu.Unlock()

		reader, conn := connect(t)
		defer conn.Close()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		sendAndRead(t, reader, conn, "a3 EXPUNGE")        // blocked
		sendAndRead(t, reader, conn, "a4 STORE 1 +FLAGS (\\Deleted)") // blocked
		sendAndRead(t, reader, conn, "a5 NOOP")            // allowed
		// Use LOGOUT as a synchronization barrier — once we get the response,
		// all prior commands have been processed by the upstream
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

		// Verify NOOP was forwarded
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
		// Send SELECT with literal mailbox name: {5}\r\nTrash
		fmt.Fprintf(conn, "a2 SELECT {5}\r\n")
		// Small delay to let the proxy read the command line
		time.Sleep(10 * time.Millisecond)
		fmt.Fprintf(conn, "Trash")
		// Read the SELECT response
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
		// Now try to EXPUNGE — should be blocked because proxy parsed the literal mailbox name
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
