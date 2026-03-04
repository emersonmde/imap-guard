package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProxyEndToEnd(t *testing.T) {
	upstream := newMockUpstream(t, mockSTARTTLS)
	defer func() { _ = upstream.listener.Close() }()
	go upstream.serve()

	cfg := testConfig(upstream.addr())
	rules := testRules()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer func() { _ = proxyLn.Close() }()

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
		_, _ = fmt.Fprintf(conn, "%s\r\n", cmd)
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
		defer func() { _ = conn.Close() }()
	})

	t.Run("login_forwarded", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
		resp := sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		if !strings.Contains(resp, "a1 OK") {
			t.Errorf("LOGIN should succeed, got: %s", resp)
		}
	})

	t.Run("move_blocked_in_trash", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 MOVE 5 INBOX")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("MOVE in Trash should be blocked, got: %s", resp)
		}
	})

	t.Run("close_blocked_in_trash", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 CLOSE")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("CLOSE in Trash should be blocked, got: %s", resp)
		}
	})

	t.Run("delete_blocked_on_protected_mailbox", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT INBOX")
		resp := sendAndRead(t, reader, conn, "a3 DELETE Trash")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("DELETE Trash should be blocked regardless of selected mailbox, got: %s", resp)
		}
	})

	t.Run("rename_blocked_on_protected_mailbox", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT INBOX")
		resp := sendAndRead(t, reader, conn, "a3 RENAME Drafts TempFolder")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("RENAME Drafts should be blocked regardless of selected mailbox, got: %s", resp)
		}
	})

	t.Run("expunge_blocked_in_trash", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
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
		defer func() { _ = conn.Close() }()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 STORE 1:* +FLAGS (\\Deleted)")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("STORE \\Deleted in Trash should be blocked, got: %s", resp)
		}
	})

	t.Run("store_seen_allowed_in_trash", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 STORE 1:* +FLAGS (\\Seen)")
		if !strings.Contains(resp, "a3 OK") {
			t.Errorf("STORE \\Seen in Trash should be allowed, got: %s", resp)
		}
	})

	t.Run("remove_deleted_allowed_in_trash", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Trash")
		resp := sendAndRead(t, reader, conn, "a3 STORE 1:* -FLAGS (\\Deleted)")
		if !strings.Contains(resp, "a3 OK") {
			t.Errorf("STORE -FLAGS \\Deleted in Trash should be allowed, got: %s", resp)
		}
	})

	t.Run("expunge_allowed_in_inbox", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT INBOX")
		resp := sendAndRead(t, reader, conn, "a3 EXPUNGE")
		if !strings.Contains(resp, "a3 OK") {
			t.Errorf("EXPUNGE in INBOX should be allowed, got: %s", resp)
		}
	})

	t.Run("store_deleted_allowed_in_inbox", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT INBOX")
		resp := sendAndRead(t, reader, conn, "a3 STORE 1:* +FLAGS (\\Deleted)")
		if !strings.Contains(resp, "a3 OK") {
			t.Errorf("STORE \\Deleted in INBOX should be allowed, got: %s", resp)
		}
	})

	t.Run("uid_expunge_blocked_in_drafts", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Drafts")
		resp := sendAndRead(t, reader, conn, "a3 UID EXPUNGE 100")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("UID EXPUNGE in Drafts should be blocked, got: %s", resp)
		}
	})

	t.Run("uid_store_deleted_blocked_in_drafts", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		sendAndRead(t, reader, conn, "a2 SELECT Drafts")
		resp := sendAndRead(t, reader, conn, "a3 UID STORE 100 +FLAGS (\\Deleted)")
		if !strings.Contains(resp, "a3 NO") {
			t.Errorf("UID STORE \\Deleted in Drafts should be blocked, got: %s", resp)
		}
	})

	t.Run("switching_mailbox_updates_protection", func(t *testing.T) {
		reader, conn := connect(t)
		defer func() { _ = conn.Close() }()
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
		defer func() { _ = conn.Close() }()
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
		defer func() { _ = conn.Close() }()
		sendAndRead(t, reader, conn, "a1 LOGIN user pass")
		_, _ = fmt.Fprintf(conn, "a2 SELECT {5}\r\n")
		// Proxy now handles continuation itself
		contLine, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read continuation: %v", err)
		}
		if !strings.HasPrefix(contLine, "+") {
			t.Fatalf("expected continuation response, got: %s", contLine)
		}
		// Send 5-byte literal "Trash" followed by the command continuation line
		_, _ = fmt.Fprintf(conn, "Trash\r\n")
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
		defer func() { _ = conn.Close() }()
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
	defer func() { _ = upstream.listener.Close() }()
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
	defer func() { _ = proxyLn.Close() }()

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
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.Contains(greeting, "IMAP4rev1") {
		t.Errorf("greeting missing IMAP4rev1: %s", greeting)
	}

	// Send login and verify relay works
	_, _ = fmt.Fprintf(conn, "a1 LOGIN user pass\r\n")
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
	defer func() { _ = upstream.listener.Close() }()
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
	defer func() { _ = proxyLn.Close() }()

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
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.Contains(greeting, "IMAP4rev1") {
		t.Errorf("greeting missing IMAP4rev1: %s", greeting)
	}

	// Verify relay works through implicit TLS
	_, _ = fmt.Fprintf(conn, "a1 LOGIN user pass\r\n")
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
	defer func() { _ = upstream.listener.Close() }()
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
	defer func() { _ = proxyLn.Close() }()

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
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// When client TLS is enabled, STARTTLS should NOT be stripped
	if !strings.Contains(greeting, "IMAP4rev1") {
		t.Errorf("greeting missing IMAP4rev1: %s", greeting)
	}
	if !strings.Contains(strings.ToUpper(greeting), "STARTTLS") {
		t.Errorf("with client TLS, STARTTLS should NOT be stripped from greeting: %s", greeting)
	}
}

func TestCAFileVerification(t *testing.T) {
	caCertParsed, caKeyPair, caFilePath := generateTestCA(t)
	caPrivKey := caKeyPair.PrivateKey.(*ecdsa.PrivateKey)

	serverCert := signServerCert(t, caCertParsed, caPrivKey)
	upstream := newMockUpstreamWithCert(t, mockImplicitTLS, serverCert)
	defer func() { _ = upstream.listener.Close() }()
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
	defer func() { _ = proxyLn.Close() }()

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
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.Contains(greeting, "IMAP4rev1") {
		t.Errorf("greeting missing IMAP4rev1: %s", greeting)
	}

	// Verify relay works with CA-verified connection
	_, _ = fmt.Fprintf(conn, "a1 LOGIN user pass\r\n")
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
	defer func() { _ = conn.Close() }()

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
	defer func() { _ = conn.Close() }()

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

// ── Deny-unless-copied integration tests ──

func TestDenyUnlessCopiedWorkflow(t *testing.T) {
	rules := testDenyUnlessCopiedRules()
	_, connect, sendAndRead := startProxyWithCOPYUID(t, rules, true)

	reader, conn := connect(t)
	defer func() { _ = conn.Close() }()

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
	defer func() { _ = conn.Close() }()

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
	defer func() { _ = conn.Close() }()

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
	defer func() { _ = conn.Close() }()

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
	defer func() { _ = conn.Close() }()

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
	defer func() { _ = conn.Close() }()

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
	defer func() { _ = conn.Close() }()

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

// ── Timeout tests ──

func TestIdleTimeout(t *testing.T) {
	upstream := newMockUpstream(t, mockSTARTTLS)
	go upstream.serve()
	t.Cleanup(func() {
		_ = upstream.listener.Close()
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
	t.Cleanup(func() { _ = proxyLn.Close() })

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
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Wait for idle timeout to expire
	time.Sleep(400 * time.Millisecond)

	// Connection should be closed by now
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err = reader.ReadString('\n')
	if err == nil {
		t.Error("expected connection to be closed after idle timeout")
	}
}

func TestSessionTimeout(t *testing.T) {
	upstream := newMockUpstream(t, mockSTARTTLS)
	go upstream.serve()
	t.Cleanup(func() {
		_ = upstream.listener.Close()
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
	t.Cleanup(func() { _ = proxyLn.Close() })

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
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Keep sending NOOPs to reset idle, but session timeout should still fire
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		_, _ = fmt.Fprintf(conn, "a%d NOOP\r\n", i)
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := reader.ReadString('\n')
		if err != nil {
			// Connection closed due to session timeout
			return
		}
	}
	t.Error("expected connection to be closed after session timeout")
}

// ── Graceful shutdown tests ──

func TestGracefulShutdown(t *testing.T) {
	upstream := newMockUpstream(t, mockSTARTTLS)
	go upstream.serve()
	t.Cleanup(func() {
		_ = upstream.listener.Close()
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
		_ = proxyLn.Close()
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
	_ = conn.Close()

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
		_ = upstream.listener.Close()
		<-upstream.done
	})

	cfg := testConfig(upstream.addr())
	m := &metrics{}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = proxyLn.Close() })

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
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Login
	_, _ = fmt.Fprintf(conn, "a1 LOGIN user pass\r\n")
	readTagged(t, reader, "a1")

	// Send COMPRESS DEFLATE
	_, _ = fmt.Fprintf(conn, "a2 COMPRESS DEFLATE\r\n")
	resp := readTagged(t, reader, "a2")
	if !strings.Contains(resp, "a2 OK") {
		t.Fatalf("COMPRESS DEFLATE should succeed, got: %s", resp)
	}

	// Now the connection is compressed — wrap our side with flate
	clientFlate, _ := flate.NewWriter(conn, flate.DefaultCompression)
	clientFW := &flushWriter{w: clientFlate}
	compressedReader := bufio.NewReaderSize(flate.NewReader(conn), 8192)

	// Send a command over the compressed stream
	_, _ = clientFW.Write([]byte("a3 NOOP\r\n"))
	compResp := readTagged(t, compressedReader, "a3")
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
	defer func() { _ = conn.Close() }()

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
	// Standard mock without COMPRESS support responds "NO COMPRESS not supported"
	_, connect, sendAndRead := startProxy(t, nil)

	reader, conn := connect(t)
	defer func() { _ = conn.Close() }()

	sendAndRead(t, reader, conn, "a1 LOGIN user pass")

	// Send COMPRESS DEFLATE — upstream rejects it
	resp := sendAndRead(t, reader, conn, "a2 COMPRESS DEFLATE")
	if !strings.Contains(resp, "a2 NO") {
		t.Errorf("COMPRESS should be rejected by non-compress upstream, got: %s", resp)
	}

	// Connection should still work uncompressed
	resp = sendAndRead(t, reader, conn, "a3 NOOP")
	if !strings.Contains(resp, "a3 OK") {
		t.Errorf("NOOP after rejected COMPRESS should work, got: %s", resp)
	}
}

func TestCompressDeflateWithACL(t *testing.T) {
	rules := testRules()
	upstream := newMockUpstreamWithCompress(t, mockSTARTTLS)
	go upstream.serve()
	t.Cleanup(func() {
		_ = upstream.listener.Close()
		<-upstream.done
	})

	cfg := testConfig(upstream.addr())
	m := &metrics{}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = proxyLn.Close() })

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
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Login and select non-protected mailbox
	_, _ = fmt.Fprintf(conn, "a1 LOGIN user pass\r\n")
	readTagged(t, reader, "a1")
	_, _ = fmt.Fprintf(conn, "a2 SELECT INBOX\r\n")
	readTagged(t, reader, "a2")

	// Negotiate COMPRESS DEFLATE
	_, _ = fmt.Fprintf(conn, "a3 COMPRESS DEFLATE\r\n")
	resp := readTagged(t, reader, "a3")
	if !strings.Contains(resp, "a3 OK") {
		t.Fatalf("COMPRESS DEFLATE should succeed, got: %s", resp)
	}

	// Wrap with flate
	clientFlate, _ := flate.NewWriter(conn, flate.DefaultCompression)
	clientFW := &flushWriter{w: clientFlate}
	compressedReader := bufio.NewReaderSize(flate.NewReader(conn), 8192)

	// Select Trash over compressed stream
	_, _ = clientFW.Write([]byte("a4 SELECT Trash\r\n"))
	readTagged(t, compressedReader, "a4")

	// EXPUNGE should be blocked even over compressed stream
	_, _ = clientFW.Write([]byte("a5 EXPUNGE\r\n"))
	compResp := readTagged(t, compressedReader, "a5")
	if !strings.Contains(compResp, "a5 NO") {
		t.Errorf("EXPUNGE in Trash over compressed stream should be blocked, got: %s", compResp)
	}
}

// ── DELETE/RENAME literal tests ──

func TestDeleteLiteralBlocked(t *testing.T) {
	upstream, connect, sendAndRead := startProxy(t, testRules())
	reader, conn := connect(t)
	defer func() { _ = conn.Close() }()
	sendAndRead(t, reader, conn, "a1 LOGIN user pass")

	// DELETE Trash using IMAP synchronizing literal
	_, _ = fmt.Fprintf(conn, "a2 DELETE {5}\r\n")
	contLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read continuation: %v", err)
	}
	if !strings.HasPrefix(contLine, "+ ") {
		t.Fatalf("expected continuation, got: %s", contLine)
	}
	// Send literal data
	_, _ = fmt.Fprintf(conn, "Trash\r\n")
	resp := readTagged(t, reader, "a2")
	if !strings.Contains(resp, "a2 NO") {
		t.Errorf("DELETE with literal Trash should be blocked, got: %s", resp)
	}

	// Verify upstream did NOT receive the DELETE
	time.Sleep(50 * time.Millisecond)
	for _, r := range upstream.getReceived() {
		if strings.Contains(strings.ToUpper(r), "DELETE") {
			t.Errorf("upstream should not have received DELETE, got: %s", r)
		}
	}
}

func TestDeleteLiteralPlusBlocked(t *testing.T) {
	_, connect, sendAndRead := startProxy(t, testRules())
	reader, conn := connect(t)
	defer func() { _ = conn.Close() }()
	sendAndRead(t, reader, conn, "a1 LOGIN user pass")

	// DELETE Trash using LITERAL+ — proxy must NOT send a continuation response
	_, _ = fmt.Fprintf(conn, "a2 DELETE {5+}\r\nTrash\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading response: %v", err)
		}
		if strings.HasPrefix(line, "+ ") {
			t.Fatal("proxy sent spurious continuation for LITERAL+")
		}
		if strings.HasPrefix(line, "a2 ") {
			if !strings.Contains(line, "a2 NO") {
				t.Errorf("DELETE with LITERAL+ Trash should be blocked, got: %s", line)
			}
			break
		}
	}
}

func TestRenameLiteralBlocked(t *testing.T) {
	_, connect, sendAndRead := startProxy(t, testRules())
	reader, conn := connect(t)
	defer func() { _ = conn.Close() }()
	sendAndRead(t, reader, conn, "a1 LOGIN user pass")

	// RENAME Trash using IMAP synchronizing literal
	_, _ = fmt.Fprintf(conn, "a2 RENAME {5}\r\n")
	contLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read continuation: %v", err)
	}
	if !strings.HasPrefix(contLine, "+ ") {
		t.Fatalf("expected continuation, got: %s", contLine)
	}
	_, _ = fmt.Fprintf(conn, "Trash NewName\r\n")
	resp := readTagged(t, reader, "a2")
	if !strings.Contains(resp, "a2 NO") {
		t.Errorf("RENAME with literal Trash should be blocked, got: %s", resp)
	}
}

func TestDeleteLiteralAllowed(t *testing.T) {
	upstream, connect, sendAndRead := startProxy(t, testRules())
	reader, conn := connect(t)
	defer func() { _ = conn.Close() }()
	sendAndRead(t, reader, conn, "a1 LOGIN user pass")

	// DELETE "OldFolder" via literal — should be allowed (not protected)
	_, _ = fmt.Fprintf(conn, "a2 DELETE {9}\r\n")
	contLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read continuation: %v", err)
	}
	if !strings.HasPrefix(contLine, "+ ") {
		t.Fatalf("expected continuation, got: %s", contLine)
	}
	_, _ = fmt.Fprintf(conn, "OldFolder\r\n")
	resp := readTagged(t, reader, "a2")
	if !strings.Contains(resp, "a2 OK") {
		t.Errorf("DELETE of OldFolder should be allowed, got: %s", resp)
	}

	// Verify upstream received the rewritten command as quoted string
	var found bool
	for range 20 {
		for _, r := range upstream.getReceived() {
			if strings.Contains(r, "DELETE") && strings.Contains(r, `"OldFolder"`) {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		t.Errorf("upstream should have received DELETE \"OldFolder\", got: %v", upstream.getReceived())
	}
}

// ── Connection limit tests ──

func TestConnectionLimit(t *testing.T) {
	upstream := newMockUpstream(t, mockSTARTTLS)
	defer func() { _ = upstream.listener.Close() }()
	go upstream.serve()

	cfg := testConfig(upstream.addr())
	cfg.maxConnections = 1

	m := &metrics{}
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer func() { _ = proxyLn.Close() }()

	// Mirror the production accept loop: pre-increment activeConns before spawning goroutine
	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			if cfg.maxConnections > 0 && m.activeConns.Load() >= cfg.maxConnections {
				_ = conn.Close()
				continue
			}
			m.activeConns.Add(1)
			go handleClient(conn, cfg, nil, "test", m)
		}
	}()

	// First connection should succeed
	conn1, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	defer func() { _ = conn1.Close() }()

	reader1 := bufio.NewReader(conn1)
	greeting, err := reader1.ReadString('\n')
	if err != nil {
		t.Fatalf("read first greeting: %v", err)
	}
	if !strings.Contains(greeting, "IMAP4rev1") {
		t.Errorf("first connection should get greeting, got: %s", greeting)
	}

	// Poll until activeConns is incremented instead of a fixed sleep
	deadline := time.Now().Add(2 * time.Second)
	for m.activeConns.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if m.activeConns.Load() < 1 {
		t.Fatal("activeConns never incremented")
	}

	// Second connection should be rejected (closed immediately)
	conn2, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("second connect: %v", err)
	}
	defer func() { _ = conn2.Close() }()

	// The rejected connection should be closed by the server
	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn2.Read(buf)
	if err == nil {
		t.Error("second connection should have been closed, but got data")
	}
}

// ── Unit tests for proxy-layer types ──

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
	_ = fw.Close()

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
