package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── Mock upstream types ──

type mockUpstreamMode int

const (
	mockSTARTTLS mockUpstreamMode = iota
	mockPlaintext
	mockImplicitTLS
)

// mockUpstream simulates an upstream IMAP server supporting different connection modes.
type mockUpstream struct {
	listener        net.Listener
	received        []string
	errors          []string
	mu              sync.Mutex
	cert            tls.Certificate
	mode            mockUpstreamMode
	supportCOPYUID  bool // when true, COPY/UID COPY/UID MOVE responses include COPYUID
	supportCompress bool // when true, COMPRESS DEFLATE is accepted
	done            chan struct{}
}

// ── Certificate helpers ──

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

// generateTestCA creates a CA key pair. Returns the parsed CA cert, the CA
// tls.Certificate (for signing), and the path to a temp PEM file containing the CA cert.
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

// ── Test config/rule helpers ──

// testConfig returns a config for tests. Defaults to STARTTLS with skip-verify.
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

// testRules returns the standard three-mailbox deny rules from README.
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

// testDenyUnlessCopiedRules returns ACL rules with deny-unless-copied for EXPUNGE on *trash*.
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

// ── Mock upstream constructors ──

func newMockUpstream(t *testing.T, mode mockUpstreamMode) *mockUpstream {
	t.Helper()
	return newMockUpstreamWithCert(t, mode, generateTestCert(t))
}

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

func newMockUpstreamWithCompress(t *testing.T, mode mockUpstreamMode) *mockUpstream {
	t.Helper()
	m := newMockUpstream(t, mode)
	m.supportCompress = true
	return m
}

// ── Mock upstream methods ──

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
	defer func() { _ = conn.Close() }()

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
	_, _ = fmt.Fprintf(conn, "* OK [CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN] Mock server ready\r\n")
	m.handleIMAPCommands(conn)
}

func (m *mockUpstream) handleSTARTTLSConn(conn net.Conn) {
	_, _ = fmt.Fprintf(conn, "* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED IDLE AUTH=PLAIN] Mock server ready\r\n")

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
	_, _ = fmt.Fprintf(conn, "%s OK Begin TLS\r\n", parts[0])

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{m.cert},
	}
	tlsConn := tls.Server(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		m.recordError(fmt.Sprintf("TLS handshake failed: %v", err))
		return
	}
	defer func() { _ = tlsConn.Close() }()

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
			_, _ = fmt.Fprintf(conn, "+ Ready\r\n")
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
			_, _ = fmt.Fprintf(conn, "%s OK [CAPABILITY IMAP4rev1 IDLE MOVE AUTH=PLAIN] LOGIN completed\r\n", tag)
		case "SELECT", "EXAMINE":
			mailbox := ""
			if len(parts) > 2 {
				mailbox = strings.Trim(parts[2], "\"")
			}
			_, _ = fmt.Fprintf(conn, "* 10 EXISTS\r\n")
			_, _ = fmt.Fprintf(conn, "* 0 RECENT\r\n")
			_, _ = fmt.Fprintf(conn, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n")
			_, _ = fmt.Fprintf(conn, "%s OK [READ-WRITE] %s selected\r\n", tag, mailbox)
		case "COPY":
			if m.supportCOPYUID && len(parts) > 2 {
				// Extract sequence set from "seqset mailbox" args
				copyArgs := strings.SplitN(parts[2], " ", 2)
				seqSet := copyArgs[0]
				_, _ = fmt.Fprintf(conn, "%s OK [COPYUID 12345 %s %s] COPY completed\r\n", tag, seqSet, seqSet)
			} else {
				_, _ = fmt.Fprintf(conn, "%s OK COPY completed\r\n", tag)
			}
		case "STORE":
			_, _ = fmt.Fprintf(conn, "%s OK STORE completed\r\n", tag)
		case "EXPUNGE":
			_, _ = fmt.Fprintf(conn, "%s OK EXPUNGE completed\r\n", tag)
		case "MOVE":
			_, _ = fmt.Fprintf(conn, "%s OK MOVE completed\r\n", tag)
		case "UID":
			if len(parts) > 2 {
				subParts := strings.SplitN(parts[2], " ", 2)
				subCmd := strings.ToUpper(subParts[0])
				if m.supportCOPYUID && (subCmd == "COPY" || subCmd == "MOVE") && len(subParts) > 1 {
					// Extract UID set from "uidset mailbox" args
					uidArgs := strings.SplitN(subParts[1], " ", 2)
					uidSet := uidArgs[0]
					_, _ = fmt.Fprintf(conn, "%s OK [COPYUID 12345 %s %s] UID %s completed\r\n", tag, uidSet, uidSet, subCmd)
				} else {
					_, _ = fmt.Fprintf(conn, "%s OK UID %s completed\r\n", tag, subCmd)
				}
			} else {
				_, _ = fmt.Fprintf(conn, "%s OK UID completed\r\n", tag)
			}
		case "COMPRESS":
			if m.supportCompress && len(parts) > 2 && strings.ToUpper(parts[2]) == "DEFLATE" {
				_, _ = fmt.Fprintf(conn, "%s OK COMPRESS DEFLATE active\r\n", tag)
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
			_, _ = fmt.Fprintf(conn, "%s NO COMPRESS not supported\r\n", tag)
		case "LOGOUT":
			_, _ = fmt.Fprintf(conn, "* BYE logging out\r\n")
			_, _ = fmt.Fprintf(conn, "%s OK LOGOUT completed\r\n", tag)
			return
		case "NOOP":
			_, _ = fmt.Fprintf(conn, "%s OK NOOP completed\r\n", tag)
		default:
			_, _ = fmt.Fprintf(conn, "%s OK %s completed\r\n", tag, cmd)
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
			_, _ = fmt.Fprintf(writer, "* 10 EXISTS\r\n")
			_, _ = fmt.Fprintf(writer, "* 0 RECENT\r\n")
			_, _ = fmt.Fprintf(writer, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n")
			_, _ = fmt.Fprintf(writer, "%s OK [READ-WRITE] %s selected\r\n", tag, mailbox)
		case "LOGOUT":
			_, _ = fmt.Fprintf(writer, "* BYE logging out\r\n")
			_, _ = fmt.Fprintf(writer, "%s OK LOGOUT completed\r\n", tag)
			return
		case "NOOP":
			_, _ = fmt.Fprintf(writer, "%s OK NOOP completed\r\n", tag)
		case "EXPUNGE":
			_, _ = fmt.Fprintf(writer, "%s OK EXPUNGE completed\r\n", tag)
		default:
			_, _ = fmt.Fprintf(writer, "%s OK %s completed\r\n", tag, cmd)
		}
	}
}

// ── Proxy test helpers ──

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
		_ = proxyLn.Close()
		<-proxyDone
		proxyWg.Wait()
		_ = upstream.listener.Close()
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
