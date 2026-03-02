package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type upstreamTLSMode int

const (
	upstreamPlaintext  upstreamTLSMode = iota
	upstreamSTARTTLS
	upstreamImplicitTLS
)

type config struct {
	listenAddr     string
	upstreamAddr   string
	upstreamTLS    upstreamTLSMode
	upstreamVerify string // "verify", "skip", or CA file path
	clientTLSCert  string
	clientTLSKey   string
}

func parseConfig() (*config, error) {
	cfg := &config{
		listenAddr:     envOrDefault("IMAP_GUARD_LISTEN", ":1143"),
		upstreamAddr:   envOrDefault("IMAP_GUARD_UPSTREAM", "127.0.0.1:143"),
		upstreamVerify: envOrDefault("IMAP_GUARD_UPSTREAM_VERIFY", "verify"),
		clientTLSCert:  os.Getenv("IMAP_GUARD_CLIENT_TLS_CERT"),
		clientTLSKey:   os.Getenv("IMAP_GUARD_CLIENT_TLS_KEY"),
	}

	switch strings.ToLower(envOrDefault("IMAP_GUARD_UPSTREAM_TLS", "starttls")) {
	case "plaintext":
		cfg.upstreamTLS = upstreamPlaintext
	case "starttls":
		cfg.upstreamTLS = upstreamSTARTTLS
	case "tls":
		cfg.upstreamTLS = upstreamImplicitTLS
	default:
		return nil, fmt.Errorf("invalid IMAP_GUARD_UPSTREAM_TLS value %q (must be plaintext, starttls, or tls)",
			os.Getenv("IMAP_GUARD_UPSTREAM_TLS"))
	}

	// Verify settings are meaningless without TLS
	if cfg.upstreamTLS == upstreamPlaintext && cfg.upstreamVerify != "verify" {
		return nil, fmt.Errorf("IMAP_GUARD_UPSTREAM_VERIFY=%q has no effect with plaintext upstream (no TLS to verify)",
			cfg.upstreamVerify)
	}

	// Validate verify setting
	if cfg.upstreamVerify != "verify" && cfg.upstreamVerify != "skip" {
		if _, err := os.Stat(cfg.upstreamVerify); err != nil {
			return nil, fmt.Errorf("CA file %q: %w", cfg.upstreamVerify, err)
		}
	}

	// Client TLS: both or neither
	if (cfg.clientTLSCert == "") != (cfg.clientTLSKey == "") {
		return nil, fmt.Errorf("IMAP_GUARD_CLIENT_TLS_CERT and IMAP_GUARD_CLIENT_TLS_KEY must both be set or both be empty")
	}
	if cfg.clientTLSCert != "" {
		if _, err := os.Stat(cfg.clientTLSCert); err != nil {
			return nil, fmt.Errorf("client TLS cert %q: %w", cfg.clientTLSCert, err)
		}
		if _, err := os.Stat(cfg.clientTLSKey); err != nil {
			return nil, fmt.Errorf("client TLS key %q: %w", cfg.clientTLSKey, err)
		}
	}

	return cfg, nil
}

func (c *config) clientTLSEnabled() bool {
	return c.clientTLSCert != "" && c.clientTLSKey != ""
}

func (c *config) shouldStripCaps() bool {
	return !c.clientTLSEnabled()
}

func (c *config) buildUpstreamTLSConfig() (*tls.Config, error) {
	host, _, err := net.SplitHostPort(c.upstreamAddr)
	if err != nil {
		host = c.upstreamAddr
	}

	tlsCfg := &tls.Config{
		ServerName: host,
	}

	switch c.upstreamVerify {
	case "verify":
		// Default system CA pool, no changes needed
	case "skip":
		tlsCfg.InsecureSkipVerify = true
	default:
		// CA file path
		pemData, err := os.ReadFile(c.upstreamVerify)
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", c.upstreamVerify, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("CA file %q contains no valid certificates", c.upstreamVerify)
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}

var protectedKeywords = []string{"trash", "drafts", "junk"}

var reCapStrip = regexp.MustCompile(`(?i)\s+(STARTTLS|LOGINDISABLED)`)

type connState struct {
	selectedMailbox string
	isProtected     bool
}

func main() {
	cfg, err := parseConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("imap-guard starting: listen=%s upstream=%s tls=%s",
		cfg.listenAddr, cfg.upstreamAddr, []string{"plaintext", "starttls", "tls"}[cfg.upstreamTLS])

	var ln net.Listener
	if cfg.clientTLSEnabled() {
		cert, err := tls.LoadX509KeyPair(cfg.clientTLSCert, cfg.clientTLSKey)
		if err != nil {
			log.Fatalf("load client TLS cert/key: %v", err)
		}
		ln, err = tls.Listen("tcp", cfg.listenAddr, &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
		if err != nil {
			log.Fatalf("failed to listen (TLS) on %s: %v", cfg.listenAddr, err)
		}
		log.Printf("client-side TLS enabled")
	} else {
		ln, err = net.Listen("tcp", cfg.listenAddr)
		if err != nil {
			log.Fatalf("failed to listen on %s: %v", cfg.listenAddr, err)
		}
	}

	var connCounter uint64
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		connID := fmt.Sprintf("C%d", atomic.AddUint64(&connCounter, 1))
		log.Printf("ACCEPT %s from %s", connID, conn.RemoteAddr())
		go handleClient(conn, cfg, connID)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func handleClient(clientConn net.Conn, cfg *config, connID string) {
	defer clientConn.Close()

	upstreamConn, greeting, err := connectToUpstream(cfg)
	if err != nil {
		log.Printf("ERROR %s: upstream connect: %v", connID, err)
		return
	}
	defer upstreamConn.Close()

	// Strip capabilities when proxy terminates TLS (client connects plaintext)
	if cfg.shouldStripCaps() {
		greeting = stripCaps(greeting)
	}
	if _, err := clientConn.Write([]byte(greeting)); err != nil {
		log.Printf("ERROR %s: send greeting: %v", connID, err)
		return
	}

	state := &connState{}
	clientReader := bufio.NewReaderSize(clientConn, 8192)
	upstreamReader := bufio.NewReaderSize(upstreamConn, 8192)
	stripCapsRelay := cfg.shouldStripCaps()

	done := make(chan struct{}, 2)

	go func() {
		relayServerToClient(upstreamReader, clientConn, connID, stripCapsRelay)
		done <- struct{}{}
	}()

	go func() {
		relayClientToServer(clientReader, upstreamConn, clientConn, state, connID)
		done <- struct{}{}
	}()

	<-done
	clientConn.Close()
	upstreamConn.Close()
	<-done

	log.Printf("CLOSED %s", connID)
}

func connectToUpstream(cfg *config) (net.Conn, string, error) {
	switch cfg.upstreamTLS {
	case upstreamPlaintext:
		return connectUpstreamPlaintext(cfg.upstreamAddr)
	case upstreamSTARTTLS:
		return connectUpstreamSTARTTLS(cfg)
	case upstreamImplicitTLS:
		return connectUpstreamTLS(cfg)
	default:
		return nil, "", fmt.Errorf("unknown upstream TLS mode: %d", cfg.upstreamTLS)
	}
}

func connectUpstreamPlaintext(addr string) (net.Conn, string, error) {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("dial: %w", err)
	}

	greeting, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("read greeting: %w", err)
	}

	return conn, greeting, nil
}

func connectUpstreamSTARTTLS(cfg *config) (net.Conn, string, error) {
	conn, err := net.DialTimeout("tcp", cfg.upstreamAddr, 10*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("dial: %w", err)
	}

	reader := bufio.NewReader(conn)

	greeting, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("read greeting: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "proxy0 STARTTLS\r\n"); err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("send STARTTLS: %w", err)
	}

	resp, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("read STARTTLS response: %w", err)
	}
	if !strings.HasPrefix(resp, "proxy0 OK") {
		conn.Close()
		return nil, "", fmt.Errorf("STARTTLS rejected: %s", strings.TrimSpace(resp))
	}

	tlsCfg, err := cfg.buildUpstreamTLSConfig()
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("TLS handshake: %w", err)
	}

	return tlsConn, greeting, nil
}

func connectUpstreamTLS(cfg *config) (net.Conn, string, error) {
	tlsCfg, err := cfg.buildUpstreamTLSConfig()
	if err != nil {
		return nil, "", err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", cfg.upstreamAddr, tlsCfg)
	if err != nil {
		return nil, "", fmt.Errorf("dial TLS: %w", err)
	}

	greeting, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("read greeting: %w", err)
	}

	return conn, greeting, nil
}

func relayClientToServer(client *bufio.Reader, upstream, clientConn net.Conn, state *connState, connID string) {
	for {
		line, err := client.ReadString('\n')
		if err != nil {
			return
		}

		tag, cmd, args := parseCommand(line)

		// Track mailbox selection
		if cmd == "SELECT" || cmd == "EXAMINE" {
			mailbox := extractMailbox(args)
			// If the mailbox name is sent as a literal, read it from the stream
			if mailbox == "" {
				if n, ok := parseLiteral(line); ok && n > 0 && n <= 1024 {
					// Forward the command line first
					if _, err := upstream.Write([]byte(line)); err != nil {
						return
					}
					// Read the literal mailbox name from client and forward it
					litBuf := make([]byte, n)
					if _, err := io.ReadFull(client, litBuf); err != nil {
						return
					}
					if _, err := upstream.Write(litBuf); err != nil {
						return
					}
					mailbox = strings.TrimRight(string(litBuf), "\r\n")
					state.selectedMailbox = mailbox
					state.isProtected = isProtected(mailbox)
					continue
				}
			}
			if mailbox != "" {
				state.selectedMailbox = mailbox
				state.isProtected = isProtected(mailbox)
			}
		}

		// Block forbidden operations on protected mailboxes
		if shouldBlock(cmd, args, state) {
			resp := fmt.Sprintf("%s NO [NOPERM] Operation blocked on protected mailbox\r\n", tag)
			if _, err := clientConn.Write([]byte(resp)); err != nil {
				return
			}
			log.Printf("BLOCKED %s: %s %s %s (mailbox=%s)", connID, tag, cmd, args, state.selectedMailbox)
			continue
		}

		// Forward to upstream
		if _, err := upstream.Write([]byte(line)); err != nil {
			return
		}

		// Pass through any literal data
		if n, ok := parseLiteral(line); ok {
			if _, err := io.CopyN(upstream, client, n); err != nil {
				return
			}
		}
	}
}

func relayServerToClient(upstream *bufio.Reader, clientConn net.Conn, connID string, stripCapabilities bool) {
	for {
		line, err := upstream.ReadString('\n')
		if err != nil {
			return
		}

		if stripCapabilities {
			line = stripCaps(line)
		}

		if _, err := clientConn.Write([]byte(line)); err != nil {
			return
		}

		// Pass through any literal data
		if n, ok := parseLiteral(line); ok {
			if _, err := io.CopyN(clientConn, upstream, n); err != nil {
				return
			}
		}
	}
}

// parseCommand extracts tag, command (uppercased), and remaining args from an IMAP client line.
func parseCommand(line string) (tag, cmd, args string) {
	line = strings.TrimRight(line, "\r\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return "", "", ""
	}
	tag = parts[0]
	cmd = strings.ToUpper(parts[1])
	if len(parts) > 2 {
		args = parts[2]
	}
	return
}

// extractMailbox extracts the mailbox name from SELECT/EXAMINE arguments.
func extractMailbox(args string) string {
	args = strings.TrimSpace(args)
	if len(args) == 0 {
		return ""
	}
	if args[0] == '"' {
		// Quoted string
		for i := 1; i < len(args); i++ {
			if args[i] == '\\' && i+1 < len(args) {
				i++
				continue
			}
			if args[i] == '"' {
				return args[1:i]
			}
		}
		return args[1:] // malformed, best effort
	}
	if args[0] == '{' {
		// Literal — can't extract inline, return empty (errs on side of permissiveness)
		return ""
	}
	// Unquoted atom
	if idx := strings.IndexByte(args, ' '); idx >= 0 {
		return args[:idx]
	}
	return args
}

func isProtected(mailbox string) bool {
	lower := strings.ToLower(mailbox)
	for _, keyword := range protectedKeywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func shouldBlock(cmd, args string, state *connState) bool {
	// DELETE and RENAME target a named mailbox, not the selected one
	switch cmd {
	case "DELETE":
		mailbox := extractMailbox(args)
		return mailbox != "" && isProtected(mailbox)
	case "RENAME":
		mailbox := extractMailbox(args)
		return mailbox != "" && isProtected(mailbox)
	case "COMPRESS":
		// COMPRESS would make traffic opaque, bypassing ACL enforcement
		return state.isProtected
	}

	if !state.isProtected {
		return false
	}

	switch cmd {
	case "EXPUNGE", "CLOSE", "MOVE":
		return true
	case "STORE":
		return storeAddsDeleted(args)
	case "UID":
		subParts := strings.SplitN(args, " ", 2)
		if len(subParts) == 0 {
			return false
		}
		subCmd := strings.ToUpper(subParts[0])
		switch subCmd {
		case "EXPUNGE", "MOVE":
			return true
		case "STORE":
			if len(subParts) > 1 {
				return storeAddsDeleted(subParts[1])
			}
		}
	}
	return false
}

// storeAddsDeleted checks if STORE args would add the \Deleted flag.
// Format: sequence-set SP [+/-]FLAGS[.SILENT] SP flag-list
func storeAddsDeleted(args string) bool {
	upper := strings.ToUpper(args)
	if !strings.Contains(upper, `\DELETED`) {
		return false
	}

	parts := strings.SplitN(strings.TrimSpace(args), " ", 3)
	if len(parts) < 3 {
		return false
	}

	flagOp := strings.ToUpper(parts[1])

	// -FLAGS removes flags — allow it
	if strings.HasPrefix(flagOp, "-") {
		return false
	}

	// +FLAGS, +FLAGS.SILENT, FLAGS, FLAGS.SILENT with \Deleted → block
	if flagOp == "FLAGS" || flagOp == "FLAGS.SILENT" ||
		flagOp == "+FLAGS" || flagOp == "+FLAGS.SILENT" {
		return strings.Contains(strings.ToUpper(parts[2]), `\DELETED`)
	}

	return false
}

// stripCaps removes STARTTLS and LOGINDISABLED from IMAP capability lines.
// Only modifies lines that are capability responses to avoid corrupting message bodies.
func stripCaps(line string) string {
	upper := strings.ToUpper(line)
	// Only apply to capability lines: "* CAPABILITY ..." or "* OK [CAPABILITY ...]" or tagged "OK [CAPABILITY ...]"
	if !strings.Contains(upper, "CAPABILITY") {
		return line
	}
	if !strings.Contains(upper, "STARTTLS") && !strings.Contains(upper, "LOGINDISABLED") {
		return line
	}
	return reCapStrip.ReplaceAllString(line, "")
}

// parseLiteral checks if a line ends with {N} or {N+} before CRLF and returns N.
func parseLiteral(line string) (int64, bool) {
	trimmed := strings.TrimRight(line, "\r\n")
	if !strings.HasSuffix(trimmed, "}") {
		return 0, false
	}
	idx := strings.LastIndex(trimmed, "{")
	if idx < 0 {
		return 0, false
	}
	numStr := trimmed[idx+1 : len(trimmed)-1]
	numStr = strings.TrimSuffix(numStr, "+") // LITERAL+ syntax
	n, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
