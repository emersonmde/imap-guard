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
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
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

var reCapStrip = regexp.MustCompile(`(?i)\s+(STARTTLS|LOGINDISABLED)`)

type aclResult int

const (
	aclAllow           aclResult = iota
	aclDeny
	aclDenyUnlessCopied
)

const maxUIDSetExpansion = 10000

type connState struct {
	selectedMailbox string

	mu            sync.Mutex
	pendingCopies map[string]bool  // tags of in-flight COPY/MOVE commands
	copiedUIDs    map[uint32]bool  // source UIDs confirmed copied (from COPYUID)
}

func (s *connState) recordPendingCopy(tag string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingCopies == nil {
		s.pendingCopies = make(map[string]bool)
	}
	s.pendingCopies[tag] = true
}

func (s *connState) resolvePendingCopy(tag string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingCopies == nil {
		return false
	}
	if s.pendingCopies[tag] {
		delete(s.pendingCopies, tag)
		return true
	}
	return false
}

func (s *connState) recordCopiedUIDs(uids []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.copiedUIDs == nil {
		s.copiedUIDs = make(map[uint32]bool)
	}
	for _, uid := range uids {
		s.copiedUIDs[uid] = true
	}
}

func (s *connState) allUIDsCopied(uids []uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(uids) == 0 || s.copiedUIDs == nil {
		return false
	}
	for _, uid := range uids {
		if !s.copiedUIDs[uid] {
			return false
		}
	}
	return true
}

func (s *connState) resetCopyState() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingCopies = nil
	s.copiedUIDs = nil
}

// ── ACL types ──

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

// ── Glob matcher ──

// globMatch matches pattern against name, case-insensitively.
// * matches any sequence of characters (including / and .).
// ? matches exactly one character.
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

// ── Config parsing ──

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

var validDenyCommands = map[string]bool{
	"EXPUNGE": true, "CLOSE": true, "DELETE": true,
	"RENAME": true, "MOVE": true, "STORE": true, "COMPRESS": true,
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

// ── STORE args parser ──

// parseStoreArgs extracts the operation type and flags from STORE command arguments.
// Format: sequence-set SP [+/-]FLAGS[.SILENT] SP flag-list
// Returns op ("+" for +FLAGS/FLAGS, "-" for -FLAGS) and uppercased flags string.
func parseStoreArgs(args string) (op, flags string) {
	parts := strings.SplitN(strings.TrimSpace(args), " ", 3)
	if len(parts) < 3 {
		return "", ""
	}

	flagOp := strings.ToUpper(parts[1])

	if strings.HasPrefix(flagOp, "-") {
		op = "-"
	} else if strings.HasPrefix(flagOp, "+") {
		op = "+"
	} else {
		// Bare FLAGS or FLAGS.SILENT — equivalent to replacing, treat as "+"
		op = "+"
	}

	// Validate it's actually a FLAGS operation
	base := strings.TrimPrefix(strings.TrimPrefix(flagOp, "+"), "-")
	if base != "FLAGS" && base != "FLAGS.SILENT" {
		return "", ""
	}

	flags = strings.ToUpper(parts[2])
	return op, flags
}

// ── Rule evaluation ──

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
		if d.storeOp == "+" && storeOp == "+" && strings.Contains(storeFlags, d.storeFlag) {
			desc := fmt.Sprintf("mailbox=%q deny=STORE %s%s", r.mailbox, d.storeOp, d.storeFlag)
			return aclDeny, desc
		}
		if d.storeOp == "-" && storeOp == "-" && strings.Contains(storeFlags, d.storeFlag) {
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

func main() {
	cfg, err := parseConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	rules, err := loadACLConfig(os.Getenv("IMAP_GUARD_CONFIG"))
	if err != nil {
		log.Fatalf("ACL config error: %v", err)
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("imap-guard starting: listen=%s upstream=%s tls=%s",
		cfg.listenAddr, cfg.upstreamAddr, []string{"plaintext", "starttls", "tls"}[cfg.upstreamTLS])
	if rules == nil {
		log.Printf("no ACL config: operating as pure pass-through proxy")
	} else {
		log.Printf("ACL config loaded: %d rules", len(rules))
	}

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
		go handleClient(conn, cfg, rules, connID)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func handleClient(clientConn net.Conn, cfg *config, rules []rule, connID string) {
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
		relayServerToClient(upstreamReader, clientConn, state, connID, stripCapsRelay)
		done <- struct{}{}
	}()

	go func() {
		relayClientToServer(clientReader, upstreamConn, clientConn, state, rules, connID)
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

func relayClientToServer(client *bufio.Reader, upstream, clientConn net.Conn, state *connState, rules []rule, connID string) {
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
					state.resetCopyState()
					// Literal path: already forwarded above, skip normal forwarding
					continue
				}
			}
			if mailbox != "" {
				state.selectedMailbox = mailbox
				state.resetCopyState()
			}
		}

		// Track COPY/MOVE/UID COPY/UID MOVE commands for deny-unless-copied
		if cmd == "COPY" || cmd == "MOVE" {
			state.recordPendingCopy(tag)
		} else if cmd == "UID" {
			subParts := strings.SplitN(args, " ", 2)
			if len(subParts) > 0 {
				subCmd := strings.ToUpper(subParts[0])
				if subCmd == "COPY" || subCmd == "MOVE" {
					state.recordPendingCopy(tag)
				}
			}
		}

		// Block forbidden operations per ACL rules
		if blocked, ruleDesc := shouldBlock(cmd, args, state, rules); blocked {
			resp := fmt.Sprintf("%s NO [NOPERM] Operation blocked by ACL rule\r\n", tag)
			if _, err := clientConn.Write([]byte(resp)); err != nil {
				return
			}
			log.Printf("BLOCKED %s: %s %s %s (mailbox=%s, %s)", connID, tag, cmd, args, state.selectedMailbox, ruleDesc)
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

func relayServerToClient(upstream *bufio.Reader, clientConn net.Conn, state *connState, connID string, stripCapabilities bool) {
	for {
		line, err := upstream.ReadString('\n')
		if err != nil {
			return
		}

		if stripCapabilities {
			line = stripCaps(line)
		}

		// Track COPYUID responses for deny-unless-copied
		if tag, rest := parseTaggedResponse(line); tag != "" {
			if state.resolvePendingCopy(tag) {
				// This is a response to a COPY/MOVE command we tracked
				upper := strings.ToUpper(rest)
				if strings.HasPrefix(upper, "OK") {
					if uids, ok := parseCOPYUID(line); ok {
						state.recordCopiedUIDs(uids)
					}
				}
				// NO/BAD: copy failed, no UIDs recorded
			}
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

func shouldBlock(cmd, args string, state *connState, rules []rule) (bool, string) {
	if len(rules) == 0 {
		return false, ""
	}

	// DELETE and RENAME target a named mailbox, not the selected one
	switch cmd {
	case "DELETE":
		mailbox := extractMailbox(args)
		if mailbox == "" {
			return false, ""
		}
		result, desc := evalACL(rules, mailbox, "DELETE", "", "")
		return result != aclAllow, desc
	case "RENAME":
		mailbox := extractMailbox(args)
		if mailbox == "" {
			return false, ""
		}
		result, desc := evalACL(rules, mailbox, "RENAME", "", "")
		return result != aclAllow, desc
	}

	mailbox := state.selectedMailbox
	if mailbox == "" {
		return false, ""
	}

	switch cmd {
	case "EXPUNGE":
		result, desc := evalACL(rules, mailbox, "EXPUNGE", "", "")
		if result == aclDenyUnlessCopied {
			// Plain EXPUNGE affects all \Deleted messages — can't verify which UIDs
			return true, desc
		}
		return result == aclDeny, desc
	case "CLOSE", "MOVE", "COMPRESS":
		result, desc := evalACL(rules, mailbox, cmd, "", "")
		return result != aclAllow, desc
	case "STORE":
		op, flags := parseStoreArgs(args)
		result, desc := evalACL(rules, mailbox, "STORE", op, flags)
		return result != aclAllow, desc
	case "UID":
		subParts := strings.SplitN(args, " ", 2)
		if len(subParts) == 0 {
			return false, ""
		}
		subCmd := strings.ToUpper(subParts[0])
		switch subCmd {
		case "EXPUNGE":
			result, desc := evalACL(rules, mailbox, "EXPUNGE", "", "")
			if result == aclDeny {
				return true, desc
			}
			if result == aclDenyUnlessCopied {
				// UID EXPUNGE <uid-set>: check if all UIDs have been copied
				if len(subParts) < 2 {
					return true, desc
				}
				uidSetStr := strings.TrimSpace(subParts[1])
				uids, ok := parseUIDSet(uidSetStr)
				if !ok {
					return true, desc // unparseable or too large → block
				}
				if state.allUIDsCopied(uids) {
					return false, ""
				}
				return true, desc
			}
			return false, ""
		case "MOVE":
			result, desc := evalACL(rules, mailbox, "MOVE", "", "")
			return result != aclAllow, desc
		case "STORE":
			if len(subParts) > 1 {
				op, flags := parseStoreArgs(subParts[1])
				result, desc := evalACL(rules, mailbox, "STORE", op, flags)
				return result != aclAllow, desc
			}
		}
	}
	return false, ""
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

// ── UID set and COPYUID parsing ──

// parseUIDSet expands UID set syntax (e.g. "1", "1:5", "1,3:5") into individual UIDs.
// Returns (nil, false) for "*", ranges exceeding maxUIDSetExpansion, or parse errors.
func parseUIDSet(s string) ([]uint32, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "*") {
		return nil, false
	}

	var result []uint32
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, false
		}
		if idx := strings.IndexByte(part, ':'); idx >= 0 {
			lo, err := strconv.ParseUint(part[:idx], 10, 32)
			if err != nil || lo == 0 {
				return nil, false
			}
			hi, err := strconv.ParseUint(part[idx+1:], 10, 32)
			if err != nil || hi == 0 {
				return nil, false
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			count := hi - lo + 1
			if count > maxUIDSetExpansion || len(result)+int(count) > maxUIDSetExpansion {
				return nil, false
			}
			for uid := lo; uid <= hi; uid++ {
				result = append(result, uint32(uid))
			}
		} else {
			uid, err := strconv.ParseUint(part, 10, 32)
			if err != nil || uid == 0 {
				return nil, false
			}
			if len(result)+1 > maxUIDSetExpansion {
				return nil, false
			}
			result = append(result, uint32(uid))
		}
	}
	return result, len(result) > 0
}

// parseCOPYUID extracts source UIDs from a COPYUID response code in a tagged OK line.
// Format: tag OK [COPYUID <uidvalidity> <source-uids> <dest-uids>] ...
// Returns the expanded source UIDs and true on success.
func parseCOPYUID(line string) ([]uint32, bool) {
	upper := strings.ToUpper(line)
	idx := strings.Index(upper, "[COPYUID ")
	if idx < 0 {
		return nil, false
	}
	// Find the closing ]
	rest := line[idx+len("[COPYUID "):]
	closeBracket := strings.IndexByte(rest, ']')
	if closeBracket < 0 {
		return nil, false
	}
	// Fields: <uidvalidity> <source-uids> <dest-uids>
	fields := strings.Fields(rest[:closeBracket])
	if len(fields) != 3 {
		return nil, false
	}
	return parseUIDSet(fields[1])
}

// parseTaggedResponse extracts the tag from a server response line.
// Returns ("", "") for untagged (*) and continuation (+) lines.
func parseTaggedResponse(line string) (tag, rest string) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", ""
	}
	if line[0] == '*' || line[0] == '+' {
		return "", ""
	}
	idx := strings.IndexByte(line, ' ')
	if idx < 0 {
		return line, ""
	}
	return line[:idx], line[idx+1:]
}
