package main

import (
	"bufio"
	"crypto/tls"
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

var protectedKeywords = []string{"trash", "drafts", "junk"}

var reCapStrip = regexp.MustCompile(`(?i)\s+(STARTTLS|LOGINDISABLED)`)

type connState struct {
	selectedMailbox string
	isProtected     bool
}

func main() {
	listenAddr := envOrDefault("IMAP_GUARD_LISTEN", ":1143")
	upstreamAddr := envOrDefault("IMAP_GUARD_UPSTREAM", "127.0.0.1:143")

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("imap-guard starting: listen=%s upstream=%s", listenAddr, upstreamAddr)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", listenAddr, err)
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
		go handleClient(conn, upstreamAddr, connID)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func handleClient(clientConn net.Conn, upstreamAddr, connID string) {
	defer clientConn.Close()

	upstreamConn, greeting, err := connectToUpstream(upstreamAddr)
	if err != nil {
		log.Printf("ERROR %s: upstream connect: %v", connID, err)
		return
	}
	defer upstreamConn.Close()

	// Send modified greeting to client
	if _, err := clientConn.Write([]byte(stripCaps(greeting))); err != nil {
		log.Printf("ERROR %s: send greeting: %v", connID, err)
		return
	}

	state := &connState{}
	clientReader := bufio.NewReaderSize(clientConn, 8192)
	upstreamReader := bufio.NewReaderSize(upstreamConn, 8192)

	done := make(chan struct{}, 2)

	go func() {
		relayServerToClient(upstreamReader, clientConn, connID)
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

func connectToUpstream(addr string) (net.Conn, string, error) {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("dial: %w", err)
	}

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("read greeting: %w", err)
	}

	// Send STARTTLS
	if _, err := fmt.Fprintf(conn, "proxy0 STARTTLS\r\n"); err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("send STARTTLS: %w", err)
	}

	// Read STARTTLS response
	resp, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("read STARTTLS response: %w", err)
	}
	if !strings.HasPrefix(resp, "proxy0 OK") {
		conn.Close()
		return nil, "", fmt.Errorf("STARTTLS rejected: %s", strings.TrimSpace(resp))
	}

	// Upgrade to TLS
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("TLS handshake: %w", err)
	}

	return tlsConn, greeting, nil
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

func relayServerToClient(upstream *bufio.Reader, clientConn net.Conn, connID string) {
	for {
		line, err := upstream.ReadString('\n')
		if err != nil {
			return
		}

		line = stripCaps(line)

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
