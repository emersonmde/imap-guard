package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── COMPRESS DEFLATE types ──

type compressDone struct {
	ok           bool
	clientWriter *syncWriter // shared compressed writer for client
}

// syncWriter wraps an io.Writer with a mutex for concurrent write safety.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (sw *syncWriter) Write(p []byte) (int, error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.w.Write(p)
}

type flushWriter struct {
	w *flate.Writer
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err != nil {
		return n, err
	}
	if err := fw.w.Flush(); err != nil {
		return n, err
	}
	return n, nil
}

type connState struct {
	// selectedMailbox is only accessed from the client→server relay goroutine.
	// No mutex needed — single-goroutine access is the invariant.
	selectedMailbox string

	mu            sync.Mutex
	pendingCopies map[string]bool // tags of in-flight COPY/MOVE commands
	copiedUIDs    map[uint32]bool // source UIDs confirmed copied (from COPYUID)

	// COMPRESS DEFLATE coordination
	compressTag    atomic.Value      // stores string tag when COMPRESS is in-flight
	compressRespCh chan string       // server response line (server→client sends back to client→server)
	compressDoneCh chan compressDone // completion signal with new streams
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

func handleClient(clientConn net.Conn, cfg *config, rules []rule, connID string, m *metrics) {
	// activeConns is incremented by the accept loop before spawning this goroutine
	defer m.activeConns.Add(-1)
	defer func() { _ = clientConn.Close() }()

	upstreamConn, greeting, err := connectToUpstream(cfg)
	if err != nil {
		slog.Error("upstream connect failed", "conn", connID, "err", err)
		return
	}
	defer func() { _ = upstreamConn.Close() }()

	// Strip capabilities when proxy terminates TLS (client connects plaintext)
	if cfg.shouldStripCaps() {
		greeting = stripCaps(greeting)
	}
	if _, err := clientConn.Write([]byte(greeting)); err != nil {
		slog.Error("send greeting failed", "conn", connID, "err", err)
		return
	}

	sessionDeadline := time.Now().Add(cfg.sessionTimeout)
	// Set write deadline to session max; read deadlines are managed by resetDeadline
	_ = clientConn.SetWriteDeadline(sessionDeadline)
	_ = upstreamConn.SetWriteDeadline(sessionDeadline)

	state := &connState{
		compressRespCh: make(chan string, 1),
		compressDoneCh: make(chan compressDone, 1),
	}
	clientReader := bufio.NewReaderSize(clientConn, 8192)
	upstreamReader := bufio.NewReaderSize(upstreamConn, 8192)
	stripCapsRelay := cfg.shouldStripCaps()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 2)

	go func() {
		relayServerToClient(ctx, upstreamReader, upstreamConn, clientConn, clientConn,
			state, connID, stripCapsRelay,
			cfg.idleTimeout, sessionDeadline)
		done <- struct{}{}
	}()

	go func() {
		relayClientToServer(ctx, clientReader, clientConn,
			upstreamConn, upstreamConn,
			state, rules, connID, m,
			cfg.idleTimeout, sessionDeadline)
		done <- struct{}{}
	}()

	<-done   // first goroutine exits
	cancel() // unblock channel waits in the other goroutine
	_ = clientConn.Close()
	_ = upstreamConn.Close()
	<-done // second goroutine exits cleanly

	slog.Info("connection closed", "conn", connID)
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

	greeting, err := readLine(bufio.NewReaderSize(conn, 8192), maxLineLength)
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("read greeting: %w", err)
	}

	return conn, greeting, nil
}

func connectUpstreamSTARTTLS(cfg *config) (net.Conn, string, error) {
	conn, err := net.DialTimeout("tcp", cfg.upstreamAddr, 10*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("dial: %w", err)
	}

	reader := bufio.NewReaderSize(conn, 8192)

	greeting, err := readLine(reader, maxLineLength)
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("read greeting: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "proxy0 STARTTLS\r\n"); err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("send STARTTLS: %w", err)
	}

	resp, err := readLine(reader, maxLineLength)
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("read STARTTLS response: %w", err)
	}
	if !strings.HasPrefix(resp, "proxy0 OK") {
		_ = conn.Close()
		return nil, "", fmt.Errorf("STARTTLS rejected: %s", strings.TrimSpace(resp))
	}

	tlsCfg, err := cfg.buildUpstreamTLSConfig()
	if err != nil {
		_ = conn.Close()
		return nil, "", err
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
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

	greeting, err := readLine(bufio.NewReaderSize(conn, 8192), maxLineLength)
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("read greeting: %w", err)
	}

	return conn, greeting, nil
}

func resetDeadline(conn net.Conn, idleTimeout time.Duration, sessionDeadline time.Time) {
	deadline := time.Now().Add(idleTimeout)
	if deadline.After(sessionDeadline) {
		deadline = sessionDeadline
	}
	_ = conn.SetReadDeadline(deadline)
}

func relayClientToServer(ctx context.Context, clientReader *bufio.Reader, clientConn net.Conn,
	upstreamWriter io.Writer, upstreamConn net.Conn,
	state *connState, rules []rule, connID string, m *metrics,
	idleTimeout time.Duration, sessionDeadline time.Time) {

	var clientWriter io.Writer = clientConn

	for {
		resetDeadline(clientConn, idleTimeout, sessionDeadline)
		line, err := readLine(clientReader, maxLineLength)
		if err != nil {
			return
		}

		tag, cmd, args := parseCommand(line)
		logArgs := args
		if cmd == "LOGIN" || cmd == "AUTHENTICATE" {
			logArgs = "[REDACTED]"
		}
		slog.Debug("client command", "conn", connID, "tag", tag, "cmd", cmd, "args", logArgs)

		// Track mailbox selection
		if cmd == "SELECT" || cmd == "EXAMINE" {
			mailbox := extractMailbox(args)
			// If the mailbox name is sent as a literal, consume it and rewrite as quoted
			if mailbox == "" {
				if n, isPlus, ok := parseLiteralEx(line); ok && n > 0 && n <= 1024 {
					if !isPlus {
						if _, err := clientWriter.Write([]byte("+ go ahead\r\n")); err != nil {
							return
						}
					}
					litBuf := make([]byte, n)
					if _, err := io.ReadFull(clientReader, litBuf); err != nil {
						return
					}
					// Consume continuation line (empty for SELECT/EXAMINE)
					if _, err := readLine(clientReader, maxLineLength); err != nil {
						return
					}
					mailbox = strings.TrimSuffix(strings.TrimSuffix(string(litBuf), "\r\n"), "\n")
					state.selectedMailbox = mailbox
					state.resetCopyState()
					// Rewrite as quoted string and forward to upstream
					quoted, ok := quoteMailbox(mailbox)
					if !ok {
						resp := fmt.Sprintf("%s NO Invalid mailbox name\r\n", tag)
						if _, err := clientWriter.Write([]byte(resp)); err != nil {
							return
						}
						continue
					}
					rewritten := fmt.Sprintf("%s %s %s\r\n", tag, cmd, quoted)
					if _, err := upstreamWriter.Write([]byte(rewritten)); err != nil {
						return
					}
					m.totalProxied.Add(1)
					continue
				} else if ok && n > 1024 {
					// Oversized literal — drain LITERAL+ data before rejecting to prevent state desync
					if isPlus {
						if _, err := io.CopyN(io.Discard, clientReader, n); err != nil {
							return
						}
						if _, err := readLine(clientReader, maxLineLength); err != nil {
							return
						}
					}
					resp := fmt.Sprintf("%s NO Mailbox name too long\r\n", tag)
					if _, err := clientWriter.Write([]byte(resp)); err != nil {
						return
					}
					continue
				}
			}
			if mailbox != "" {
				state.selectedMailbox = mailbox
				state.resetCopyState()
			}
		}

		// Handle DELETE/RENAME with literal mailbox names to prevent ACL bypass.
		// Without this, a client can send the mailbox name as an IMAP literal
		// which extractMailbox returns "" for, causing shouldBlock to skip the check.
		if cmd == "DELETE" || cmd == "RENAME" {
			mailbox := extractMailbox(args)
			if mailbox == "" {
				if n, isPlus, ok := parseLiteralEx(line); ok && n > 0 {
					if n > 1024 {
						// Oversized literal — reject rather than allowing ACL bypass
						if !isPlus {
							if _, err := clientWriter.Write([]byte("+ go ahead\r\n")); err != nil {
								return
							}
						}
						// Drain the literal data so the connection stays in sync
						if _, err := io.CopyN(io.Discard, clientReader, n); err != nil {
							return
						}
						// Drain continuation line
						if _, err := readLine(clientReader, maxLineLength); err != nil {
							return
						}
						resp := fmt.Sprintf("%s NO Mailbox name too long\r\n", tag)
						if _, err := clientWriter.Write([]byte(resp)); err != nil {
							return
						}
						continue
					}
					if !isPlus {
						if _, err := clientWriter.Write([]byte("+ go ahead\r\n")); err != nil {
							return
						}
					}
					litBuf := make([]byte, n)
					if _, err := io.ReadFull(clientReader, litBuf); err != nil {
						return
					}
					// Read the continuation of the command line after the literal
					restLine, err := readLine(clientReader, maxLineLength)
					if err != nil {
						return
					}
					mailbox = strings.TrimSuffix(strings.TrimSuffix(string(litBuf), "\r\n"), "\n")

					// Check ACL against the extracted mailbox name
					result, desc := evalACL(rules, mailbox, cmd, "", "")
					if result != aclAllow {
						resp := fmt.Sprintf("%s NO [NOPERM] Operation blocked by ACL rule\r\n", tag)
						if _, err := clientWriter.Write([]byte(resp)); err != nil {
							return
						}
						m.totalBlocked.Add(1)
						slog.Info("command blocked", "conn", connID, "tag", tag, "cmd", cmd,
							"mailbox", mailbox, "rule", desc)
						continue
					}

					// Allowed — rewrite command using quoted string and forward
					quoted, ok := quoteMailbox(mailbox)
					if !ok {
						resp := fmt.Sprintf("%s NO Invalid mailbox name\r\n", tag)
						if _, err := clientWriter.Write([]byte(resp)); err != nil {
							return
						}
						continue
					}
					restLine = strings.TrimSuffix(strings.TrimSuffix(restLine, "\r\n"), "\n")
					rewrittenLine := fmt.Sprintf("%s %s %s%s\r\n", tag, cmd, quoted, restLine)
					if _, err := upstreamWriter.Write([]byte(rewrittenLine)); err != nil {
						return
					}
					m.totalProxied.Add(1)
					continue
				}
			}
		}

		// Track COPY/MOVE/UID COPY/UID MOVE commands for deny-unless-copied
		switch cmd {
		case "COPY", "MOVE":
			state.recordPendingCopy(tag)
		case "UID":
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
			if _, err := clientWriter.Write([]byte(resp)); err != nil {
				return
			}
			m.totalBlocked.Add(1)
			logBlockedArgs := args
			if len(logBlockedArgs) > 256 {
				logBlockedArgs = logBlockedArgs[:256] + "..."
			}
			slog.Info("command blocked", "conn", connID, "tag", tag, "cmd", cmd,
				"args", logBlockedArgs, "mailbox", state.selectedMailbox, "rule", ruleDesc)
			continue
		}

		// Handle COMPRESS DEFLATE negotiation.
		// ACL check uses the selected mailbox — clients can negotiate COMPRESS from an unprotected mailbox.
		if cmd == "COMPRESS" && strings.ToUpper(strings.TrimSpace(args)) == "DEFLATE" {
			// Signal server→client relay to intercept the response for this tag
			state.compressTag.Store(tag)

			// Forward to upstream
			if _, err := upstreamWriter.Write([]byte(line)); err != nil {
				return
			}
			m.totalProxied.Add(1)

			// Wait for the server response line (sent by server→client relay)
			var respLine string
			select {
			case respLine = <-state.compressRespCh:
			case <-ctx.Done():
				return
			}

			_, rest := parseTaggedResponse(respLine)
			upper := strings.ToUpper(rest)

			if !strings.HasPrefix(upper, "OK") {
				// Server rejected COMPRESS — send response to client, continue uncompressed
				if _, err := clientWriter.Write([]byte(respLine)); err != nil {
					return
				}
				slog.Info("COMPRESS DEFLATE rejected by upstream", "conn", connID)
				continue
			}

			// Server accepted COMPRESS — set up deflate streams
			slog.Info("COMPRESS DEFLATE accepted", "conn", connID)

			// Send the OK response to client (uncompressed — client expects this before switching)
			if _, err := clientWriter.Write([]byte(respLine)); err != nil {
				return
			}

			// Wrap upstream writer with flate
			// error is nil for valid compression levels per compress/flate docs
			upstreamFlate, _ := flate.NewWriter(upstreamConn, flate.DefaultCompression)
			upstreamFW := &flushWriter{w: upstreamFlate}

			// Create a single shared compressed writer for client (used by both goroutines)
			// error is nil for valid compression levels per compress/flate docs
			clientFlate, _ := flate.NewWriter(clientConn, flate.DefaultCompression)
			clientFW := &syncWriter{w: &flushWriter{w: clientFlate}}

			// Signal server→client relay with new writers
			state.compressDoneCh <- compressDone{
				ok:           true,
				clientWriter: clientFW,
			}

			// Swap our own streams
			upstreamWriter = upstreamFW
			clientWriter = clientFW
			clientReader = bufio.NewReaderSize(flate.NewReader(clientConn), 8192)
			continue
		}

		// Forward to upstream
		if _, err := upstreamWriter.Write([]byte(line)); err != nil {
			return
		}
		m.totalProxied.Add(1)

		// Pass through any literal data
		if n, ok := parseLiteral(line); ok {
			if _, err := io.CopyN(upstreamWriter, clientReader, n); err != nil {
				return
			}
		}
	}
}

func relayServerToClient(ctx context.Context, upstreamReader *bufio.Reader, upstreamConn net.Conn,
	clientWriter io.Writer, clientConn net.Conn,
	state *connState, connID string, stripCapabilities bool,
	idleTimeout time.Duration, sessionDeadline time.Time) {

	for {
		resetDeadline(upstreamConn, idleTimeout, sessionDeadline)
		line, err := readLine(upstreamReader, maxLineLength)
		if err != nil {
			return
		}

		if stripCapabilities {
			line = stripCaps(line)
		}

		// Check if this is a response to a COMPRESS DEFLATE command
		if tag, rest := parseTaggedResponse(line); tag != "" {
			if compTag, ok := state.compressTag.Load().(string); ok && compTag == tag {
				// Clear the compress tag
				state.compressTag.Store("")

				// Send the response line to client→server relay
				state.compressRespCh <- line

				upper := strings.ToUpper(rest)
				if !strings.HasPrefix(upper, "OK") {
					// Rejected — continue as normal
					continue
				}

				// Wait for client→server relay to set up streams and signal us
				var done compressDone
				select {
				case done = <-state.compressDoneCh:
				case <-ctx.Done():
					return
				}
				if !done.ok {
					continue
				}

				// Drain any buffered data from old reader
				buffered := upstreamReader.Buffered()
				var newUpstreamReader io.Reader
				if buffered > 0 {
					buf, _ := upstreamReader.Peek(buffered)
					bufCopy := make([]byte, len(buf))
					copy(bufCopy, buf)
					newUpstreamReader = io.MultiReader(bytes.NewReader(bufCopy), upstreamConn)
				} else {
					newUpstreamReader = upstreamConn
				}

				// Wrap upstream reader with flate decompression
				upstreamReader = bufio.NewReaderSize(flate.NewReader(newUpstreamReader), 8192)
				clientWriter = done.clientWriter
				continue
			}

			// Track COPYUID responses for deny-unless-copied
			if state.resolvePendingCopy(tag) {
				upper := strings.ToUpper(rest)
				if strings.HasPrefix(upper, "OK") {
					if uids, ok := parseCOPYUID(line); ok {
						state.recordCopiedUIDs(uids)
					}
				}
			}
		}

		if _, err := clientWriter.Write([]byte(line)); err != nil {
			return
		}

		// Pass through any literal data
		if n, ok := parseLiteral(line); ok {
			if _, err := io.CopyN(clientWriter, upstreamReader, n); err != nil {
				return
			}
		}
	}
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
