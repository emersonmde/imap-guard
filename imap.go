package main

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const maxLineLength = 65536 // 64 KiB — generous for IMAP command/response lines
const maxUIDSetExpansion = 10000

// readLine reads a line (up to and including '\n') from r, returning an error
// if the line exceeds maxLen bytes. This prevents unbounded memory allocation
// from a malicious peer that sends data without newlines.
func readLine(r *bufio.Reader, maxLen int) (string, error) {
	var buf []byte
	for {
		slice, err := r.ReadSlice('\n')
		buf = append(buf, slice...)
		if len(buf) > maxLen {
			return "", fmt.Errorf("line exceeds maximum length (%d bytes)", maxLen)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return string(buf), err
		}
		return string(buf), nil
	}
}

var reCapStrip = regexp.MustCompile(`(?i)\s+(STARTTLS|LOGINDISABLED)`)

// stripCaps removes STARTTLS and LOGINDISABLED from IMAP capability lines.
// Only modifies lines that are capability responses to avoid corrupting message bodies.
func stripCaps(line string) string {
	upper := strings.ToUpper(line)
	if !strings.Contains(upper, "CAPABILITY") {
		return line
	}
	if !strings.Contains(upper, "STARTTLS") && !strings.Contains(upper, "LOGINDISABLED") {
		return line
	}
	return reCapStrip.ReplaceAllString(line, "")
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
// Quoted strings are unescaped (\\→\, \"→").
func extractMailbox(args string) string {
	args = strings.TrimSpace(args)
	if len(args) == 0 {
		return ""
	}
	if args[0] == '"' {
		var b strings.Builder
		for i := 1; i < len(args); i++ {
			if args[i] == '\\' && i+1 < len(args) {
				i++
				b.WriteByte(args[i])
				continue
			}
			if args[i] == '"' {
				return b.String()
			}
			b.WriteByte(args[i])
		}
		return b.String() // malformed, best effort
	}
	if args[0] == '{' {
		return ""
	}
	if idx := strings.IndexByte(args, ' '); idx >= 0 {
		return args[:idx]
	}
	return args
}

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

	base := strings.TrimPrefix(strings.TrimPrefix(flagOp, "+"), "-")
	if base != "FLAGS" && base != "FLAGS.SILENT" {
		return "", ""
	}

	flags = strings.ToUpper(parts[2])
	return op, flags
}

// containsFlag checks if the IMAP flag string contains an exact flag token.
// Flags are space-separated and may be wrapped in parentheses.
// Both arguments are expected to be already uppercased by callers.
func containsFlag(flagStr, flag string) bool {
	flagStr = strings.TrimPrefix(flagStr, "(")
	flagStr = strings.TrimSuffix(flagStr, ")")
	for _, token := range strings.Fields(flagStr) {
		if token == flag {
			return true
		}
	}
	return false
}

// parseLiteralEx checks if a line ends with {N} or {N+} before CRLF.
// Returns the byte count, whether it's LITERAL+ (non-synchronizing), and whether a literal was found.
func parseLiteralEx(line string) (n int64, isPlus bool, ok bool) {
	trimmed := strings.TrimRight(line, "\r\n")
	if !strings.HasSuffix(trimmed, "}") {
		return 0, false, false
	}
	idx := strings.LastIndex(trimmed, "{")
	if idx < 0 {
		return 0, false, false
	}
	numStr := trimmed[idx+1 : len(trimmed)-1]
	if strings.HasSuffix(numStr, "+") {
		isPlus = true
		numStr = numStr[:len(numStr)-1]
	}
	val, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil || val < 0 {
		return 0, false, false
	}
	return val, isPlus, true
}

// parseLiteral checks if a line ends with {N} or {N+} before CRLF and returns N.
func parseLiteral(line string) (int64, bool) {
	n, _, ok := parseLiteralEx(line)
	return n, ok
}

// quoteMailbox returns the mailbox name as a quoted IMAP string.
// Returns ("", false) if the name contains CR, LF, or NUL which cannot be quoted.
func quoteMailbox(name string) (string, bool) {
	if strings.ContainsAny(name, "\r\n\x00") {
		return "", false
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(name); i++ {
		if name[i] == '\\' || name[i] == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(name[i])
	}
	b.WriteByte('"')
	return b.String(), true
}

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
func parseCOPYUID(line string) ([]uint32, bool) {
	upper := strings.ToUpper(line)
	idx := strings.Index(upper, "[COPYUID ")
	if idx < 0 {
		return nil, false
	}
	rest := line[idx+len("[COPYUID "):]
	closeBracket := strings.IndexByte(rest, ']')
	if closeBracket < 0 {
		return nil, false
	}
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
