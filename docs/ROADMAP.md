# imap-guard Development Roadmap

## Design Principles

- **Thin proxy**: minimal overhead, pass everything through unless a rule says otherwise
- **Allow by default**: the proxy passes everything through with no blocking unless ACL rules are explicitly configured
- **No protocol rewriting**: avoid modifying IMAP traffic beyond what's necessary for the proxy to function (capability stripping, ACL enforcement)
- **Simple configuration**: easy to set up for common cases, extensible for complex ones

---

## v0.1 — Current State

Single-file IMAP proxy with hardcoded protections.

- Listens for plaintext IMAP connections
- Connects to upstream via STARTTLS (assumes Proton Bridge-style setup)
- Strips STARTTLS and LOGINDISABLED capabilities
- Blocks EXPUNGE and STORE +\Deleted on hardcoded Trash/Drafts mailboxes
- Full test suite with mock upstream server

### Known Issues

- `InsecureSkipVerify: true` is hardcoded with no option for real cert verification
- Upstream connection mode is hardcoded to STARTTLS (no plaintext or implicit TLS)
- `stripCaps` runs on all server traffic including message bodies — will corrupt emails containing "STARTTLS" in the body text
- `CLOSE` command is not blocked but implicitly expunges all \Deleted messages (protection bypass)
- `DELETE` command is not blocked — can destroy an entire protected mailbox and all its contents
- `RENAME` command is not blocked — can rename a protected mailbox to an unprotected name, bypassing all rules
- `MOVE` from a protected mailbox is not blocked — can relocate messages to an unprotected mailbox where they can then be deleted
- `COMPRESS` extension (RFC 4978) is not handled — if negotiated, all subsequent traffic is opaque to the proxy and ACLs become unenforceable
- Literal mailbox names (`SELECT {5}\r\nTrash`) bypass protection entirely
- Protected mailbox list is hardcoded, not configurable
- Default listen port is `:144` (not standard IMAP port 143, requires root)
- Blocked response write errors are silently ignored
- Test goroutines call `t.Errorf` from background goroutines (panics on Go 1.24+)

---

## v0.2 — Bug Fixes and Hardening

Fix correctness issues found in code review.

- [ ] Only apply `stripCaps` to CAPABILITY response lines (lines starting with `* CAPABILITY` or containing `[CAPABILITY ...`), not message body data
- [ ] Block `CLOSE` on protected mailboxes (it implicitly expunges)
- [ ] Block `DELETE` on protected mailboxes (destroys entire mailbox)
- [ ] Block `RENAME` on protected mailboxes (moves mailbox out of protection scope)
- [ ] Block `MOVE` from protected mailboxes by default (relocates messages to unprotected mailbox)
- [ ] Block `COMPRESS` negotiation (RFC 4978) — if compressed, the proxy can no longer parse traffic and all ACLs are bypassed
- [ ] Handle literal mailbox names in SELECT/EXAMINE, or conservatively block literal-form SELECT on protected mailboxes
- [ ] Check error return from `clientConn.Write` when sending blocked responses
- [ ] Change default listen port from `:144` to `:1143` or another non-privileged port
- [ ] Fix test goroutine lifecycle: don't call `t.Errorf` from background goroutines, add `sync.WaitGroup` to track proxy goroutines
- [ ] Fix `generateTestCert` to propagate errors via `testing.T`
- [ ] Replace racy `time.Sleep` in tests with deterministic synchronization

---

## v0.3 — Upstream Connection Modes

Remove Proton Bridge assumptions. Support any IMAP server.

- [x] Configurable upstream connection mode:
  - `plaintext` — connect without TLS (local/trusted network)
  - `starttls` — connect plaintext, upgrade via STARTTLS (current behavior)
  - `tls` — connect with implicit TLS (standard port 993 setup)
- [x] Configurable TLS verification:
  - `verify` (default) — validate upstream certificate against system CA pool
  - `skip` — `InsecureSkipVerify` for self-signed certs (current behavior, must be explicit)
  - `ca-file` — verify against a custom CA certificate (for private PKI)
- [x] Optional client-side TLS: serve TLS to clients instead of plaintext
- [x] Only strip STARTTLS/LOGINDISABLED when the proxy is handling TLS termination
- [x] Rename env var `IMAP_GUARD_UPSTREAM` default to `127.0.0.1:143` (standard IMAP)

### Configuration

Environment variables for now, keeping it simple:

```
IMAP_GUARD_LISTEN=:1143
IMAP_GUARD_UPSTREAM=mail.example.com:993
IMAP_GUARD_UPSTREAM_TLS=tls          # plaintext | starttls | tls
IMAP_GUARD_UPSTREAM_VERIFY=verify    # verify | skip | /path/to/ca.pem
IMAP_GUARD_CLIENT_TLS_CERT=/path/to/cert.pem  # optional, enables client-side TLS
IMAP_GUARD_CLIENT_TLS_KEY=/path/to/key.pem
```

---

## v0.4 — ACL System

Replace hardcoded protections with a configurable rule engine.

### Design

Rules are evaluated in order, first match wins. Default policy is `allow` (the proxy is pass-through by default; you add rules to restrict).

```yaml
# imap-guard.yaml
rules:
  - mailbox: "Trash"
    deny: [EXPUNGE, CLOSE, DELETE, RENAME, MOVE, "STORE +\\Deleted"]

  - mailbox: "Drafts"
    deny: [EXPUNGE, CLOSE, DELETE, RENAME, MOVE, "STORE +\\Deleted"]

  # Wildcard: protect all mailboxes from expunge
  # - mailbox: "*"
  #   deny: [EXPUNGE]
```

### Scope

- Match on mailbox name (exact, case-insensitive) with glob wildcards (`*`, `?`)
- Match on IMAP command: EXPUNGE, CLOSE, DELETE, RENAME, MOVE, STORE (and their UID variants)
- For STORE commands, match on flag operations (+FLAGS, FLAGS with specific flags like \Deleted)
- Rules apply to the currently-selected mailbox for most commands
- DELETE and RENAME match on the mailbox argument (not the selected mailbox), since they target a named mailbox directly

### COMPRESS DEFLATE support (RFC 4978)

When ACL rules are defined and the client negotiates `COMPRESS DEFLATE` with the upstream, the proxy intercepts the successful response and inserts `compress/flate` (Go stdlib) wrappers on both sides of the connection. The proxy continues parsing and evaluating ACLs on the decompressed stream. When no ACL rules are configured, COMPRESS passes through unmodified like everything else — the proxy doesn't need to parse traffic it isn't enforcing rules on.

### Implementation Notes

Existing Go ACL libraries (casbin, ladon) are designed for web-style RBAC/ABAC and would be heavy dependencies for what is essentially a small lookup table. A custom rule engine is more appropriate here — the domain is narrow (command × mailbox × flags) and the evaluation logic is straightforward.

If the ACL grows to need user-level rules (different restrictions per IMAP user), casbin's model/policy separation could be worth revisiting.

### Tasks

- [ ] Define config file format (YAML)
- [ ] Implement rule parser and evaluator
- [ ] Replace `shouldBlock` / `isProtected` / `protectedMailboxes` with rule engine
- [ ] Handle DELETE and RENAME by matching on command argument (target mailbox), not selected mailbox
- [ ] Support COMPRESS DEFLATE (RFC 4978): intercept negotiation, wrap both sides with `compress/flate`, continue ACL evaluation on decompressed stream
- [ ] Support config file path via `IMAP_GUARD_CONFIG` env var
- [ ] When no config file is present, proxy is fully pass-through (no blocking)
- [ ] Log which rule matched when blocking a command
- [ ] Config file reload on SIGHUP (optional, nice to have)

---

## v0.5 — Workflow Tracking

Track multi-command sequences to make smarter allow/deny decisions.

### Problem

The current approach blocks all EXPUNGE in protected mailboxes. But some workflows involving EXPUNGE are safe:

- `MOVE 1 INBOX` in Trash — message is relocated, server handles expunge internally (already works, MOVE is atomic per RFC 6851)
- `COPY 1 Archive` then `EXPUNGE` in Trash — message has a safe copy, expunge just cleans up

Other workflows are destructive:

- `EXPUNGE` in Trash with no prior COPY/MOVE — permanent deletion
- `STORE +\Deleted` on all messages, then `CLOSE` — permanent deletion

### Design

Per-connection state tracking:

- Track which message UIDs/sequences have been copied or moved out of the current mailbox
- When EXPUNGE is requested, only allow it if all \Deleted messages have been copied/moved elsewhere
- Conservative default: if we can't determine safety, block

This requires parsing COPY/MOVE responses to know which messages were affected, and correlating with STORE \Deleted flags.

### Tasks

- [ ] Track COPY/MOVE commands and their target mailboxes per connection
- [ ] Track which messages have \Deleted flag set (from STORE responses or FETCH)
- [ ] Implement "safe expunge" check: all \Deleted messages have a copy elsewhere
- [ ] Add ACL action: `deny-unless-copied` for EXPUNGE (in addition to hard `deny`)
- [ ] Handle UID vs sequence number mapping (server sends EXPUNGE with sequence numbers)

### Complexity Warning

This is the most complex milestone. IMAP message tracking across commands is stateful and error-prone — sequence numbers shift after every EXPUNGE, UID validity can change on SELECT, and concurrent clients can modify the mailbox state. Start with a conservative implementation that blocks when uncertain.

---

## v1.0 — Production Ready

Polish, observability, and operational readiness.

- [ ] Structured logging (JSON option for log aggregation)
- [ ] Log levels (debug for per-command relay, info for connections/blocks, error for failures)
- [ ] Graceful shutdown on SIGTERM/SIGINT (drain active connections)
- [ ] Health check endpoint (HTTP) for container orchestration
- [ ] Connection timeout configuration (idle timeout, total session timeout)
- [ ] Metrics: active connections, commands proxied, commands blocked (Prometheus endpoint or structured log counters)
- [ ] Docker image and example docker-compose setup
- [ ] man page or `--help` with full option documentation
- [ ] CI pipeline (lint, test, build, release binaries)

---

## Future / Post-v1

Ideas that don't belong in v1 but are worth tracking.

- **Per-user ACLs**: different rules based on the authenticated IMAP user (parse LOGIN/AUTHENTICATE)
- **Audit log**: structured log of all blocked commands with full context (user, mailbox, command, timestamp) for compliance
- **IMAP IDLE passthrough optimization**: avoid buffering during IDLE
- **Multiple upstream support**: route different users to different upstream servers
- **IMAP4rev2 (RFC 9051) support**: new protocol features, different capability negotiation
- **Web UI**: simple dashboard showing active connections, recent blocks, rule management
