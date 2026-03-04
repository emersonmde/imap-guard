# imap-guard Development Roadmap

Current version: **v0.5**

## Design Principles

- **Thin proxy**: minimal overhead, pass everything through unless a rule says otherwise
- **Allow by default**: the proxy passes everything through with no blocking unless ACL rules are explicitly configured
- **No protocol rewriting**: avoid modifying IMAP traffic beyond what's necessary for the proxy to function (capability stripping, ACL enforcement)
- **Simple configuration**: easy to set up for common cases, extensible for complex ones

---

## v0.1 — Initial Release

Single-file IMAP proxy with hardcoded protections.

- Listens for plaintext IMAP connections
- Connects to upstream via STARTTLS (assumes Proton Bridge-style setup)
- Strips STARTTLS and LOGINDISABLED capabilities
- Blocks EXPUNGE and STORE +\Deleted on hardcoded Trash/Drafts mailboxes
- Full test suite with mock upstream server

### Known Issues (all addressed in v0.2–v0.4)

- `InsecureSkipVerify: true` is hardcoded with no option for real cert verification → *fixed in v0.3*
- Upstream connection mode is hardcoded to STARTTLS (no plaintext or implicit TLS) → *fixed in v0.3*
- `stripCaps` runs on all server traffic including message bodies → *fixed in v0.2*
- `CLOSE` command is not blocked but implicitly expunges → *fixed in v0.4 ACL system*
- `DELETE` command is not blocked → *fixed in v0.4 ACL system*
- `RENAME` command is not blocked → *fixed in v0.4 ACL system*
- `MOVE` from a protected mailbox is not blocked → *fixed in v0.4 ACL system*
- `COMPRESS` extension (RFC 4978) is not handled → *fixed in v0.4 ACL system (blocked via deny rules)*
- Literal mailbox names (`SELECT {5}\r\nTrash`) bypass protection entirely → *fixed in v0.2 (conservative literal handling)*
- Protected mailbox list is hardcoded, not configurable → *fixed in v0.4 ACL system*
- Default listen port is `:144` (not standard IMAP port 143, requires root) → *fixed in v0.3*
- Blocked response write errors are silently ignored → *fixed in v0.2*
- Test goroutines call `t.Errorf` from background goroutines (panics on Go 1.24+)

---

## v0.2 — Bug Fixes and Hardening

Fix correctness issues found in code review.

- [x] Only apply `stripCaps` to CAPABILITY response lines (lines starting with `* CAPABILITY` or containing `[CAPABILITY ...`), not message body data
- [x] Block `CLOSE` on protected mailboxes (it implicitly expunges) — *moved to v0.4 ACL system*
- [x] Block `DELETE` on protected mailboxes (destroys entire mailbox) — *moved to v0.4 ACL system*
- [x] Block `RENAME` on protected mailboxes (moves mailbox out of protection scope) — *moved to v0.4 ACL system*
- [x] Block `MOVE` from protected mailboxes by default (relocates messages to unprotected mailbox) — *moved to v0.4 ACL system*
- [x] Block `COMPRESS` negotiation (RFC 4978) — *moved to v0.4 ACL system (deny rules)*
- [x] Handle literal mailbox names in SELECT/EXAMINE, or conservatively block literal-form SELECT on protected mailboxes
- [x] Check error return from `clientConn.Write` when sending blocked responses
- [x] Change default listen port from `:144` to `:1143` or another non-privileged port — *done in v0.3*
- [ ] Fix test goroutine lifecycle: don't call `t.Errorf` from background goroutines, add `sync.WaitGroup` to track proxy goroutines
- [x] Fix `generateTestCert` to propagate errors via `testing.T`
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
  - mailbox: "*trash*"
    deny: [EXPUNGE, CLOSE, DELETE, RENAME, MOVE, COMPRESS, "STORE +\\Deleted"]

  - mailbox: "*drafts*"
    deny: [EXPUNGE, CLOSE, DELETE, RENAME, MOVE, COMPRESS, "STORE +\\Deleted"]

  - mailbox: "*junk*"
    deny: [EXPUNGE, CLOSE, DELETE, RENAME, MOVE, COMPRESS, "STORE +\\Deleted"]
```

### Scope

- Match on mailbox name (exact, case-insensitive) with glob wildcards (`*`, `?`)
- Match on IMAP command: EXPUNGE, CLOSE, DELETE, RENAME, MOVE, STORE, COMPRESS (and their UID variants)
- For STORE commands, match on flag operations (+FLAGS, FLAGS with specific flags like \Deleted)
- Rules apply to the currently-selected mailbox for most commands
- DELETE and RENAME match on the mailbox argument (not the selected mailbox), since they target a named mailbox directly

### Implementation Notes

Existing Go ACL libraries (casbin, ladon) are designed for web-style RBAC/ABAC and would be heavy dependencies for what is essentially a small lookup table. A custom rule engine is more appropriate here — the domain is narrow (command × mailbox × flags) and the evaluation logic is straightforward.

COMPRESS is handled explicitly — if users want COMPRESS blocked, they add it to the deny list. No implicit blocking.

Config is loaded at startup. Users restart to pick up changes. SIGHUP reload deferred to avoid atomic swap complexity.

### Tasks

- [x] Define config file format (YAML)
- [x] Implement rule parser and evaluator
- [x] Replace `shouldBlock` / `isProtected` / `protectedMailboxes` with rule engine
- [x] Handle DELETE and RENAME by matching on command argument (target mailbox), not selected mailbox
- [x] Support config file path via `IMAP_GUARD_CONFIG` env var
- [x] When no config file is present, proxy is fully pass-through (no blocking)
- [x] Log which rule matched when blocking a command

---

## v0.5 — Workflow Tracking (deny-unless-copied)

Track COPY/MOVE commands to allow safe EXPUNGE workflows.

### Problem

The v0.4 approach blocks all EXPUNGE in protected mailboxes. But some workflows are safe:

- `UID COPY 1:3 Archive` then `UID EXPUNGE 1:3` in Trash — messages have a safe copy

### Design

- New ACL action `deny-unless-copied`: allows `UID EXPUNGE` when all targeted UIDs have been confirmed copied via COPYUID responses (RFC 4315) from prior COPY/UID COPY/UID MOVE commands
- Plain `EXPUNGE` is always blocked under `deny-unless-copied` (can't verify which UIDs are affected)
- Tag correlation: `relayClientToServer` records pending COPY tags, `relayServerToClient` resolves them against COPYUID responses
- State resets on SELECT/EXAMINE (copied UIDs are mailbox-specific)
- UID set expansion capped at 10,000 to prevent memory exhaustion
- Conservative: if server doesn't support UIDPLUS (no COPYUID in response), block

### Deferred from original spec

- \Deleted flag tracking — not needed; UID EXPUNGE doesn't require it
- Sequence number → UID mapping — not needed; COPYUID gives source UIDs directly
- `deny-unless-copied` for CLOSE — CLOSE always blocked (same pre-existing \Deleted problem as plain EXPUNGE)

### Tasks

- [x] Add `deny-unless-copied` ACL action (only valid for EXPUNGE)
- [x] Track COPY/UID COPY/UID MOVE commands via tag correlation
- [x] Parse COPYUID responses from server to record source UIDs
- [x] Allow UID EXPUNGE when all UIDs in the set have been copied
- [x] Block plain EXPUNGE unconditionally under deny-unless-copied
- [x] Reset copy state on SELECT/EXAMINE
- [x] Config validation: no overlap between deny and deny-unless-copied
- [x] Unit tests for parseUIDSet, parseCOPYUID, parseTaggedResponse, connState methods
- [x] Integration tests for full copy-then-expunge workflows

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
- [ ] Support COMPRESS DEFLATE (RFC 4978): intercept negotiation, wrap both sides with `compress/flate`, continue ACL evaluation on decompressed stream
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
