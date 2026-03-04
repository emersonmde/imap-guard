# imap-guard

An IMAP proxy that blocks destructive operations on configurable mailboxes. Sits between an IMAP client and an upstream IMAP server, evaluating commands against YAML-based ACL rules. Without a config file, it operates as a pure pass-through proxy.

## Install

```sh
go install github.com/emersonmde/imap-guard@latest
```

Or build from source:

```sh
git clone https://github.com/emersonmde/imap-guard.git
cd imap-guard
go build -o imap-guard .
```

## Configuration

All configuration is via environment variables. Run `imap-guard --help` for a summary.

| Environment Variable | Default | Description |
|---|---|---|
| `IMAP_GUARD_LISTEN` | `:1143` | Address to listen on for client connections |
| `IMAP_GUARD_UPSTREAM` | `127.0.0.1:143` | Upstream IMAP server address |
| `IMAP_GUARD_UPSTREAM_TLS` | `starttls` | Upstream connection mode: `plaintext`, `starttls`, or `tls` |
| `IMAP_GUARD_UPSTREAM_VERIFY` | `verify` | TLS verification: `verify` (system CAs), `skip` (insecure), or path to CA PEM file |
| `IMAP_GUARD_CLIENT_TLS_CERT` | (empty) | Path to PEM certificate for client-facing TLS |
| `IMAP_GUARD_CLIENT_TLS_KEY` | (empty) | Path to PEM private key for client-facing TLS |
| `IMAP_GUARD_CONFIG` | (empty) | Path to YAML ACL config file |
| `IMAP_GUARD_LOG_FORMAT` | `text` | Log format: `text` or `json` |
| `IMAP_GUARD_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `IMAP_GUARD_SHUTDOWN_TIMEOUT` | `30s` | Max time to drain active connections on shutdown |
| `IMAP_GUARD_HEALTH_LISTEN` | (empty) | HTTP health/metrics listen address (e.g., `:8080`), empty to disable |
| `IMAP_GUARD_IDLE_TIMEOUT` | `30m` | Close connection after this duration of inactivity |
| `IMAP_GUARD_SESSION_TIMEOUT` | `24h` | Max total connection duration |

### ACL configuration

Without a config file (`IMAP_GUARD_CONFIG` unset), imap-guard is a pure pass-through proxy — no commands are blocked. To enforce rules, create a YAML config file:

```yaml
# imap-guard.yaml
rules:
  - mailbox: "*trash*"
    deny: [CLOSE, DELETE, RENAME, MOVE, COMPRESS, "STORE +\\Deleted"]
    deny-unless-copied: [EXPUNGE]
  - mailbox: "*drafts*"
    deny: [EXPUNGE, CLOSE, DELETE, RENAME, MOVE, COMPRESS, "STORE +\\Deleted"]
  - mailbox: "*junk*"
    deny: [EXPUNGE, CLOSE, DELETE, RENAME, MOVE, COMPRESS, "STORE +\\Deleted"]
```

```sh
IMAP_GUARD_CONFIG=imap-guard.yaml imap-guard
```

Rules are evaluated in order — the first rule whose mailbox pattern matches is used, and the command is blocked only if it appears in that rule's deny list. If no rule matches, the command passes through.

#### Deny entry syntax

| Deny entry | Effect |
|---|---|
| `EXPUNGE` | Block EXPUNGE and UID EXPUNGE |
| `CLOSE` | Block CLOSE (implicitly expunges) |
| `DELETE` | Block DELETE (destroys mailbox) |
| `RENAME` | Block RENAME (moves mailbox out of scope) |
| `MOVE` | Block MOVE and UID MOVE |
| `COMPRESS` | Block COMPRESS DEFLATE negotiation |
| `STORE` | Block all STORE and UID STORE commands |
| `"STORE +\\Deleted"` | Block STORE/UID STORE when adding `\Deleted` flag (+FLAGS or FLAGS) |
| `"STORE -\\Seen"` | Block STORE/UID STORE when removing `\Seen` flag (-FLAGS) |

Commands not in the deny list pass through. All other IMAP commands (COPY, FETCH, SEARCH, NOOP, etc.) are never blocked.

DELETE and RENAME are evaluated against the target mailbox name from the command arguments (not the currently selected mailbox). All other commands are evaluated against the currently selected mailbox.

#### Conditional deny: `deny-unless-copied`

The `deny-unless-copied` action allows `UID EXPUNGE` only when all targeted UIDs have been confirmed copied via a prior `COPY`, `UID COPY`, or `UID MOVE` command in the same session and mailbox. This enables safe "copy then expunge" workflows while still blocking unprotected deletions.

```yaml
rules:
  - mailbox: "*trash*"
    deny: [CLOSE, DELETE, RENAME, MOVE, COMPRESS, "STORE +\\Deleted"]
    deny-unless-copied: [EXPUNGE]
```

Behavior:
- **`UID EXPUNGE <uid-set>`**: Allowed if every UID in the set was previously copied. Blocked otherwise.
- **Plain `EXPUNGE`**: Always blocked (affects all `\Deleted` messages — the proxy can't verify which UIDs are targeted).
- **No UIDPLUS support**: If the upstream server doesn't include `[COPYUID ...]` in its COPY/MOVE response (RFC 4315), the proxy blocks conservatively.
- **State resets on `SELECT`/`EXAMINE`**: Copied UID tracking is per-mailbox; switching mailboxes clears the state.
- **UID set cap**: UID set expansion is capped at 10,000 UIDs. A `UID EXPUNGE` targeting more than 10,000 UIDs is blocked.

Only `EXPUNGE` is valid in `deny-unless-copied`. A command cannot appear in both `deny` and `deny-unless-copied` within the same rule (the config loader rejects overlaps at startup).

#### Glob patterns

Mailbox patterns support `*` (matches any characters, including hierarchy separators `/` and `.`) and `?` (matches exactly one character). Matching is case-insensitive.

| Pattern | Matches |
|---|---|
| `Trash` | `Trash`, `trash`, `TRASH` |
| `*trash*` | `Trash`, `Folders/Trash`, `INBOX.Trash` |
| `INBOX.*` | `INBOX.Sent`, `INBOX.Drafts` |
| `*` | All mailboxes |

### COMPRESS DEFLATE

imap-guard supports COMPRESS DEFLATE (RFC 4978). When a client negotiates COMPRESS DEFLATE with the upstream server, the proxy intercepts the negotiation and wraps both connections with raw DEFLATE streams. ACL evaluation continues to operate on the decompressed command stream.

To block COMPRESS negotiation on specific mailboxes, add `COMPRESS` to the deny list:

```yaml
rules:
  - mailbox: "*trash*"
    deny: [COMPRESS]
```

If COMPRESS is not in the deny list, the proxy transparently relays the COMPRESS negotiation and switches to compressed streams when the upstream server accepts.

### Connection timeouts

The proxy enforces two timeout types:

- **Idle timeout** (`IMAP_GUARD_IDLE_TIMEOUT`, default 30m): Closes connections with no read activity. The 30-minute default aligns with RFC 2177's recommendation for IMAP IDLE re-issue intervals.
- **Session timeout** (`IMAP_GUARD_SESSION_TIMEOUT`, default 24h): Maximum total connection duration regardless of activity.

Both timeouts apply to the client-facing and upstream connections.

### Graceful shutdown

On SIGINT or SIGTERM, the proxy stops accepting new connections and waits up to `IMAP_GUARD_SHUTDOWN_TIMEOUT` (default 30s) for active connections to complete. If connections don't drain within the timeout, the process exits.

### Health check and metrics

Set `IMAP_GUARD_HEALTH_LISTEN` to enable an HTTP health/metrics endpoint:

```sh
IMAP_GUARD_HEALTH_LISTEN=:8080 imap-guard
```

- `GET /healthz` — Returns `200 OK` with body `ok`
- `GET /metrics` — Returns JSON:
  ```json
  {"active_connections": 5, "total_commands_proxied": 1234, "total_commands_blocked": 12}
  ```

### Logging

Structured logging via Go's `log/slog`. Configure format and level:

```sh
IMAP_GUARD_LOG_FORMAT=json IMAP_GUARD_LOG_LEVEL=debug imap-guard
```

Log levels:
- `debug` — Per-command relay logging (every IMAP command)
- `info` — Connection accept/close, blocked commands, startup messages
- `warn` — Shutdown timeout warnings
- `error` — Connection failures, upstream errors

### Migrating from v0.5

v1.0 adds structured logging, connection timeouts, COMPRESS DEFLATE support, health endpoints, and graceful shutdown. Existing ACL configs work unchanged. New environment variables are all optional with sensible defaults.

## Usage

### Standard IMAP server (implicit TLS, port 993)

```sh
IMAP_GUARD_UPSTREAM=imap.gmail.com:993 IMAP_GUARD_UPSTREAM_TLS=tls imap-guard
```

Connects to the upstream over implicit TLS and verifies the server certificate against system CAs. Point your IMAP client at `localhost:1143`.

### STARTTLS upstream (default)

```sh
IMAP_GUARD_UPSTREAM=mail.example.com:143 imap-guard
```

Connects plaintext, upgrades to TLS via STARTTLS, and verifies the server certificate.

### Proton Bridge

Proton Bridge uses STARTTLS with a self-signed certificate. Run imap-guard on a different port and skip certificate verification:

```sh
IMAP_GUARD_LISTEN=:1144 IMAP_GUARD_UPSTREAM=127.0.0.1:1143 IMAP_GUARD_UPSTREAM_VERIFY=skip imap-guard
```

Then configure your IMAP client to connect to `localhost:1144` instead of `1143`.

### Plaintext upstream (trusted network)

```sh
IMAP_GUARD_UPSTREAM=10.0.0.5:143 IMAP_GUARD_UPSTREAM_TLS=plaintext imap-guard
```

No TLS to the upstream. Only use this on a trusted network (loopback, VPN, etc.).

### Custom CA verification

```sh
IMAP_GUARD_UPSTREAM=mail.internal:993 IMAP_GUARD_UPSTREAM_TLS=tls IMAP_GUARD_UPSTREAM_VERIFY=/etc/ssl/internal-ca.pem imap-guard
```

Verifies the upstream certificate against a custom CA instead of system CAs.

### Client-side TLS

```sh
IMAP_GUARD_CLIENT_TLS_CERT=/etc/ssl/proxy-cert.pem IMAP_GUARD_CLIENT_TLS_KEY=/etc/ssl/proxy-key.pem imap-guard
```

Serves TLS to connecting IMAP clients. When client-side TLS is enabled, `STARTTLS` and `LOGINDISABLED` capabilities are not stripped from the upstream greeting (the client already has TLS).

When client-side TLS is not configured, the proxy strips `STARTTLS` and `LOGINDISABLED` capabilities so clients can authenticate in plaintext to the proxy.

### systemd

```ini
[Unit]
Description=imap-guard IMAP proxy
After=network.target

[Service]
ExecStart=/path/to/imap-guard
Environment=IMAP_GUARD_LISTEN=:1143
Environment=IMAP_GUARD_UPSTREAM=imap.gmail.com:993
Environment=IMAP_GUARD_UPSTREAM_TLS=tls
Environment=IMAP_GUARD_CONFIG=/etc/imap-guard/rules.yaml
Environment=IMAP_GUARD_HEALTH_LISTEN=:8080
Restart=always

[Install]
WantedBy=multi-user.target
```

### Docker

```sh
docker build -t imap-guard .
docker run -e IMAP_GUARD_UPSTREAM=imap.gmail.com:993 -e IMAP_GUARD_UPSTREAM_TLS=tls -p 1143:1143 imap-guard
```

A `docker-compose.yaml` is included with an example Proton Bridge setup.

## Testing

```sh
go test -v ./...
go test -race ./...
```

## License

MIT
