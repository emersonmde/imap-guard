# imap-guard

An IMAP proxy that prevents permanent deletion of messages in protected mailboxes. Sits between an IMAP client and an upstream IMAP server, intercepting and blocking destructive operations while passing everything else through.

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

All configuration is via environment variables.

| Environment Variable | Default | Description |
|---|---|---|
| `IMAP_GUARD_LISTEN` | `:1143` | Address to listen on for client connections |
| `IMAP_GUARD_UPSTREAM` | `127.0.0.1:143` | Upstream IMAP server address |
| `IMAP_GUARD_UPSTREAM_TLS` | `starttls` | Upstream connection mode: `plaintext`, `starttls`, or `tls` |
| `IMAP_GUARD_UPSTREAM_VERIFY` | `verify` | TLS verification: `verify` (system CAs), `skip` (insecure), or path to CA PEM file |
| `IMAP_GUARD_CLIENT_TLS_CERT` | (empty) | Path to PEM certificate for client-facing TLS |
| `IMAP_GUARD_CLIENT_TLS_KEY` | (empty) | Path to PEM private key for client-facing TLS |

### Protected mailboxes

Any mailbox whose name contains one of these keywords (case-insensitive) is protected:

- `trash`
- `drafts`
- `junk`

This matches standard names (`Trash`) and path-prefixed names (`Folders/Trash`, `INBOX.Trash`).

### Blocked operations on protected mailboxes

| Command | Reason |
|---|---|
| `EXPUNGE` / `UID EXPUNGE` | Permanently removes messages |
| `CLOSE` | Implicitly expunges all \Deleted messages |
| `DELETE` | Destroys the entire mailbox |
| `RENAME` | Moves mailbox out of protection scope |
| `MOVE` / `UID MOVE` | Relocates messages to an unprotected mailbox |
| `STORE +FLAGS (\Deleted)` | Marks messages for deletion |
| `COMPRESS` | Would make traffic opaque, bypassing enforcement |

All other IMAP commands pass through unmodified, including `COPY`, `FETCH`, `SEARCH`, `STORE +FLAGS (\Seen)`, `STORE -FLAGS (\Deleted)`, etc.

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
Restart=always

[Install]
WantedBy=multi-user.target
```

### Docker (alongside Proton Bridge)

```dockerfile
FROM golang:1.22 AS build
RUN go install github.com/emersonmde/imap-guard@latest

FROM debian:bookworm-slim
COPY --from=build /go/bin/imap-guard /usr/local/bin/
ENV IMAP_GUARD_LISTEN=:1144
ENV IMAP_GUARD_UPSTREAM=127.0.0.1:1143
ENTRYPOINT ["imap-guard"]
```

## Testing

```sh
go test -v ./...
go test -race ./...
```

## License

MIT
