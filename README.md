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

### Standard IMAP server

```sh
imap-guard
```

Listens on `:1143`, connects upstream to `127.0.0.1:143` via STARTTLS. Point your IMAP client at `localhost:1143`.

### Proton Bridge

Proton Bridge listens on port `1143` by default. Run imap-guard on a different port and point it at Bridge:

```sh
IMAP_GUARD_LISTEN=:1144 IMAP_GUARD_UPSTREAM=127.0.0.1:1143 imap-guard
```

Then configure your IMAP client to connect to `localhost:1144` instead of `1143`.

The proxy handles STARTTLS negotiation and self-signed certificate validation with Bridge automatically. It strips `STARTTLS` and `LOGINDISABLED` capabilities from the client-facing connection so clients can authenticate in plaintext to the proxy.

### systemd

```ini
[Unit]
Description=imap-guard IMAP proxy
After=network.target

[Service]
ExecStart=/path/to/imap-guard
Environment=IMAP_GUARD_LISTEN=:1143
Environment=IMAP_GUARD_UPSTREAM=127.0.0.1:143
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
