# imap-guard

A transparent IMAP proxy that prevents permanent deletion of messages in protected mailboxes. Designed to sit between an IMAP client (or AI assistant) and an upstream IMAP server, intercepting and blocking destructive operations on configurable folders.

## Problem

AI assistants and automated tools with IMAP access can permanently delete messages from Trash and Drafts folders via EXPUNGE or STORE +\Deleted commands. imap-guard prevents this by proxying the IMAP connection and blocking these operations on protected mailboxes while allowing all other IMAP commands to pass through transparently.

## How it works

imap-guard listens for plaintext IMAP connections, connects to an upstream IMAP server via STARTTLS, and relays traffic bidirectionally. On the client-facing side, it strips STARTTLS and LOGINDISABLED capabilities so clients connect in plaintext to the proxy (TLS is handled between the proxy and the upstream server).

For each connection, the proxy tracks which mailbox is currently selected. When a client issues a destructive command on a protected mailbox, the proxy returns `NO [NOPERM]` without forwarding the command upstream.

### Blocked operations on protected mailboxes

- `EXPUNGE`
- `UID EXPUNGE`
- `STORE ... +FLAGS (\Deleted)` / `FLAGS (\Deleted)`
- `UID STORE ... +FLAGS (\Deleted)` / `FLAGS (\Deleted)`

### Allowed operations on protected mailboxes

- `MOVE`, `COPY`, `FETCH`, `SEARCH`, `NOOP`
- `STORE -FLAGS (\Deleted)` (removing the deleted flag)
- `STORE +FLAGS (\Seen)` and other non-destructive flag changes

### Protected mailboxes

- Trash
- Drafts

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `IMAP_GUARD_LISTEN` | `:1143` | Address to listen on for client connections |
| `IMAP_GUARD_UPSTREAM` | `127.0.0.1:1143` | Upstream IMAP server address |

## Usage

```sh
go build -o imap-guard .
IMAP_GUARD_UPSTREAM=127.0.0.1:993 ./imap-guard
```

Then point your IMAP client at `localhost:1143` instead of connecting directly to the upstream server.

## Testing

```sh
go test -v ./...
```

## License

MIT
