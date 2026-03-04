FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /imap-guard .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && adduser -D -H appuser
USER appuser
COPY --from=build /imap-guard /usr/local/bin/imap-guard
EXPOSE 1143 8080
ENTRYPOINT ["imap-guard"]
