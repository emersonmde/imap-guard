FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /imap-guard .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=build /imap-guard /usr/local/bin/imap-guard
ENTRYPOINT ["imap-guard"]
