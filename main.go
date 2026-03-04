package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type upstreamTLSMode int

const (
	upstreamPlaintext  upstreamTLSMode = iota
	upstreamSTARTTLS
	upstreamImplicitTLS
)

type config struct {
	listenAddr      string
	upstreamAddr    string
	upstreamTLS     upstreamTLSMode
	upstreamVerify  string // "verify", "skip", or CA file path
	clientTLSCert   string
	clientTLSKey    string
	logFormat       string
	logLevel        slog.Level
	shutdownTimeout time.Duration
	healthListen    string
	idleTimeout     time.Duration
	sessionTimeout  time.Duration
	maxConnections  int64
}

func parseConfig() (*config, error) {
	cfg := &config{
		listenAddr:     envOrDefault("IMAP_GUARD_LISTEN", ":1143"),
		upstreamAddr:   envOrDefault("IMAP_GUARD_UPSTREAM", "127.0.0.1:143"),
		upstreamVerify: envOrDefault("IMAP_GUARD_UPSTREAM_VERIFY", "verify"),
		clientTLSCert:  os.Getenv("IMAP_GUARD_CLIENT_TLS_CERT"),
		clientTLSKey:   os.Getenv("IMAP_GUARD_CLIENT_TLS_KEY"),
		logFormat:      strings.ToLower(envOrDefault("IMAP_GUARD_LOG_FORMAT", "text")),
		healthListen:   os.Getenv("IMAP_GUARD_HEALTH_LISTEN"),
	}

	level, err := parseLogLevel(envOrDefault("IMAP_GUARD_LOG_LEVEL", "info"))
	if err != nil {
		return nil, err
	}
	cfg.logLevel = level

	cfg.shutdownTimeout, err = parseDuration("IMAP_GUARD_SHUTDOWN_TIMEOUT", "30s")
	if err != nil {
		return nil, err
	}
	cfg.idleTimeout, err = parseDuration("IMAP_GUARD_IDLE_TIMEOUT", "30m")
	if err != nil {
		return nil, err
	}
	cfg.sessionTimeout, err = parseDuration("IMAP_GUARD_SESSION_TIMEOUT", "24h")
	if err != nil {
		return nil, err
	}

	if cfg.logFormat != "text" && cfg.logFormat != "json" {
		return nil, fmt.Errorf("invalid IMAP_GUARD_LOG_FORMAT value %q (must be text or json)", cfg.logFormat)
	}

	switch strings.ToLower(envOrDefault("IMAP_GUARD_UPSTREAM_TLS", "starttls")) {
	case "plaintext":
		cfg.upstreamTLS = upstreamPlaintext
	case "starttls":
		cfg.upstreamTLS = upstreamSTARTTLS
	case "tls":
		cfg.upstreamTLS = upstreamImplicitTLS
	default:
		return nil, fmt.Errorf("invalid IMAP_GUARD_UPSTREAM_TLS value %q (must be plaintext, starttls, or tls)",
			os.Getenv("IMAP_GUARD_UPSTREAM_TLS"))
	}

	// Verify settings are meaningless without TLS
	if cfg.upstreamTLS == upstreamPlaintext && cfg.upstreamVerify != "verify" {
		return nil, fmt.Errorf("IMAP_GUARD_UPSTREAM_VERIFY=%q has no effect with plaintext upstream (no TLS to verify)",
			cfg.upstreamVerify)
	}

	// Validate verify setting
	if cfg.upstreamVerify != "verify" && cfg.upstreamVerify != "skip" {
		if _, err := os.Stat(cfg.upstreamVerify); err != nil {
			return nil, fmt.Errorf("CA file %q: %w", cfg.upstreamVerify, err)
		}
	}

	// Client TLS: both or neither
	if (cfg.clientTLSCert == "") != (cfg.clientTLSKey == "") {
		return nil, fmt.Errorf("IMAP_GUARD_CLIENT_TLS_CERT and IMAP_GUARD_CLIENT_TLS_KEY must both be set or both be empty")
	}
	if cfg.clientTLSCert != "" {
		if _, err := os.Stat(cfg.clientTLSCert); err != nil {
			return nil, fmt.Errorf("client TLS cert %q: %w", cfg.clientTLSCert, err)
		}
		if _, err := os.Stat(cfg.clientTLSKey); err != nil {
			return nil, fmt.Errorf("client TLS key %q: %w", cfg.clientTLSKey, err)
		}
	}

	if v := os.Getenv("IMAP_GUARD_MAX_CONNECTIONS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid IMAP_GUARD_MAX_CONNECTIONS value %q", v)
		}
		cfg.maxConnections = n
	}

	return cfg, nil
}

func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid IMAP_GUARD_LOG_LEVEL value %q (must be debug, info, warn, or error)", s)
	}
}

func parseDuration(envKey, defaultVal string) (time.Duration, error) {
	s := envOrDefault(envKey, defaultVal)
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid %s value %q: %w", envKey, s, err)
	}
	return d, nil
}

func initLogger(format string, level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(handler)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `imap-guard — IMAP proxy with ACL-based command blocking

Environment Variables:
  IMAP_GUARD_LISTEN            Listen address (default: :1143)
  IMAP_GUARD_UPSTREAM          Upstream IMAP server (default: 127.0.0.1:143)
  IMAP_GUARD_UPSTREAM_TLS      Upstream TLS mode: plaintext, starttls, tls (default: starttls)
  IMAP_GUARD_UPSTREAM_VERIFY   TLS verification: verify, skip, or CA file path (default: verify)
  IMAP_GUARD_CLIENT_TLS_CERT   Path to PEM certificate for client-facing TLS
  IMAP_GUARD_CLIENT_TLS_KEY    Path to PEM private key for client-facing TLS
  IMAP_GUARD_CONFIG            Path to YAML ACL config file
  IMAP_GUARD_LOG_FORMAT        Log format: text or json (default: text)
  IMAP_GUARD_LOG_LEVEL         Log level: debug, info, warn, error (default: info)
  IMAP_GUARD_SHUTDOWN_TIMEOUT  Max time to drain connections on shutdown (default: 30s)
  IMAP_GUARD_HEALTH_LISTEN     HTTP health/metrics listen address, e.g. :8080 (default: disabled)
  IMAP_GUARD_IDLE_TIMEOUT      Close connection after inactivity (default: 30m)
  IMAP_GUARD_SESSION_TIMEOUT   Max total connection duration (default: 24h)
  IMAP_GUARD_MAX_CONNECTIONS   Max concurrent connections, 0 = unlimited (default: 0)
`)
}

// ── Metrics ──

type metrics struct {
	activeConns  atomic.Int64
	totalProxied atomic.Int64
	totalBlocked atomic.Int64
}

// ── Health endpoint ──

func startHealthServer(addr string, m *metrics) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int64{
			"active_connections":     m.activeConns.Load(),
			"total_commands_proxied": m.totalProxied.Load(),
			"total_commands_blocked": m.totalBlocked.Load(),
		})
	})
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("health server error", "err", err)
		}
	}()
	return srv
}

func (c *config) clientTLSEnabled() bool {
	return c.clientTLSCert != "" && c.clientTLSKey != ""
}

func (c *config) shouldStripCaps() bool {
	return !c.clientTLSEnabled()
}

func (c *config) buildUpstreamTLSConfig() (*tls.Config, error) {
	host, _, err := net.SplitHostPort(c.upstreamAddr)
	if err != nil {
		host = c.upstreamAddr
	}

	tlsCfg := &tls.Config{
		ServerName: host,
	}

	switch c.upstreamVerify {
	case "verify":
		// Default system CA pool, no changes needed
	case "skip":
		tlsCfg.InsecureSkipVerify = true
	default:
		// CA file path
		pemData, err := os.ReadFile(c.upstreamVerify)
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", c.upstreamVerify, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("CA file %q contains no valid certificates", c.upstreamVerify)
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	// Check for --help before anything else
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-h", "--help", "help":
			printUsage()
			os.Exit(0)
		}
	}

	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger := initLogger(cfg.logFormat, cfg.logLevel)
	slog.SetDefault(logger)

	rules, err := loadACLConfig(os.Getenv("IMAP_GUARD_CONFIG"))
	if err != nil {
		slog.Error("ACL config error", "err", err)
		os.Exit(1)
	}

	slog.Info("imap-guard starting",
		"listen", cfg.listenAddr,
		"upstream", cfg.upstreamAddr,
		"tls", []string{"plaintext", "starttls", "tls"}[cfg.upstreamTLS])
	if rules == nil {
		slog.Info("no ACL config: operating as pure pass-through proxy")
	} else {
		slog.Info("ACL config loaded", "rules", len(rules))
	}

	var ln net.Listener
	if cfg.clientTLSEnabled() {
		cert, err := tls.LoadX509KeyPair(cfg.clientTLSCert, cfg.clientTLSKey)
		if err != nil {
			slog.Error("load client TLS cert/key", "err", err)
			os.Exit(1)
		}
		ln, err = tls.Listen("tcp", cfg.listenAddr, &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
		if err != nil {
			slog.Error("failed to listen (TLS)", "addr", cfg.listenAddr, "err", err)
			os.Exit(1)
		}
		slog.Info("client-side TLS enabled")
	} else {
		ln, err = net.Listen("tcp", cfg.listenAddr)
		if err != nil {
			slog.Error("failed to listen", "addr", cfg.listenAddr, "err", err)
			os.Exit(1)
		}
	}

	m := &metrics{}

	// Start health server if configured
	var healthSrv *http.Server
	if cfg.healthListen != "" {
		healthSrv = startHealthServer(cfg.healthListen, m)
		slog.Info("health endpoint enabled", "addr", cfg.healthListen)
	}

	// Graceful shutdown setup
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	var connCounter uint64

	// Close listener on shutdown signal
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// Accept loop
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break // shutdown requested
			}
			slog.Error("accept error", "err", err)
			continue
		}
		// The accept loop is single-goroutined, so Load and Add are not racy here.
		if cfg.maxConnections > 0 && m.activeConns.Load() >= cfg.maxConnections {
			slog.Warn("connection limit reached, rejecting",
				"remote", conn.RemoteAddr(),
				"limit", cfg.maxConnections,
				"active", m.activeConns.Load())
			conn.Close()
			continue
		}
		connID := fmt.Sprintf("C%d", atomic.AddUint64(&connCounter, 1))
		slog.Info("connection accepted", "conn", connID, "remote", conn.RemoteAddr())
		m.activeConns.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleClient(conn, cfg, rules, connID, m)
		}()
	}

	// Drain active connections
	slog.Info("shutting down, draining active connections",
		"timeout", cfg.shutdownTimeout,
		"active", m.activeConns.Load())

	drainDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(drainDone)
	}()

	select {
	case <-drainDone:
		slog.Info("all connections drained")
	case <-time.After(cfg.shutdownTimeout):
		slog.Warn("shutdown timeout reached, forcing exit",
			"active", m.activeConns.Load())
	}

	// Shutdown health server
	if healthSrv != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		healthSrv.Shutdown(shutdownCtx)
	}

	slog.Info("imap-guard stopped",
		"total_proxied", m.totalProxied.Load(),
		"total_blocked", m.totalBlocked.Load())
}
