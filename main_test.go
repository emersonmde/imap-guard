package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestShouldStripCaps(t *testing.T) {
	tests := []struct {
		name string
		cfg  config
		want bool
	}{
		{"no client TLS strips caps", config{}, true},
		{"client TLS does not strip", config{clientTLSCert: "/some/cert.pem", clientTLSKey: "/some/key.pem"}, false},
		{"only cert set strips caps", config{clientTLSCert: "/some/cert.pem"}, true},
		{"only key set strips caps", config{clientTLSKey: "/some/key.pem"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.shouldStripCaps()
			if got != tt.want {
				t.Errorf("shouldStripCaps() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseConfigValidation(t *testing.T) {
	// clearEnv sets all config env vars to empty via t.Setenv (auto-restored on subtest cleanup)
	clearEnv := func(t *testing.T) {
		t.Helper()
		for _, k := range []string{
			"IMAP_GUARD_LISTEN", "IMAP_GUARD_UPSTREAM",
			"IMAP_GUARD_UPSTREAM_TLS", "IMAP_GUARD_UPSTREAM_VERIFY",
			"IMAP_GUARD_CLIENT_TLS_CERT", "IMAP_GUARD_CLIENT_TLS_KEY",
			"IMAP_GUARD_LOG_FORMAT", "IMAP_GUARD_LOG_LEVEL",
			"IMAP_GUARD_SHUTDOWN_TIMEOUT", "IMAP_GUARD_IDLE_TIMEOUT",
			"IMAP_GUARD_SESSION_TIMEOUT", "IMAP_GUARD_MAX_CONNECTIONS",
		} {
			t.Setenv(k, "")
		}
	}

	t.Run("defaults", func(t *testing.T) {
		clearEnv(t)
		cfg, err := parseConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.listenAddr != ":1143" {
			t.Errorf("listenAddr = %q, want :1143", cfg.listenAddr)
		}
		if cfg.upstreamAddr != "127.0.0.1:143" {
			t.Errorf("upstreamAddr = %q, want 127.0.0.1:143", cfg.upstreamAddr)
		}
		if cfg.upstreamTLS != upstreamSTARTTLS {
			t.Errorf("upstreamTLS = %d, want upstreamSTARTTLS", cfg.upstreamTLS)
		}
		if cfg.upstreamVerify != "verify" {
			t.Errorf("upstreamVerify = %q, want verify", cfg.upstreamVerify)
		}
	})

	t.Run("invalid TLS mode", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("IMAP_GUARD_UPSTREAM_TLS", "invalid")
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for invalid TLS mode")
		}
		if !strings.Contains(err.Error(), "invalid") {
			t.Errorf("error should mention 'invalid', got: %v", err)
		}
	})

	t.Run("skip verify with plaintext", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("IMAP_GUARD_UPSTREAM_TLS", "plaintext")
		t.Setenv("IMAP_GUARD_UPSTREAM_VERIFY", "skip")
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for skip+plaintext")
		}
		if !strings.Contains(err.Error(), "no TLS to verify") {
			t.Errorf("error should mention no TLS, got: %v", err)
		}
	})

	t.Run("CA file with plaintext", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("IMAP_GUARD_UPSTREAM_TLS", "plaintext")
		t.Setenv("IMAP_GUARD_UPSTREAM_VERIFY", "/some/ca.pem")
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for CA file+plaintext")
		}
	})

	t.Run("cert without key", func(t *testing.T) {
		clearEnv(t)
		tmpDir := t.TempDir()
		certFile := filepath.Join(tmpDir, "cert.pem")
		if err := os.WriteFile(certFile, []byte("dummy"), 0o600); err != nil {
			t.Fatalf("write cert: %v", err)
		}
		t.Setenv("IMAP_GUARD_CLIENT_TLS_CERT", certFile)
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for cert without key")
		}
		if !strings.Contains(err.Error(), "both be set") {
			t.Errorf("error should mention both, got: %v", err)
		}
	})

	t.Run("key without cert", func(t *testing.T) {
		clearEnv(t)
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "key.pem")
		if err := os.WriteFile(keyFile, []byte("dummy"), 0o600); err != nil {
			t.Fatalf("write key: %v", err)
		}
		t.Setenv("IMAP_GUARD_CLIENT_TLS_KEY", keyFile)
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for key without cert")
		}
	})

	t.Run("nonexistent CA file", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("IMAP_GUARD_UPSTREAM_VERIFY", "/nonexistent/ca.pem")
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for nonexistent CA file")
		}
	})

	t.Run("nonexistent cert file", func(t *testing.T) {
		clearEnv(t)
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "key.pem")
		if err := os.WriteFile(keyFile, []byte("dummy"), 0o600); err != nil {
			t.Fatalf("write key: %v", err)
		}
		t.Setenv("IMAP_GUARD_CLIENT_TLS_CERT", "/nonexistent/cert.pem")
		t.Setenv("IMAP_GUARD_CLIENT_TLS_KEY", keyFile)
		_, err := parseConfig()
		if err == nil {
			t.Fatal("expected error for nonexistent cert file")
		}
	})

	t.Run("plaintext mode", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("IMAP_GUARD_UPSTREAM_TLS", "plaintext")
		cfg, err := parseConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.upstreamTLS != upstreamPlaintext {
			t.Errorf("upstreamTLS = %d, want upstreamPlaintext", cfg.upstreamTLS)
		}
	})

	t.Run("tls mode", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("IMAP_GUARD_UPSTREAM_TLS", "tls")
		cfg, err := parseConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.upstreamTLS != upstreamImplicitTLS {
			t.Errorf("upstreamTLS = %d, want upstreamImplicitTLS", cfg.upstreamTLS)
		}
	})
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input   string
		want    slog.Level
		wantErr bool
	}{
		{"debug", slog.LevelDebug, false},
		{"info", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"INFO", slog.LevelInfo, false},
		{"Debug", slog.LevelDebug, false},
		{"invalid", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := parseLogLevel(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseLogLevel(%q) error=%v, wantErr=%v", tt.input, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("parseLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseDuration(t *testing.T) {
	const key = "IMAP_GUARD_TEST_DUR"

	t.Run("default value", func(t *testing.T) {
		t.Setenv(key, "") // ensure clean state
		d, err := parseDuration(key, "5m")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d != 5*time.Minute {
			t.Errorf("got %v, want 5m", d)
		}
	})

	t.Run("env override", func(t *testing.T) {
		t.Setenv(key, "10s")
		d, err := parseDuration(key, "5m")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d != 10*time.Second {
			t.Errorf("got %v, want 10s", d)
		}
	})

	t.Run("invalid value", func(t *testing.T) {
		t.Setenv(key, "notaduration")
		_, err := parseDuration(key, "5m")
		if err == nil {
			t.Fatal("expected error for invalid duration")
		}
	})
}

func TestMetrics(t *testing.T) {
	m := &metrics{}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.activeConns.Add(1)
			m.totalProxied.Add(1)
			m.totalBlocked.Add(1)
			m.activeConns.Add(-1)
		}()
	}
	wg.Wait()

	if m.activeConns.Load() != 0 {
		t.Errorf("activeConns = %d, want 0", m.activeConns.Load())
	}
	if m.totalProxied.Load() != 100 {
		t.Errorf("totalProxied = %d, want 100", m.totalProxied.Load())
	}
	if m.totalBlocked.Load() != 100 {
		t.Errorf("totalBlocked = %d, want 100", m.totalBlocked.Load())
	}
}

func TestHealthEndpoint(t *testing.T) {
	m := &metrics{}
	m.activeConns.Store(5)
	m.totalProxied.Store(1234)
	m.totalBlocked.Store(12)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_ = ln.Close() // free the port

	srv := startHealthServer(ln.Addr().String(), m)
	defer func() { _ = srv.Close() }()

	// Poll until the health server is ready instead of a fixed sleep
	addr := "http://" + ln.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Run("healthz", func(t *testing.T) {
		resp, err := http.Get(addr + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if strings.TrimSpace(string(body)) != "ok" {
			t.Errorf("body = %q, want ok", string(body))
		}
	})

	t.Run("metrics", func(t *testing.T) {
		resp, err := http.Get(addr + "/metrics")
		if err != nil {
			t.Fatalf("GET /metrics: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		var result map[string]float64
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode JSON: %v", err)
		}
		if result["active_connections"] != 5 {
			t.Errorf("active_connections = %v, want 5", result["active_connections"])
		}
		if result["total_commands_proxied"] != 1234 {
			t.Errorf("total_commands_proxied = %v, want 1234", result["total_commands_proxied"])
		}
		if result["total_commands_blocked"] != 12 {
			t.Errorf("total_commands_blocked = %v, want 12", result["total_commands_blocked"])
		}
	})
}
