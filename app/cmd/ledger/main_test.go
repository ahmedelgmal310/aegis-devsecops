//go:build unix

package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return "127.0.0.1:" + strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

func TestRunServesAndShutsDownGracefully(t *testing.T) {
	addr := freeAddr(t)
	t.Setenv("LEDGER_API_TOKEN", "")
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	done := make(chan error, 1)
	go func() { done <- run(logger, addr) }()

	deadline := time.Now().Add(5 * time.Second)
	for healthcheck(addr) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("server never became healthy")
		}
		time.Sleep(50 * time.Millisecond)
	}

	resp, err := http.Get("http://" + addr + "/api/v1/transactions")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("api without token = %d, want 503", resp.StatusCode)
	}

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestRunFailsOnBadAddress(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if err := run(logger, "256.0.0.1:bad"); err == nil {
		t.Fatal("expected listen error")
	}
}

func TestHealthcheckFailsWhenDown(t *testing.T) {
	if code := healthcheck(freeAddr(t)); code != 1 {
		t.Fatalf("healthcheck = %d, want 1", code)
	}
}

func TestLoadToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEDGER_API_TOKEN", "env-token")

	t.Setenv("LEDGER_API_TOKEN_FILE", path)
	if got, err := loadToken(); err != nil || got != "file-token" {
		t.Fatalf("loadToken() = %q, %v; want file-token", got, err)
	}

	t.Setenv("LEDGER_API_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := loadToken(); err == nil {
		t.Fatal("expected error for missing token file")
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if err := run(logger, freeAddr(t)); err == nil {
		t.Fatal("run should fail when the token file is missing")
	}

	t.Setenv("LEDGER_API_TOKEN_FILE", "")
	if got, _ := loadToken(); got != "env-token" {
		t.Fatalf("loadToken() = %q, want env-token", got)
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("LEDGER_TEST_VALUE", "set")
	if got := envOr("LEDGER_TEST_VALUE", "fallback"); got != "set" {
		t.Fatalf("envOr = %q", got)
	}
	if got := envOr("LEDGER_TEST_MISSING", "fallback"); got != "fallback" {
		t.Fatalf("envOr = %q", got)
	}
}
