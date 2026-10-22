// Command ledger runs the Aegis demo workload, a small transactions API used
// to exercise the platform's supply-chain and runtime security controls.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ahmedelgmal310/aegis-devsecops/app/internal/api"
)

// Set at build time with -ldflags.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	addr := envOr("LEDGER_ADDR", ":8080")

	// The runtime image has no shell or curl, so the binary checks itself.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(addr))
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger, addr); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, addr string) error {
	token, err := loadToken()
	if err != nil {
		return err
	}
	if token == "" {
		logger.Warn("no API token configured; /api routes are disabled")
	}

	srv := api.New(api.Config{
		Token:   token,
		Version: version,
		Commit:  commit,
		Logger:  logger,
	})
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("ledger listening", "addr", addr, "version", version, "commit", commit)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	// Fail readiness first so the Service stops routing new traffic here.
	srv.SetReady(false)
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func healthcheck(addr string) int {
	port := addr[strings.LastIndex(addr, ":")+1:]
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz") // #nosec G107 -- loopback URL built from our own listen address
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// loadToken prefers a mounted secret file (LEDGER_API_TOKEN_FILE) over an
// environment variable, so the token never shows up in the process environment.
func loadToken() (string, error) {
	if path := os.Getenv("LEDGER_API_TOKEN_FILE"); path != "" {
		b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 G703 -- operator-controlled path from the pod spec, never from a request
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv("LEDGER_API_TOKEN"), nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
