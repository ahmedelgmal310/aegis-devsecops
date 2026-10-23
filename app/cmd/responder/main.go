// Command responder is the Aegis automated incident responder. Falco sends
// its runtime alerts here over mutual TLS; the responder isolates the
// compromised pod, preserves evidence and lets Kubernetes replace it.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ahmedelgmal310/aegis-devsecops/app/internal/responder"
)

// Set at build time with -ldflags.
var (
	version = "dev"
	commit  = "unknown"
)

type config struct {
	addr, opsAddr     string
	playbook          string
	cert, key, ca     string
	allowedClients    []string
	holdSeconds       int
	holdOverrideIsSet bool
	reconcileEvery    time.Duration
	queueSize         int
}

func main() {
	opsAddr := envOr("RESPONDER_OPS_ADDR", ":9090")
	// The runtime image has no shell or curl, so the binary checks itself.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(opsAddr))
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := loadConfig(opsAddr)
	if err == nil {
		err = run(logger, cfg)
	}
	if err != nil {
		logger.Error("responder stopped", "error", err)
		os.Exit(1)
	}
}

func loadConfig(opsAddr string) (config, error) {
	cfg := config{
		addr:           envOr("RESPONDER_ADDR", ":8443"),
		opsAddr:        opsAddr,
		playbook:       envOr("RESPONDER_PLAYBOOK", "/etc/aegis-responder/playbook.json"),
		cert:           envOr("RESPONDER_TLS_CERT", "/etc/aegis-responder/tls/tls.crt"),
		key:            envOr("RESPONDER_TLS_KEY", "/etc/aegis-responder/tls/tls.key"),
		ca:             envOr("RESPONDER_CLIENT_CA", "/etc/aegis-responder/tls/ca.crt"),
		allowedClients: strings.Split(envOr("RESPONDER_ALLOWED_CLIENTS", "falco"), ","),
		reconcileEvery: 5 * time.Second,
		queueSize:      1024,
	}
	if v := os.Getenv("RESPONDER_HOLD_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return cfg, fmt.Errorf("RESPONDER_HOLD_SECONDS must be a non-negative integer, got %q", v)
		}
		cfg.holdSeconds, cfg.holdOverrideIsSet = n, true
	}
	return cfg, nil
}

func run(logger *slog.Logger, cfg config) error {
	pb, err := responder.LoadPlaybook(cfg.playbook)
	if err != nil {
		return err
	}
	if cfg.holdOverrideIsSet {
		pb.QuarantineHoldSeconds = cfg.holdSeconds
	}
	tlsConfig, err := mutualTLS(cfg.cert, cfg.key, cfg.ca)
	if err != nil {
		return err
	}
	kube, err := responder.InClusterClient()
	if err != nil {
		return err
	}

	metrics := responder.NewMetrics()
	resp := responder.New(pb, kube, metrics, logger)
	intake := responder.NewIntake(resp, metrics, logger, cfg.allowedClients, cfg.queueSize)

	var ready atomic.Bool
	alerts := &http.Server{
		Addr:              cfg.addr,
		Handler:           intake.Handler(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ops := &http.Server{
		Addr:              cfg.opsAddr,
		Handler:           responder.OpsHandler(metrics, ready.Load),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); intake.Work(ctx) }()
	go func() { defer wg.Done(); resp.Run(ctx, cfg.reconcileEvery) }()

	errCh := make(chan error, 2)
	go func() { errCh <- alerts.ListenAndServeTLS("", "") }()
	go func() { errCh <- ops.ListenAndServe() }()
	ready.Store(true)
	logger.Info("responder listening",
		"alerts_addr", cfg.addr, "ops_addr", cfg.opsAddr, "version", version, "commit", commit,
		"protected_namespaces", pb.Namespaces, "hold_seconds", pb.QuarantineHoldSeconds,
		"playbook_rules", len(pb.Rules))

	var runErr error
	select {
	case runErr = <-errCh:
	case <-ctx.Done():
	}
	ready.Store(false)
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = alerts.Shutdown(shutdownCtx)
	_ = ops.Shutdown(shutdownCtx)
	wg.Wait()
	if runErr != nil && !errors.Is(runErr, http.ErrServerClosed) {
		return runErr
	}
	return nil
}

// mutualTLS only accepts clients presenting a certificate issued by the
// responder's own CA. Falco is the only holder of such a certificate.
func mutualTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Clean(caFile)) // #nosec G304 -- operator-controlled path from the pod spec
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("client CA bundle has no certificates")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
