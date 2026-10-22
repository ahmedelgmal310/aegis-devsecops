// Package api exposes the ledger over HTTP with authentication, input
// validation, rate limiting, security headers and Prometheus metrics.
package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/ahmedelgmal310/aegis-devsecops/app/internal/ledger"
)

const maxBodyBytes = 4 << 10

//go:embed static
var staticFiles embed.FS

// Config holds the runtime settings of the API server.
type Config struct {
	// Token is the bearer token required for /api routes. An empty token
	// disables the API instead of leaving it open (fail closed).
	Token   string
	Version string
	Commit  string
	Logger  *slog.Logger
	// RequestsPerSecond and Burst size the per-client rate limiter.
	RequestsPerSecond float64
	Burst             int
	// Capacity bounds the number of stored transactions.
	Capacity int
}

// Server is the HTTP front end of the ledger.
type Server struct {
	cfg     Config
	store   *ledger.Store
	metrics *metrics
	limiter *clientLimiter
	ready   atomic.Bool
	handler http.Handler
}

// New builds a Server and its route table.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = 20
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 40
	}
	s := &Server{
		cfg:     cfg,
		store:   ledger.NewStore(cfg.Capacity),
		metrics: newMetrics(),
		limiter: newClientLimiter(cfg.RequestsPerSecond, cfg.Burst),
	}
	s.ready.Store(true)

	static, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err) // embedded at build time, cannot fail at runtime
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex(static))
	mux.Handle("GET /static/", cacheStatic(http.StripPrefix("/static/", http.FileServerFS(static))))
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /version", s.handleVersion)
	mux.Handle("GET /metrics", s.metrics.handler())
	mux.HandleFunc("GET /api/v1/transactions", s.requireToken(s.handleList))
	mux.HandleFunc("POST /api/v1/transactions", s.requireToken(s.handleCreate))
	mux.HandleFunc("GET /api/v1/transactions/{id}", s.requireToken(s.handleGet))

	s.handler = chain(mux,
		recoverPanics(cfg.Logger),
		requestID,
		securityHeaders,
		s.observe,
		s.rateLimit,
	)
	return s
}

// Handler returns the fully wrapped HTTP handler.
func (s *Server) Handler() http.Handler { return s.handler }

// SetReady flips the readiness probe, e.g. while shutting down.
func (s *Server) SetReady(ready bool) { s.ready.Store(ready) }

func (s *Server) handleIndex(static fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		page, err := fs.ReadFile(static, "index.html")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "page unavailable")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "shutting down"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.cfg.Version, "commit": s.cfg.Commit})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "limit must be an integer between 1 and 500")
			return
		}
		limit = n
	}
	items := s.store.List(limit)
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}

	var in ledger.NewTransaction
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "request body must be a single valid JSON object")
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "request body must be a single valid JSON object")
		return
	}

	t, err := s.store.Create(in)
	var ve *ledger.ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "validation failed", "details": ve})
		return
	case errors.Is(err, ledger.ErrFull):
		writeError(w, http.StatusServiceUnavailable, "ledger is full")
		return
	case err != nil:
		s.cfg.Logger.Error("create transaction", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.metrics.transactions.Set(float64(s.store.Len()))
	w.Header().Set("Location", "/api/v1/transactions/"+t.ID)
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.Get(r.PathValue("id"))
	if errors.Is(err, ledger.ErrNotFound) {
		writeError(w, http.StatusNotFound, "transaction not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// requireToken enforces bearer-token authentication with a constant-time
// comparison. Hashing both sides first also hides the token length.
func (s *Server) requireToken(next http.HandlerFunc) http.HandlerFunc {
	want := sha256.Sum256([]byte(s.cfg.Token))
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token == "" {
			writeError(w, http.StatusServiceUnavailable, "api disabled: no token configured")
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		got := sha256.Sum256([]byte(token))
		if !ok || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			s.metrics.authFailures.Inc()
			w.Header().Set("WWW-Authenticate", `Bearer realm="ledger"`)
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
