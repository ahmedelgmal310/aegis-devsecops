package responder

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"golang.org/x/time/rate"
)

const maxAlertBytes = 64 << 10

// Intake receives Falco alerts over mutually authenticated TLS and feeds
// them to the Responder through a bounded queue, so a burst of alerts can
// never block Falco or exhaust the responder's memory.
type Intake struct {
	responder      *Responder
	metrics        *Metrics
	log            *slog.Logger
	allowedClients []string
	limiter        *rate.Limiter
	queue          chan Event
}

// NewIntake returns an Intake. allowedClients are the certificate common
// names accepted as alert sources (normally just "falco").
func NewIntake(r *Responder, m *Metrics, log *slog.Logger, allowedClients []string, queueSize int) *Intake {
	return &Intake{
		responder:      r,
		metrics:        m,
		log:            log,
		allowedClients: allowedClients,
		limiter:        rate.NewLimiter(50, 200),
		queue:          make(chan Event, queueSize),
	}
}

// Handler serves POST /v1/falco.
func (in *Intake) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/falco", in.handleAlert)
	return mux
}

func (in *Intake) handleAlert(w http.ResponseWriter, r *http.Request) {
	// The TLS layer already verified the chain; this pins the identity.
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 ||
		!slices.Contains(in.allowedClients, r.TLS.VerifiedChains[0][0].Subject.CommonName) {
		in.metrics.dropped.WithLabelValues("unauthenticated").Inc()
		http.Error(w, "client certificate not allowed", http.StatusForbidden)
		return
	}
	if !in.limiter.Allow() {
		in.metrics.dropped.WithLabelValues("rate_limited").Inc()
		http.Error(w, "too many alerts", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAlertBytes))
	if err != nil {
		in.metrics.dropped.WithLabelValues("too_large").Inc()
		http.Error(w, "alert too large", http.StatusRequestEntityTooLarge)
		return
	}
	ev, err := ParseEvent(body)
	if err != nil {
		in.metrics.dropped.WithLabelValues("invalid").Inc()
		http.Error(w, "invalid falco alert", http.StatusBadRequest)
		return
	}
	select {
	case in.queue <- ev:
		w.WriteHeader(http.StatusAccepted)
	default:
		in.metrics.dropped.WithLabelValues("queue_full").Inc()
		http.Error(w, "queue full", http.StatusServiceUnavailable)
	}
}

// Work handles queued alerts one at a time until the context ends.
func (in *Intake) Work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-in.queue:
			hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			in.responder.Handle(hctx, ev)
			cancel()
		}
	}
}

// OpsHandler serves the plain-HTTP operational endpoints: health, readiness
// and metrics. It never accepts alerts.
func OpsHandler(m *Metrics, ready func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.Handle("GET /metrics", m.Handler())
	return mux
}
