package api

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	registry     *prometheus.Registry
	requests     *prometheus.CounterVec
	duration     *prometheus.HistogramVec
	authFailures prometheus.Counter
	rateLimited  prometheus.Counter
	transactions prometheus.Gauge
}

func newMetrics() *metrics {
	m := &metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ledger_http_requests_total",
			Help: "HTTP requests by method, route and status code.",
		}, []string{"method", "route", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ledger_http_request_duration_seconds",
			Help:    "HTTP request latency by route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route"}),
		authFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ledger_auth_failures_total",
			Help: "Requests rejected because of a missing or invalid token.",
		}),
		rateLimited: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ledger_rate_limited_total",
			Help: "Requests rejected by the per-client rate limiter.",
		}),
		transactions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ledger_transactions",
			Help: "Number of stored transactions.",
		}),
	}
	m.registry.MustRegister(
		m.requests, m.duration, m.authFailures, m.rateLimited, m.transactions,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

func (m *metrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
