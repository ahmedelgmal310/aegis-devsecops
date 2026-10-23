package responder

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics are the responder's Prometheus series. Label values come from the
// playbook and fixed enums, never from the alert text, so cardinality stays
// bounded whatever an attacker does.
type Metrics struct {
	registry    *prometheus.Registry
	events      *prometheus.CounterVec
	actions     *prometheus.CounterVec
	dropped     *prometheus.CounterVec
	containment prometheus.Histogram
	quarantined prometheus.Gauge
}

// NewMetrics registers the responder metrics on a fresh registry.
func NewMetrics() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aegis_responder_events_total",
			Help: "Falco alerts handled, by decision and playbook rule.",
		}, []string{"decision", "playbook_rule"}),
		actions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aegis_responder_actions_total",
			Help: "Response actions executed, by action and result.",
		}, []string{"action", "result"}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aegis_responder_alerts_dropped_total",
			Help: "Alerts rejected before handling, by reason.",
		}, []string{"reason"}),
		containment: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "aegis_responder_containment_seconds",
			Help:    "Time from the Falco detection to the pod being isolated.",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30},
		}),
		quarantined: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "aegis_responder_quarantined_pods",
			Help: "Pods currently isolated and waiting for termination.",
		}),
	}
	m.registry.MustRegister(
		m.events, m.actions, m.dropped, m.containment, m.quarantined,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Initialize creates every series at zero, so the first incident shows up as
// an increase in Prometheus instead of a brand-new series (which increase()
// cannot see).
func (m *Metrics) Initialize(pb *Playbook) {
	rules := []string{"none"}
	for _, r := range pb.Rules {
		rules = append(rules, r.Name)
	}
	for _, d := range []Decision{DecisionContained, DecisionRecorded, DecisionNotified, DecisionDuplicate, DecisionIgnored, DecisionRejected, DecisionFailed} {
		for _, r := range rules {
			m.events.WithLabelValues(string(d), r)
		}
	}
	for _, a := range []Action{ActionRecord, ActionQuarantine, ActionEvidence, ActionTerminate} {
		m.actions.WithLabelValues(string(a), "ok")
		m.actions.WithLabelValues(string(a), "error")
	}
	for _, reason := range []string{"unauthenticated", "rate_limited", "too_large", "invalid", "queue_full"} {
		m.dropped.WithLabelValues(reason)
	}
}

// Handler serves the metrics in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) action(a Action, err error) {
	result := "ok"
	if err != nil {
		result = "error"
	}
	m.actions.WithLabelValues(string(a), result).Inc()
}
