package responder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const shippedPlaybook = "../../../deploy/response/base/playbook.json"

var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

// fakeCluster records every call so tests can assert on the exact API traffic.
type fakeCluster struct {
	mu          sync.Mutex
	pods        map[string]*Pod
	selectors   map[string]map[string]string
	patches     []map[string]any
	deleted     []string
	configMaps  []*ConfigMap
	events      []*KubeEvent
	getCalls    int
	failPatch   error
	failGet     error
	failDelete  error
	failList    error
	failLogs    error
	failConfig  error
	failEvent   error
	failRSRead  error
	podsInLabel map[string][]Pod
}

func (f *fakeCluster) eventCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func newFakeCluster() *fakeCluster {
	return &fakeCluster{
		pods:        map[string]*Pod{},
		selectors:   map[string]map[string]string{},
		podsInLabel: map[string][]Pod{},
	}
}

func (f *fakeCluster) GetPod(_ context.Context, ns, name string) (*Pod, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	if f.failGet != nil {
		return nil, f.failGet
	}
	p, ok := f.pods[ns+"/"+name]
	if !ok {
		return nil, fmt.Errorf("pod %s: %w", name, ErrNotFound)
	}
	return p, nil
}

func (f *fakeCluster) ListPods(_ context.Context, ns, _ string) ([]Pod, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList != nil {
		return nil, f.failList
	}
	return f.podsInLabel[ns], nil
}

func (f *fakeCluster) PatchPod(_ context.Context, _, _ string, patch any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failPatch != nil {
		return f.failPatch
	}
	b, _ := json.Marshal(patch)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	f.patches = append(f.patches, m)
	return nil
}

func (f *fakeCluster) DeletePod(_ context.Context, ns, name, uid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDelete != nil {
		return f.failDelete
	}
	f.deleted = append(f.deleted, ns+"/"+name+"@"+uid)
	return nil
}

func (f *fakeCluster) PodLogs(_ context.Context, _, _, container string, _ int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failLogs != nil {
		return "", f.failLogs
	}
	return "log line from " + container + "\n", nil
}

func (f *fakeCluster) ReplicaSetSelector(_ context.Context, ns, name string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRSRead != nil {
		return nil, f.failRSRead
	}
	return f.selectors[ns+"/"+name], nil
}

func (f *fakeCluster) CreateConfigMap(_ context.Context, cm *ConfigMap) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failConfig != nil {
		return f.failConfig
	}
	f.configMaps = append(f.configMaps, cm)
	return nil
}

func (f *fakeCluster) CreateEvent(_ context.Context, ev *KubeEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failEvent != nil {
		return f.failEvent
	}
	f.events = append(f.events, ev)
	return nil
}

func testPod(ns, name string) *Pod {
	controller := true
	p := &Pod{}
	p.Metadata = ObjectMeta{
		Name: name, Namespace: ns, UID: "uid-" + name,
		Labels: map[string]string{"app": "web", "pod-template-hash": "abc"},
		OwnerReferences: []OwnerReference{
			{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-abc", Controller: &controller},
		},
	}
	p.Spec.NodeName = "node-1"
	p.Spec.Containers = append(p.Spec.Containers, struct {
		Name  string `json:"name"`
		Image string `json:"image"`
	}{Name: "app", Image: "alpine:3.23"})
	p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, struct {
		Name        string `json:"name"`
		ContainerID string `json:"containerID"`
	}{Name: "app", ContainerID: "containerd://0123456789abcdef0123456789abcdef"})
	p.Raw = json.RawMessage(`{"kind":"Pod"}`)
	return p
}

func testEvent(rule, priority, ns, pod string) Event {
	raw := fmt.Sprintf(`{"uuid":"u-1","rule":%q,"priority":%q,"time":%q,"output":"something bad",
		"tags":["aegis","container"],"hostname":"node-1",
		"output_fields":{"k8s.ns.name":%q,"k8s.pod.name":%q,"container.id":"0123456789ab"}}`,
		rule, priority, t0.Format(time.RFC3339Nano), ns, pod)
	ev, err := ParseEvent([]byte(raw))
	if err != nil {
		panic(err)
	}
	return ev
}

func newTestResponder(t *testing.T, kube Cluster) (*Responder, *Metrics) {
	t.Helper()
	pb, err := LoadPlaybook(shippedPlaybook)
	if err != nil {
		t.Fatalf("shipped playbook: %v", err)
	}
	m := NewMetrics()
	r := New(pb, kube, m, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.now = func() time.Time { return t0.Add(1500 * time.Millisecond) }
	return r, m
}

func TestContainShellInReplicaSetPod(t *testing.T) {
	kube := newFakeCluster()
	kube.pods["aegis-drill/web-1"] = testPod("aegis-drill", "web-1")
	kube.selectors["aegis-drill/web-abc"] = map[string]string{"app": "web", "pod-template-hash": "abc"}
	r, m := newTestResponder(t, kube)

	got := r.Handle(context.Background(), testEvent("Aegis Shell Spawned in Workload", "Warning", "aegis-drill", "web-1"))
	if got != DecisionContained {
		t.Fatalf("decision = %s, want contained", got)
	}

	if len(kube.patches) != 1 {
		t.Fatalf("patches = %d, want 1", len(kube.patches))
	}
	meta := kube.patches[0]["metadata"].(map[string]any)
	if meta["uid"] != "uid-web-1" {
		t.Errorf("patch has no UID precondition: %v", meta["uid"])
	}
	labels := meta["labels"].(map[string]any)
	if labels[LabelQuarantine] != "true" {
		t.Errorf("quarantine label missing: %v", labels)
	}
	for _, k := range []string{"app", "pod-template-hash"} {
		if v, ok := labels[k]; !ok || v != nil {
			t.Errorf("selector label %q must be removed (null), got %v", k, v)
		}
	}
	ann := meta["annotations"].(map[string]any)
	if ann[AnnotationTerminateAfter] != t0.Add(1500*time.Millisecond+300*time.Second).Format(time.RFC3339) {
		t.Errorf("terminate-after = %v", ann[AnnotationTerminateAfter])
	}
	if !strings.Contains(ann[AnnotationOriginalLabels].(string), `"pod-template-hash":"abc"`) {
		t.Errorf("original labels not preserved: %v", ann[AnnotationOriginalLabels])
	}

	if len(kube.configMaps) != 1 {
		t.Fatalf("evidence configmaps = %d, want 1", len(kube.configMaps))
	}
	cm := kube.configMaps[0]
	if !cm.Immutable || cm.Metadata.Namespace != "aegis-response" {
		t.Errorf("evidence must be immutable and stored in aegis-response: %+v", cm.Metadata)
	}
	for _, key := range []string{"falco-alert.json", "pod.json", "logs-app.txt", "incident.json"} {
		if cm.Data[key] == "" {
			t.Errorf("evidence is missing %s", key)
		}
	}
	var summary map[string]any
	if err := json.Unmarshal([]byte(cm.Data["incident.json"]), &summary); err != nil {
		t.Fatal(err)
	}
	if summary["containmentSec"].(float64) != 1.5 || summary["playbookRule"] != "contain-interactive-shell" {
		t.Errorf("incident summary = %v", summary)
	}

	if len(kube.events) != 1 || kube.events[0].Reason != "Quarantined" || kube.events[0].InvolvedObject.UID != "uid-web-1" {
		t.Fatalf("expected one Quarantined event on the pod, got %+v", kube.events)
	}
	if n := histogramCount(t, m.containment); n != 1 {
		t.Errorf("containment observations = %d, want 1", n)
	}
	if v := value(t, m.events.WithLabelValues("contained", "contain-interactive-shell")); v != 1 {
		t.Errorf("contained events = %v", v)
	}
	if v := value(t, m.actions.WithLabelValues("quarantine", "ok")); v != 1 {
		t.Errorf("quarantine actions = %v", v)
	}

	// A follow-up alert for the same pod is a duplicate and costs no API call.
	calls := kube.getCalls
	if got := r.Handle(context.Background(), testEvent("Aegis Credential File Read", "Critical", "aegis-drill", "web-1")); got != DecisionDuplicate {
		t.Errorf("second alert decision = %s, want duplicate", got)
	}
	if kube.getCalls != calls {
		t.Errorf("duplicate alert hit the API server")
	}
}

func TestDecisions(t *testing.T) {
	tests := []struct {
		name  string
		event Event
		setup func(*fakeCluster)
		want  Decision
	}{
		{
			name:  "discovery is only recorded",
			event: testEvent("Aegis Discovery Tool Executed", "Notice", "aegis-drill", "web-1"),
			want:  DecisionRecorded,
		},
		{
			name:  "unprotected namespace is ignored",
			event: testEvent("Aegis Shell Spawned in Workload", "Warning", "kube-system", "web-1"),
			want:  DecisionIgnored,
		},
		{
			name:  "rule outside the playbook is ignored",
			event: testEvent("Some Default Rule", "Warning", "aegis-drill", "web-1"),
			want:  DecisionIgnored,
		},
		{
			name:  "host-level alert is ignored",
			event: testEvent("Aegis Shell Spawned in Workload", "Warning", "", ""),
			want:  DecisionIgnored,
		},
		{
			name:  "the broad catch-all rule is notify-only: it reports but does not contain",
			event: testEvent("Some Critical Rule", "Critical", "aegis-drill", "web-1"),
			want:  DecisionNotified,
		},
		{
			name:  "pod already gone",
			event: testEvent("Aegis Shell Spawned in Workload", "Warning", "aegis-drill", "missing"),
			want:  DecisionIgnored,
		},
		{
			name:  "alert from another container is rejected",
			event: testEvent("Aegis Shell Spawned in Workload", "Warning", "aegis-drill", "web-1"),
			setup: func(f *fakeCluster) {
				f.pods["aegis-drill/web-1"].Status.ContainerStatuses[0].ContainerID = "containerd://ffffffffffffffff"
			},
			want: DecisionRejected,
		},
		{
			name:  "pod already labelled as quarantined",
			event: testEvent("Aegis Shell Spawned in Workload", "Warning", "aegis-drill", "web-1"),
			setup: func(f *fakeCluster) { f.pods["aegis-drill/web-1"].Metadata.Labels[LabelQuarantine] = "true" },
			want:  DecisionDuplicate,
		},
		{
			name:  "quarantine patch rejected",
			event: testEvent("Aegis Shell Spawned in Workload", "Warning", "aegis-drill", "web-1"),
			setup: func(f *fakeCluster) { f.failPatch = errors.New("forbidden") },
			want:  DecisionFailed,
		},
		{
			name:  "api server unavailable",
			event: testEvent("Aegis Shell Spawned in Workload", "Warning", "aegis-drill", "web-1"),
			setup: func(f *fakeCluster) { f.failGet = errors.New("connection refused") },
			want:  DecisionFailed,
		},
		{
			name:  "evidence and event failures do not undo containment",
			event: testEvent("Aegis Shell Spawned in Workload", "Warning", "aegis-drill", "web-1"),
			setup: func(f *fakeCluster) {
				f.failConfig = errors.New("quota exceeded")
				f.failEvent = errors.New("forbidden")
				f.failLogs = errors.New("container gone")
				f.failRSRead = errors.New("forbidden")
			},
			want: DecisionContained,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kube := newFakeCluster()
			kube.pods["aegis-drill/web-1"] = testPod("aegis-drill", "web-1")
			if tt.setup != nil {
				tt.setup(kube)
			}
			r, _ := newTestResponder(t, kube)
			if got := r.Handle(context.Background(), tt.event); got != tt.want {
				t.Errorf("decision = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestFailedContainmentIsRetried(t *testing.T) {
	kube := newFakeCluster()
	kube.pods["aegis-drill/web-1"] = testPod("aegis-drill", "web-1")
	kube.failPatch = errors.New("timeout")
	r, _ := newTestResponder(t, kube)
	ev := testEvent("Aegis Shell Spawned in Workload", "Warning", "aegis-drill", "web-1")

	if got := r.Handle(context.Background(), ev); got != DecisionFailed {
		t.Fatalf("first attempt = %s", got)
	}
	kube.failPatch = nil
	if got := r.Handle(context.Background(), ev); got != DecisionContained {
		t.Fatalf("retry = %s, want contained", got)
	}
}

func TestRecordOnlyCreatesEventWithoutPatching(t *testing.T) {
	kube := newFakeCluster()
	kube.pods["aegis-drill/web-1"] = testPod("aegis-drill", "web-1")
	r, _ := newTestResponder(t, kube)

	r.Handle(context.Background(), testEvent("Aegis Discovery Tool Executed", "Notice", "aegis-drill", "web-1"))
	if len(kube.patches) != 0 {
		t.Errorf("record-only rule patched the pod")
	}
	if len(kube.events) != 1 || kube.events[0].Reason != "SuspiciousActivity" {
		t.Errorf("events = %+v", kube.events)
	}
}

func TestReconcileTerminatesAfterHold(t *testing.T) {
	kube := newFakeCluster()
	expired, onHold, noDeadline := Pod{}, Pod{}, Pod{}
	expired.Metadata = ObjectMeta{Name: "old", UID: "u-old", Annotations: map[string]string{
		AnnotationTerminateAfter: t0.Format(time.RFC3339),
	}}
	onHold.Metadata = ObjectMeta{Name: "held", UID: "u-held", Annotations: map[string]string{
		AnnotationTerminateAfter: t0.Add(time.Hour).Format(time.RFC3339),
	}}
	noDeadline.Metadata = ObjectMeta{Name: "kept", UID: "u-kept"}
	kube.podsInLabel["aegis-drill"] = []Pod{expired, onHold, noDeadline}

	r, m := newTestResponder(t, kube)
	r.markHandled("aegis/stale")
	r.handled["aegis/stale"] = t0.Add(-2 * time.Hour)
	r.Reconcile(context.Background())

	if len(kube.deleted) != 1 || kube.deleted[0] != "aegis-drill/old@u-old" {
		t.Fatalf("deleted = %v, want only the expired pod (with UID precondition)", kube.deleted)
	}
	if v := value(t, m.quarantined); v != 2 {
		t.Errorf("quarantined gauge = %v, want 2", v)
	}
	if r.alreadyHandled("aegis/stale") {
		t.Errorf("stale dedupe entries must be forgotten")
	}

	kube.failDelete = errors.New("forbidden")
	kube.failList = nil
	r.Reconcile(context.Background())
	if v := value(t, m.actions.WithLabelValues("terminate", "error")); v != 1 {
		t.Errorf("terminate errors = %v", v)
	}

	kube.failDelete = fmt.Errorf("gone: %w", ErrNotFound)
	r.Reconcile(context.Background())
	kube.failList = errors.New("forbidden")
	r.Reconcile(context.Background())
}

func TestRunStopsWithContext(t *testing.T) {
	r, _ := newTestResponder(t, newFakeCluster())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, time.Millisecond); close(done) }()
	time.Sleep(5 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestIncidentIDIsDNSSafe(t *testing.T) {
	id := newIncidentID(t0)
	if !strings.HasPrefix(id, "20261023-120000-") || len(id) != len("20261023-120000-")+6 {
		t.Errorf("incident id = %q", id)
	}
}

// value reads the current value of a counter or gauge.
func value(t *testing.T, c prometheus.Metric) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	if m.Counter != nil {
		return m.Counter.GetValue()
	}
	return m.Gauge.GetValue()
}

func histogramCount(t *testing.T, h prometheus.Histogram) uint64 {
	t.Helper()
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.Histogram.GetSampleCount()
}

func TestMetricsStartAtZero(t *testing.T) {
	_, m := newTestResponder(t, newFakeCluster())
	mfs, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	series := 0
	for _, mf := range mfs {
		if mf.GetName() == "aegis_responder_events_total" {
			series = len(mf.GetMetric())
		}
	}
	// 7 decisions x (4 playbook rules + "none"): the first incident must be an
	// increase from 0, not a new series that increase() cannot see.
	if series != 35 {
		t.Errorf("pre-initialised event series = %d, want 35", series)
	}
	if v := value(t, m.events.WithLabelValues("contained", "contain-credential-access")); v != 0 {
		t.Errorf("initial value = %v", v)
	}
}

func TestNotifyOnlyChangesNothing(t *testing.T) {
	kube := newFakeCluster()
	kube.pods["aegis-drill/web-1"] = testPod("aegis-drill", "web-1")
	r, m := newTestResponder(t, kube)
	r.playbook.NotifyOnly = true // RESPONDER_MODE=notify

	ev := testEvent("Aegis Shell Spawned in Workload", "Warning", "aegis-drill", "web-1")
	if got := r.Handle(context.Background(), ev); got != DecisionNotified {
		t.Fatalf("decision = %s, want notified", got)
	}
	if len(kube.patches) != 0 || len(kube.configMaps) != 0 || len(kube.deleted) != 0 {
		t.Fatalf("notify-only must not touch the cluster: patches=%d configmaps=%d deleted=%d",
			len(kube.patches), len(kube.configMaps), len(kube.deleted))
	}
	if len(kube.events) != 1 || kube.events[0].Reason != "WouldQuarantine" ||
		!strings.Contains(kube.events[0].Message, "contain-interactive-shell") {
		t.Fatalf("expected one WouldQuarantine event naming the rule, got %+v", kube.events)
	}
	if v := value(t, m.events.WithLabelValues("notified", "contain-interactive-shell")); v != 1 {
		t.Errorf("notified events = %v", v)
	}

	// The same pod is reported once, not once per alert.
	if got := r.Handle(context.Background(), ev); got != DecisionDuplicate {
		t.Errorf("second alert = %s, want duplicate", got)
	}
	if len(kube.events) != 1 {
		t.Errorf("events = %d, want 1", len(kube.events))
	}

	// Switching back to enforce on a new pod contains it.
	r.playbook.NotifyOnly = false
	kube.pods["aegis-drill/web-2"] = testPod("aegis-drill", "web-2")
	if got := r.Handle(context.Background(), testEvent("Aegis Shell Spawned in Workload", "Warning", "aegis-drill", "web-2")); got != DecisionContained {
		t.Errorf("enforce decision = %s, want contained", got)
	}
}
