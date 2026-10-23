package responder

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAPIServer mimics the few Kubernetes API endpoints the client calls and
// records each request.
func fakeAPIServer(t *testing.T) (*APIClient, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sa-token" {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("Content-Type")+" "+string(body))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/ns/pods/web-1":
			_, _ = w.Write([]byte(`{"metadata":{"name":"web-1","uid":"u1"},"spec":{"nodeName":"n1"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/ns/pods/web-1/log":
			_, _ = w.Write([]byte("line 1\n"))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/ns/pods":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"q1"}}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/apis/apps/v1/namespaces/ns/replicasets/web-abc":
			_, _ = w.Write([]byte(`{"spec":{"selector":{"matchLabels":{"app":"web"}}}}`))
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/configmaps"):
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"message":"configmaps \"incident-x\" already exists"}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewAPIClient(srv.URL+"/", tokenFile, nil)
	c.http = srv.Client()
	return c, &calls
}

func TestAPIClient(t *testing.T) {
	c, calls := fakeAPIServer(t)
	ctx := context.Background()

	pod, err := c.GetPod(ctx, "ns", "web-1")
	if err != nil || pod.Metadata.UID != "u1" || !strings.Contains(string(pod.Raw), `"nodeName":"n1"`) {
		t.Fatalf("GetPod = %+v, %v", pod, err)
	}
	if _, err := c.GetPod(ctx, "ns", "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing pod error = %v, want ErrNotFound", err)
	}
	pods, err := c.ListPods(ctx, "ns", "aegis.dev/quarantine=true")
	if err != nil || len(pods) != 1 {
		t.Errorf("ListPods = %v, %v", pods, err)
	}
	logs, err := c.PodLogs(ctx, "ns", "web-1", "app", 50)
	if err != nil || logs != "line 1\n" {
		t.Errorf("PodLogs = %q, %v", logs, err)
	}
	sel, err := c.ReplicaSetSelector(ctx, "ns", "web-abc")
	if err != nil || sel["app"] != "web" {
		t.Errorf("ReplicaSetSelector = %v, %v", sel, err)
	}
	if err := c.PatchPod(ctx, "ns", "web-1", map[string]any{"metadata": map[string]any{"labels": map[string]any{"x": nil}}}); err != nil {
		t.Errorf("PatchPod: %v", err)
	}
	if err := c.DeletePod(ctx, "ns", "web-1", "u1"); err != nil {
		t.Errorf("DeletePod: %v", err)
	}
	if err := c.CreateEvent(ctx, &KubeEvent{Metadata: ObjectMeta{Namespace: "ns"}}); err != nil {
		t.Errorf("CreateEvent: %v", err)
	}
	err = c.CreateConfigMap(ctx, &ConfigMap{Metadata: ObjectMeta{Namespace: "evidence", Name: "incident-x"}})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("CreateConfigMap error = %v, want the API server's message", err)
	}

	want := []string{
		"GET /api/v1/namespaces/ns/pods?labelSelector=aegis.dev%2Fquarantine%3Dtrue",
		"GET /api/v1/namespaces/ns/pods/web-1/log?container=app&tailLines=50&timestamps=true",
		`PATCH /api/v1/namespaces/ns/pods/web-1 application/merge-patch+json {"metadata":{"labels":{"x":null}}}`,
		`DELETE /api/v1/namespaces/ns/pods/web-1 application/json {"apiVersion":"v1","gracePeriodSeconds":0,"kind":"DeleteOptions","preconditions":{"uid":"u1"}}`,
		`POST /api/v1/namespaces/ns/events application/json {"apiVersion":"v1","kind":"Event"`,
		`POST /api/v1/namespaces/evidence/configmaps application/json {"apiVersion":"v1","kind":"ConfigMap"`,
	}
	joined := strings.Join(*calls, "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("missing request %q in:\n%s", w, joined)
		}
	}
}

func TestAPIClientRereadsTokenAndReportsErrors(t *testing.T) {
	c, _ := fakeAPIServer(t)
	if err := os.WriteFile(c.tokenFile, []byte("rotated-but-wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := c.GetPod(context.Background(), "ns", "web-1")
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("error = %v, want 401 with the API message", err)
	}
	c.tokenFile = filepath.Join(t.TempDir(), "missing")
	if _, err := c.GetPod(context.Background(), "ns", "web-1"); err == nil {
		t.Error("expected an error when the token file is missing")
	}
}

func TestAPIMessage(t *testing.T) {
	if got := apiMessage([]byte(`{"message":"denied"}`)); got != "denied" {
		t.Errorf("apiMessage = %q", got)
	}
	long := strings.Repeat("x", 300)
	if got := apiMessage([]byte(long)); len(got) != 200 {
		t.Errorf("non-JSON body must be truncated, got %d bytes", len(got))
	}
}

func TestInClusterClientOutsideCluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := InClusterClient(); err == nil {
		t.Error("expected an error outside a cluster")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	if _, err := InClusterClient(); err == nil {
		t.Error("expected an error without a service account CA")
	}
}

func TestPodHelpers(t *testing.T) {
	p := testPod("ns", "web-1")
	if owner := p.Controller(); owner == nil || owner.Name != "web-abc" {
		t.Errorf("Controller = %+v", owner)
	}
	for id, want := range map[string]bool{"0123456789ab": true, "ffffffffffff": false, "0123": false} {
		if got := p.RunsContainer(id); got != want {
			t.Errorf("RunsContainer(%q) = %v, want %v", id, got, want)
		}
	}
	p.Status.ContainerStatuses[0].ContainerID = "0123456789abcdef"
	if !p.RunsContainer("0123456789ab") {
		t.Error("container IDs without a runtime prefix must match too")
	}
	p.Metadata.OwnerReferences = nil
	if p.Controller() != nil {
		t.Error("bare pod has no controller")
	}
}

func TestEventParsing(t *testing.T) {
	ev := testEvent("R", "Warning", "ns", "p")
	if ev.Priority != PriorityWarning || ev.Namespace() != "ns" || ev.Pod() != "p" || ev.ContainerID() != "0123456789ab" {
		t.Errorf("parsed event = %+v", ev)
	}
	if !ev.HasTag("aegis") || ev.HasTag("nope") {
		t.Error("HasTag")
	}
	var raw map[string]any
	if err := json.Unmarshal(ev.Raw, &raw); err != nil {
		t.Errorf("raw payload must be kept intact: %v", err)
	}

	for name, body := range map[string]string{
		"not json":     `{`,
		"no rule":      `{"priority":"Warning","time":"2026-10-23T12:00:00Z"}`,
		"no time":      `{"rule":"R","priority":"Warning"}`,
		"bad priority": `{"rule":"R","priority":"Spicy","time":"2026-10-23T12:00:00Z"}`,
		"priority num": `{"rule":"R","priority":5,"time":"2026-10-23T12:00:00Z"}`,
	} {
		if _, err := ParseEvent([]byte(body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	na := testEvent("R", "Warning", "<NA>", "p")
	if na.Namespace() != "" {
		t.Error("<NA> fields must read as empty")
	}
}

func TestPriorities(t *testing.T) {
	for in, want := range map[string]Priority{
		"Emergency": PriorityEmergency, "CRITICAL": PriorityCritical, "info": PriorityInformational,
		"Informational": PriorityInformational, " notice ": PriorityNotice, "debug": PriorityDebug,
	} {
		got, err := ParsePriority(in)
		if err != nil || got != want {
			t.Errorf("ParsePriority(%q) = %v, %v", in, got, err)
		}
	}
	if Priority(42).String() != "unknown" || PriorityAlert.String() != "alert" {
		t.Error("String")
	}
}
