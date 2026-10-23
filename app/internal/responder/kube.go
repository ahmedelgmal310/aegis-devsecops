package responder

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Cluster is the small slice of the Kubernetes API the responder needs. It
// is an interface so the response logic can be tested without a cluster.
type Cluster interface {
	GetPod(ctx context.Context, namespace, name string) (*Pod, error)
	ListPods(ctx context.Context, namespace, labelSelector string) ([]Pod, error)
	PatchPod(ctx context.Context, namespace, name string, mergePatch any) error
	DeletePod(ctx context.Context, namespace, name, uid string) error
	PodLogs(ctx context.Context, namespace, name, container string, tailLines int) (string, error)
	ReplicaSetSelector(ctx context.Context, namespace, name string) (map[string]string, error)
	CreateConfigMap(ctx context.Context, cm *ConfigMap) error
	CreateEvent(ctx context.Context, ev *KubeEvent) error
}

// ErrNotFound is returned when the object does not exist (any more).
var ErrNotFound = errors.New("not found")

// ObjectMeta is the part of Kubernetes object metadata the responder uses.
type ObjectMeta struct {
	Name            string            `json:"name,omitempty"`
	GenerateName    string            `json:"generateName,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	UID             string            `json:"uid,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
	OwnerReferences []OwnerReference  `json:"ownerReferences,omitempty"`
}

// OwnerReference points at the controller that manages a pod.
type OwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller *bool  `json:"controller,omitempty"`
}

// Pod is a trimmed core/v1 Pod. Raw keeps the full object for evidence.
type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		NodeName   string `json:"nodeName"`
		Containers []struct {
			Name  string `json:"name"`
			Image string `json:"image"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		ContainerStatuses []struct {
			Name        string `json:"name"`
			ContainerID string `json:"containerID"`
		} `json:"containerStatuses"`
	} `json:"status"`

	Raw json.RawMessage `json:"-"`
}

// Controller returns the pod's controlling owner, if any.
func (p *Pod) Controller() *OwnerReference {
	for i, o := range p.Metadata.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			return &p.Metadata.OwnerReferences[i]
		}
	}
	return nil
}

// RunsContainer reports whether one of the pod's containers has the given
// ID. Falco reports the 12-character short ID; Kubernetes the full one with
// a runtime prefix ("containerd://<64 hex>").
func (p *Pod) RunsContainer(id string) bool {
	if len(id) < 12 {
		return false
	}
	for _, cs := range p.Status.ContainerStatuses {
		_, full, found := strings.Cut(cs.ContainerID, "://")
		if !found {
			full = cs.ContainerID
		}
		if strings.HasPrefix(full, id) {
			return true
		}
	}
	return false
}

// ConfigMap is a core/v1 ConfigMap.
type ConfigMap struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   ObjectMeta        `json:"metadata"`
	Immutable  bool              `json:"immutable"`
	Data       map[string]string `json:"data"`
}

// KubeEvent is a core/v1 Event attached to a pod.
type KubeEvent struct {
	APIVersion     string          `json:"apiVersion"`
	Kind           string          `json:"kind"`
	Metadata       ObjectMeta      `json:"metadata"`
	InvolvedObject ObjectReference `json:"involvedObject"`
	Reason         string          `json:"reason"`
	Message        string          `json:"message"`
	Type           string          `json:"type"`
	Source         EventSource     `json:"source"`
	FirstTimestamp time.Time       `json:"firstTimestamp"`
	LastTimestamp  time.Time       `json:"lastTimestamp"`
	Count          int             `json:"count"`
}

// EventSource names the component that reported an Event.
type EventSource struct {
	Component string `json:"component"`
}

// ObjectReference identifies the object an Event is about.
type ObjectReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

// APIClient talks to the Kubernetes API server over HTTPS with the pod's
// service account. It deliberately avoids client-go: the responder needs a
// handful of calls, and a small dependency tree keeps the image small and
// its SBOM short.
type APIClient struct {
	base      string
	tokenFile string
	http      *http.Client
}

const (
	saDir           = "/var/run/secrets/kubernetes.io/serviceaccount"
	maxResponseSize = 4 << 20
)

// InClusterClient builds an APIClient from the pod's service account.
func InClusterClient() (*APIClient, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not running in a cluster (KUBERNETES_SERVICE_HOST is not set)")
	}
	caPEM, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("cluster CA bundle has no certificates")
	}
	return NewAPIClient("https://"+net.JoinHostPort(host, port), saDir+"/token", pool), nil
}

// NewAPIClient returns a client for the given API server.
func NewAPIClient(base, tokenFile string, roots *x509.CertPool) *APIClient {
	return &APIClient{
		base:      strings.TrimSuffix(base, "/"),
		tokenFile: tokenFile,
		http: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// do sends one request. The token is re-read every time because projected
// service account tokens are rotated by the kubelet.
func (c *APIClient) do(ctx context.Context, method, path, contentType string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	token, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return fmt.Errorf("read service account token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%s %s: %w", method, path, ErrNotFound)
	case resp.StatusCode >= 300:
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, apiMessage(data))
	}
	switch v := out.(type) {
	case nil:
		return nil
	case *[]byte:
		*v = data
		return nil
	default:
		return json.Unmarshal(data, out)
	}
}

func apiMessage(body []byte) string {
	var status struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &status) == nil && status.Message != "" {
		return status.Message
	}
	if len(body) > 200 {
		body = body[:200]
	}
	return string(body)
}

func podPath(namespace, name string) string {
	return "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(name)
}

// GetPod fetches a pod and keeps its raw JSON.
func (c *APIClient) GetPod(ctx context.Context, namespace, name string) (*Pod, error) {
	var raw []byte
	if err := c.do(ctx, http.MethodGet, podPath(namespace, name), "", nil, &raw); err != nil {
		return nil, err
	}
	var pod Pod
	if err := json.Unmarshal(raw, &pod); err != nil {
		return nil, err
	}
	pod.Raw = raw
	return &pod, nil
}

// ListPods lists the pods matching a label selector.
func (c *APIClient) ListPods(ctx context.Context, namespace, labelSelector string) ([]Pod, error) {
	var list struct {
		Items []Pod `json:"items"`
	}
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods?labelSelector=" + url.QueryEscape(labelSelector)
	if err := c.do(ctx, http.MethodGet, path, "", nil, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// PatchPod applies a JSON merge patch to a pod.
func (c *APIClient) PatchPod(ctx context.Context, namespace, name string, mergePatch any) error {
	return c.do(ctx, http.MethodPatch, podPath(namespace, name), "application/merge-patch+json", mergePatch, nil)
}

// DeletePod deletes a pod immediately, but only if it is still the same pod
// (UID precondition), never a newer pod that reused the name.
func (c *APIClient) DeletePod(ctx context.Context, namespace, name, uid string) error {
	opts := map[string]any{
		"apiVersion":         "v1",
		"kind":               "DeleteOptions",
		"gracePeriodSeconds": 0,
		"preconditions":      map[string]string{"uid": uid},
	}
	return c.do(ctx, http.MethodDelete, podPath(namespace, name), "application/json", opts, nil)
}

// PodLogs returns the last lines of a container's log.
func (c *APIClient) PodLogs(ctx context.Context, namespace, name, container string, tailLines int) (string, error) {
	var raw []byte
	path := fmt.Sprintf("%s/log?container=%s&tailLines=%d&timestamps=true",
		podPath(namespace, name), url.QueryEscape(container), tailLines)
	if err := c.do(ctx, http.MethodGet, path, "", nil, &raw); err != nil {
		return "", err
	}
	return string(raw), nil
}

// ReplicaSetSelector returns the matchLabels of a ReplicaSet.
func (c *APIClient) ReplicaSetSelector(ctx context.Context, namespace, name string) (map[string]string, error) {
	var rs struct {
		Spec struct {
			Selector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"selector"`
		} `json:"spec"`
	}
	path := "/apis/apps/v1/namespaces/" + url.PathEscape(namespace) + "/replicasets/" + url.PathEscape(name)
	if err := c.do(ctx, http.MethodGet, path, "", nil, &rs); err != nil {
		return nil, err
	}
	return rs.Spec.Selector.MatchLabels, nil
}

// CreateConfigMap creates a ConfigMap.
func (c *APIClient) CreateConfigMap(ctx context.Context, cm *ConfigMap) error {
	cm.APIVersion, cm.Kind = "v1", "ConfigMap"
	path := "/api/v1/namespaces/" + url.PathEscape(cm.Metadata.Namespace) + "/configmaps"
	return c.do(ctx, http.MethodPost, path, "application/json", cm, nil)
}

// CreateEvent records a Kubernetes Event.
func (c *APIClient) CreateEvent(ctx context.Context, ev *KubeEvent) error {
	ev.APIVersion, ev.Kind = "v1", "Event"
	path := "/api/v1/namespaces/" + url.PathEscape(ev.Metadata.Namespace) + "/events"
	return c.do(ctx, http.MethodPost, path, "application/json", ev, nil)
}
