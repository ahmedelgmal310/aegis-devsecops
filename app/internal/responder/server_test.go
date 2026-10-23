package responder

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

func (ca *testCA) issue(t *testing.T, cn string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startIntake(t *testing.T, in *Intake, ca *testCA) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(in.Handler())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.issue(t, "responder", x509.ExtKeyUsageServerAuth)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func clientWith(ca *testCA, certs ...tls.Certificate) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: ca.pool, Certificates: certs, MinVersion: tls.VersionTLS12,
		}},
	}
}

const alert = `{"rule":"Aegis Shell Spawned in Workload","priority":"Warning","time":"2026-10-23T12:00:00Z",
	"output_fields":{"k8s.ns.name":"aegis-drill","k8s.pod.name":"web-1"}}`

func TestIntakeRequiresFalcoClientCertificate(t *testing.T) {
	ca := newTestCA(t)
	kube := newFakeCluster()
	kube.pods["aegis-drill/web-1"] = testPod("aegis-drill", "web-1")
	r, m := newTestResponder(t, kube)
	in := NewIntake(r, m, slog.New(slog.NewTextHandler(io.Discard, nil)), []string{"falco"}, 4)
	srv := startIntake(t, in, ca)
	url := srv.URL + "/v1/falco"

	falco := clientWith(ca, ca.issue(t, "falco", x509.ExtKeyUsageClientAuth))
	resp, err := falco.Post(url, "application/json", strings.NewReader(alert))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("falco alert status = %d, want 202", resp.StatusCode)
	}

	// Same CA, wrong identity.
	intruder := clientWith(ca, ca.issue(t, "intruder", x509.ExtKeyUsageClientAuth))
	resp, err = intruder.Post(url, "application/json", strings.NewReader(alert))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("intruder status = %d, want 403", resp.StatusCode)
	}

	// No client certificate at all: the TLS handshake itself fails.
	if resp, err := clientWith(ca).Post(url, "application/json", strings.NewReader(alert)); err == nil {
		resp.Body.Close()
		t.Error("request without a client certificate must fail")
	}

	resp, err = falco.Post(url, "application/json", strings.NewReader(`{"rule":`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid alert status = %d, want 400", resp.StatusCode)
	}

	resp, err = falco.Post(url, "application/json", bytes.NewReader(make([]byte, maxAlertBytes+1)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized alert status = %d, want 413", resp.StatusCode)
	}

	// The queued alert is processed by the worker.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { in.Work(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for kube.eventCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if len(kube.patches) != 1 {
		t.Errorf("queued alert was not handled: patches=%d", len(kube.patches))
	}
}

func TestIntakeSheddsLoad(t *testing.T) {
	ca := newTestCA(t)
	r, m := newTestResponder(t, newFakeCluster())
	in := NewIntake(r, m, slog.New(slog.NewTextHandler(io.Discard, nil)), []string{"falco"}, 1)
	srv := startIntake(t, in, ca)
	falco := clientWith(ca, ca.issue(t, "falco", x509.ExtKeyUsageClientAuth))

	codes := map[int]int{}
	for range 3 {
		resp, err := falco.Post(srv.URL+"/v1/falco", "application/json", strings.NewReader(alert))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		codes[resp.StatusCode]++
	}
	if codes[http.StatusAccepted] != 1 || codes[http.StatusServiceUnavailable] != 2 {
		t.Errorf("status codes = %v, want one 202 and two 503 with a queue of 1", codes)
	}

	in.limiter.SetBurst(0)
	resp, err := falco.Post(srv.URL+"/v1/falco", "application/json", strings.NewReader(alert))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("rate limited status = %d, want 429", resp.StatusCode)
	}
}

func TestOpsHandler(t *testing.T) {
	ready := false
	h := OpsHandler(NewMetrics(), func() bool { return ready })
	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, rec.Body.String()
	}
	if code, _ := get("/healthz"); code != http.StatusOK {
		t.Errorf("healthz = %d", code)
	}
	if code, _ := get("/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("readyz before ready = %d", code)
	}
	ready = true
	if code, _ := get("/readyz"); code != http.StatusOK {
		t.Errorf("readyz = %d", code)
	}
	if code, body := get("/metrics"); code != http.StatusOK || !strings.Contains(body, "aegis_responder_quarantined_pods") {
		t.Errorf("metrics = %d", code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/falco", strings.NewReader(alert)))
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("ops port must not accept alerts, got %d", rec.Code)
	}
}
