package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ahmedelgmal310/aegis-devsecops/app/internal/ledger"
)

const testToken = "test-token-not-a-secret"

func newTestServer(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	if cfg.Token == "" {
		cfg.Token = testToken
	}
	cfg.Version, cfg.Commit = "1.2.3", "abc123"
	return New(cfg).Handler()
}

func do(h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func authed(extra map[string]string) map[string]string {
	h := map[string]string{"Authorization": "Bearer " + testToken, "Content-Type": "application/json"}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

func TestPublicEndpoints(t *testing.T) {
	h := newTestServer(t, Config{})
	for path, want := range map[string]string{
		"/healthz": `"status":"ok"`,
		"/readyz":  `"status":"ready"`,
		"/version": `"version":"1.2.3"`,
		"/":        "Ledger API",
		"/metrics": "ledger_transactions",
	} {
		rec := do(h, http.MethodGet, path, "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("GET %s body missing %q", path, want)
		}
	}
}

func TestStaticAssetsAreCacheable(t *testing.T) {
	h := newTestServer(t, Config{})
	rec := do(h, http.MethodGet, "/static/app.css", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newTestServer(t, Config{})
	rec := do(h, http.MethodGet, "/healthz", "", nil)
	for _, name := range []string{
		"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
		"Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy",
		"Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy",
		"Strict-Transport-Security", "X-Request-ID",
	} {
		if rec.Header().Get(name) == "" {
			t.Errorf("missing header %s", name)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
}

func TestRequestIDPropagation(t *testing.T) {
	h := newTestServer(t, Config{})
	rec := do(h, http.MethodGet, "/healthz", "", map[string]string{"X-Request-ID": "abc-123"})
	if got := rec.Header().Get("X-Request-ID"); got != "abc-123" {
		t.Fatalf("X-Request-ID = %q", got)
	}
	rec = do(h, http.MethodGet, "/healthz", "", map[string]string{"X-Request-ID": "bad\r\nvalue<script>"})
	if got := rec.Header().Get("X-Request-ID"); got == "" || strings.ContainsAny(got, "<\r\n") {
		t.Fatalf("unsafe request id echoed: %q", got)
	}
}

func TestAPIRequiresToken(t *testing.T) {
	h := newTestServer(t, Config{})
	for _, hdr := range []map[string]string{
		nil,
		{"Authorization": "Bearer wrong"},
		{"Authorization": "Basic " + testToken},
		{"Authorization": testToken},
	} {
		rec := do(h, http.MethodGet, "/api/v1/transactions", "", hdr)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("headers %v: status = %d", hdr, rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatal("missing WWW-Authenticate header")
		}
	}
}

func TestAPIDisabledWithoutToken(t *testing.T) {
	h := New(Config{}).Handler()
	rec := do(h, http.MethodGet, "/api/v1/transactions", "", map[string]string{"Authorization": "Bearer "})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestCreateGetList(t *testing.T) {
	h := newTestServer(t, Config{})

	rec := do(h, http.MethodPost, "/api/v1/transactions", `{"amount":1500,"currency":"EGP","description":"Coffee beans"}`, authed(nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body)
	}
	var created ledger.Transaction
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if rec.Header().Get("Location") != "/api/v1/transactions/"+created.ID {
		t.Fatalf("Location = %q", rec.Header().Get("Location"))
	}

	rec = do(h, http.MethodGet, "/api/v1/transactions/"+created.ID, "", authed(nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Coffee beans") {
		t.Fatalf("get status = %d body=%s", rec.Code, rec.Body)
	}

	rec = do(h, http.MethodGet, "/api/v1/transactions?limit=10", "", authed(nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"count":1`) {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body)
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	h := newTestServer(t, Config{})
	tests := []struct {
		name    string
		body    string
		headers map[string]string
		want    int
	}{
		{"wrong content type", `{}`, authed(map[string]string{"Content-Type": "text/plain"}), http.StatusUnsupportedMediaType},
		{"malformed json", `{"amount":`, authed(nil), http.StatusBadRequest},
		{"unknown field", `{"amount":1,"currency":"EGP","description":"x","admin":true}`, authed(nil), http.StatusBadRequest},
		{"trailing data", `{"amount":1,"currency":"EGP","description":"x"}{}`, authed(nil), http.StatusBadRequest},
		{"validation error", `{"amount":-1,"currency":"EGP","description":"x"}`, authed(nil), http.StatusUnprocessableEntity},
		{"body too large", `{"amount":1,"currency":"EGP","description":"` + strings.Repeat("a", 5000) + `"}`, authed(nil), http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(h, http.MethodPost, "/api/v1/transactions", tc.body, tc.headers)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.want, rec.Body)
			}
		})
	}
}

func TestCreateWhenFull(t *testing.T) {
	h := newTestServer(t, Config{Capacity: 1})
	body := `{"amount":1,"currency":"USD","description":"one"}`
	if rec := do(h, http.MethodPost, "/api/v1/transactions", body, authed(nil)); rec.Code != http.StatusCreated {
		t.Fatalf("first create = %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/v1/transactions", body, authed(nil)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("second create = %d", rec.Code)
	}
}

func TestListLimitValidation(t *testing.T) {
	h := newTestServer(t, Config{})
	for _, q := range []string{"0", "-1", "abc", "501"} {
		rec := do(h, http.MethodGet, "/api/v1/transactions?limit="+q, "", authed(nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("limit=%s: status = %d", q, rec.Code)
		}
	}
}

func TestGetUnknownTransaction(t *testing.T) {
	h := newTestServer(t, Config{})
	for _, id := range []string{"txn_" + strings.Repeat("a", 32), "not-an-id", "..%2f..%2fetc"} {
		rec := do(h, http.MethodGet, "/api/v1/transactions/"+id, "", authed(nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("id %q: status = %d", id, rec.Code)
		}
	}
}

func TestRateLimit(t *testing.T) {
	h := newTestServer(t, Config{RequestsPerSecond: 1, Burst: 2})
	codes := map[int]int{}
	for i := 0; i < 5; i++ {
		codes[do(h, http.MethodGet, "/api/v1/transactions", "", authed(nil)).Code]++
	}
	if codes[http.StatusTooManyRequests] == 0 {
		t.Fatalf("rate limiter never triggered: %v", codes)
	}
	// Probes are not rate limited.
	for i := 0; i < 5; i++ {
		if rec := do(h, http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK {
			t.Fatalf("healthz throttled: %d", rec.Code)
		}
	}
}

func TestReadinessToggle(t *testing.T) {
	s := New(Config{Token: testToken})
	s.SetReady(false)
	rec := do(s.Handler(), http.MethodGet, "/readyz", "", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestMethodNotAllowedAndNotFound(t *testing.T) {
	h := newTestServer(t, Config{})
	if rec := do(h, http.MethodDelete, "/api/v1/transactions", "", authed(nil)); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE status = %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/admin", "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d", rec.Code)
	}
}

func TestPanicRecovery(t *testing.T) {
	h := chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }), recoverPanics(New(Config{}).cfg.Logger))
	rec := do(h, http.MethodGet, "/", "", nil)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "boom") {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
}

func TestClientLimiterBoundsMemory(t *testing.T) {
	l := newClientLimiter(1, 1)
	for i := 0; i < maxTrackedClients+10; i++ {
		l.allow(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	if len(l.clients) > maxTrackedClients {
		t.Fatalf("tracked %d clients", len(l.clients))
	}
}

func TestMethodLabelIsBounded(t *testing.T) {
	for in, want := range map[string]string{"GET": "GET", "DELETE": "DELETE", "BREW": "OTHER", "G\nET": "OTHER"} {
		if got := methodLabel(in); got != want {
			t.Fatalf("methodLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRequestIDFromStripsLineBreaks(t *testing.T) {
	ctx := context.WithValue(context.Background(), requestIDKey{}, "abc\r\ndef")
	if got := requestIDFrom(ctx); got != "abcdef" {
		t.Fatalf("requestIDFrom = %q", got)
	}
	if got := requestIDFrom(context.Background()); got != "" {
		t.Fatalf("requestIDFrom(empty) = %q", got)
	}
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.10:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := clientIP(req); got != "192.0.2.10" {
		t.Fatalf("clientIP = %q", got)
	}
	req.RemoteAddr = "garbage"
	if got := clientIP(req); got != "garbage" {
		t.Fatalf("clientIP = %q", got)
	}
}
