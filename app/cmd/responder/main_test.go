package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writePKI writes a CA, a server certificate and its key to dir.
func writePKI(t *testing.T, dir string) (cert, key, ca string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "responder"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	keyDER, _ := x509.MarshalECPrivateKey(srvKey)

	write := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return write("tls.crt", "CERTIFICATE", srvDER), write("tls.key", "EC PRIVATE KEY", keyDER), write("ca.crt", "CERTIFICATE", caDER)
}

func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	cert, key, ca := writePKI(t, dir)

	cfg, err := mutualTLS(cert, key, ca)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth.String() != "RequireAndVerifyClientCert" || cfg.MinVersion == 0 {
		t.Errorf("client certificates must be required: %v", cfg.ClientAuth)
	}

	if _, err := mutualTLS(filepath.Join(dir, "nope"), key, ca); err == nil {
		t.Error("missing certificate must fail")
	}
	if _, err := mutualTLS(cert, key, filepath.Join(dir, "nope")); err == nil {
		t.Error("missing CA must fail")
	}
	empty := filepath.Join(dir, "empty.crt")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := mutualTLS(cert, key, empty); err == nil {
		t.Error("CA bundle without certificates must fail")
	}
}

func TestLoadConfig(t *testing.T) {
	t.Setenv("RESPONDER_HOLD_SECONDS", "30")
	t.Setenv("RESPONDER_ALLOWED_CLIENTS", "falco,falco-canary")
	cfg, err := loadConfig(":9999")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.holdOverrideIsSet || cfg.holdSeconds != 30 || cfg.opsAddr != ":9999" || len(cfg.allowedClients) != 2 {
		t.Errorf("config = %+v", cfg)
	}
	t.Setenv("RESPONDER_MODE", "notify")
	if cfg, err := loadConfig(":9999"); err != nil || !cfg.notifyOnly {
		t.Errorf("RESPONDER_MODE=notify: %+v, %v", cfg, err)
	}
	t.Setenv("RESPONDER_MODE", "chaos")
	if _, err := loadConfig(":9999"); err == nil {
		t.Error("unknown RESPONDER_MODE must be rejected")
	}
	t.Setenv("RESPONDER_MODE", "")
	for _, bad := range []string{"-1", "soon"} {
		t.Setenv("RESPONDER_HOLD_SECONDS", bad)
		if _, err := loadConfig(":9999"); err == nil {
			t.Errorf("hold %q must be rejected", bad)
		}
	}
}

func TestRunFailsClosed(t *testing.T) {
	dir := t.TempDir()
	cert, key, ca := writePKI(t, dir)
	playbook := filepath.Join(dir, "playbook.json")
	pb := `{"namespaces":["app"],"evidenceNamespace":"e","quarantineHoldSeconds":10,
		"rules":[{"name":"r","match":{"rules":["X"]},"actions":["quarantine"]}]}`
	if err := os.WriteFile(playbook, []byte(pb), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := config{addr: "127.0.0.1:0", opsAddr: "127.0.0.1:0", playbook: playbook, cert: cert, key: key, ca: ca}

	missing := base
	missing.playbook = filepath.Join(dir, "missing.json")
	if err := run(logger, missing); err == nil || !strings.Contains(err.Error(), "playbook") {
		t.Errorf("missing playbook: %v", err)
	}

	noTLS := base
	noTLS.cert = filepath.Join(dir, "missing.crt")
	if err := run(logger, noTLS); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("missing certificate: %v", err)
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	outside := base
	outside.holdSeconds, outside.holdOverrideIsSet = 5, true
	if err := run(logger, outside); err == nil || !strings.Contains(err.Error(), "not running in a cluster") {
		t.Errorf("outside a cluster: %v", err)
	}
}

func TestHealthcheckFailsWhenDown(t *testing.T) {
	if code := healthcheck("127.0.0.1:1"); code != 1 {
		t.Errorf("healthcheck = %d, want 1", code)
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("AEGIS_TEST_ENV", "set")
	if envOr("AEGIS_TEST_ENV", "x") != "set" || envOr("AEGIS_TEST_UNSET", "x") != "x" {
		t.Error("envOr")
	}
}
