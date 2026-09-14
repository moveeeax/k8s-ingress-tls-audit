package audit

import (
	"errors"
	"testing"
	"time"
)

// mapSource is an in-memory Source for auditor tests.
type mapSource struct {
	ings    []Ingress
	secrets map[string]*Secret
	secErr  error
}

func (m *mapSource) Ingresses() ([]Ingress, error) { return m.ings, nil }
func (m *mapSource) Secret(ns, name string) (*Secret, error) {
	if m.secErr != nil {
		return nil, m.secErr
	}
	return m.secrets[ns+"/"+name], nil
}

func tlsSecret(ns, name string, crt []byte) *Secret {
	return &Secret{Namespace: ns, Name: name, Type: "kubernetes.io/tls",
		Data: map[string][]byte{"tls.crt": crt, "tls.key": []byte("key")}}
}

func findByKind(fs []Finding, kind string) *Finding {
	for i := range fs {
		if fs[i].Kind == kind {
			return &fs[i]
		}
	}
	return nil
}

func TestAudit_MissingTLS(t *testing.T) {
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web",
		Hosts: []string{"a.example.com", "b.example.com"},
		TLS:   []IngressTLS{{Hosts: []string{"a.example.com"}, SecretName: "a-tls"}},
	}}, secrets: map[string]*Secret{
		"prod/a-tls": tlsSecret("prod", "a-tls", validCert(t)),
	}}
	fs, err := New(src, Options{Now: fixedClock(now(t))}).Run()
	if err != nil {
		t.Fatal(err)
	}
	f := findByKind(fs, "missing_tls")
	if f == nil {
		t.Fatalf("expected missing_tls finding, got %+v", fs)
	}
	if f.Host != "b.example.com" {
		t.Errorf("missing_tls host = %q, want b.example.com", f.Host)
	}
}

func TestAudit_MissingSecret(t *testing.T) {
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web", Hosts: []string{"a.example.com"},
		TLS: []IngressTLS{{Hosts: []string{"a.example.com"}, SecretName: "gone"}},
	}}, secrets: map[string]*Secret{}}
	fs, _ := New(src, Options{Now: fixedClock(now(t))}).Run()
	if f := findByKind(fs, "missing_secret"); f == nil || f.Secret != "gone" {
		t.Fatalf("expected missing_secret for 'gone', got %+v", fs)
	}
}

func TestAudit_BadSecretType(t *testing.T) {
	sec := &Secret{Namespace: "prod", Name: "opaque", Type: "Opaque",
		Data: map[string][]byte{"tls.crt": validCert(t), "tls.key": []byte("k")}}
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web", Hosts: []string{"a.example.com"},
		TLS: []IngressTLS{{Hosts: []string{"a.example.com"}, SecretName: "opaque"}},
	}}, secrets: map[string]*Secret{"prod/opaque": sec}}
	fs, _ := New(src, Options{Now: fixedClock(now(t))}).Run()
	if f := findByKind(fs, "bad_secret"); f == nil {
		t.Fatalf("expected bad_secret, got %+v", fs)
	}
}

func TestAudit_BadSecretMissingKeys(t *testing.T) {
	sec := &Secret{Namespace: "prod", Name: "half", Type: "kubernetes.io/tls",
		Data: map[string][]byte{"tls.crt": validCert(t)}} // no tls.key
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web", Hosts: []string{"a.example.com"},
		TLS: []IngressTLS{{Hosts: []string{"a.example.com"}, SecretName: "half"}},
	}}, secrets: map[string]*Secret{"prod/half": sec}}
	fs, _ := New(src, Options{Now: fixedClock(now(t))}).Run()
	if f := findByKind(fs, "bad_secret"); f == nil {
		t.Fatalf("expected bad_secret for missing tls.key, got %+v", fs)
	}
}

func TestAudit_EmptySecretName(t *testing.T) {
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web", Hosts: []string{"a.example.com"},
		TLS: []IngressTLS{{Hosts: []string{"a.example.com"}, SecretName: ""}},
	}}}
	fs, _ := New(src, Options{Now: fixedClock(now(t))}).Run()
	if f := findByKind(fs, "bad_secret"); f == nil {
		t.Fatalf("expected bad_secret for empty secretName, got %+v", fs)
	}
}

func TestAudit_ExpiringAndExpired(t *testing.T) {
	ref := now(t)
	expiring := makeCertPEM(t, "soon", ref.Add(-time.Hour), ref.Add(10*24*time.Hour))
	expired := makeCertPEM(t, "old", ref.Add(-100*24*time.Hour), ref.Add(-24*time.Hour))
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web",
		Hosts: []string{"soon.example.com", "old.example.com"},
		TLS: []IngressTLS{
			{Hosts: []string{"soon.example.com"}, SecretName: "soon-tls"},
			{Hosts: []string{"old.example.com"}, SecretName: "old-tls"},
		},
	}}, secrets: map[string]*Secret{
		"prod/soon-tls": tlsSecret("prod", "soon-tls", expiring),
		"prod/old-tls":  tlsSecret("prod", "old-tls", expired),
	}}
	fs, _ := New(src, Options{ExpiryWindow: 30 * 24 * time.Hour, Now: fixedClock(ref)}).Run()
	if f := findByKind(fs, "expiring"); f == nil {
		t.Errorf("expected expiring finding, got %+v", fs)
	}
	if f := findByKind(fs, "expired"); f == nil {
		t.Errorf("expected expired finding, got %+v", fs)
	}
}

func TestAudit_ValidCertNoFindings(t *testing.T) {
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web", Hosts: []string{"a.example.com"},
		TLS: []IngressTLS{{Hosts: []string{"a.example.com"}, SecretName: "a-tls"}},
	}}, secrets: map[string]*Secret{
		"prod/a-tls": tlsSecret("prod", "a-tls", validCert(t)),
	}}
	fs, _ := New(src, Options{ExpiryWindow: 30 * 24 * time.Hour, Now: fixedClock(now(t))}).Run()
	if len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
}

func TestAudit_SecretReadError(t *testing.T) {
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web", Hosts: []string{"a.example.com"},
		TLS: []IngressTLS{{Hosts: []string{"a.example.com"}, SecretName: "x"}},
	}}, secErr: errors.New("boom")}
	fs, _ := New(src, Options{Now: fixedClock(now(t))}).Run()
	if f := findByKind(fs, "bad_secret"); f == nil {
		t.Fatalf("expected bad_secret on read error, got %+v", fs)
	}
}

func TestShouldFail(t *testing.T) {
	fs := []Finding{
		{Severity: SeverityExpiring, Kind: "expiring"},
		{Severity: SeverityMissingTLS, Kind: "missing_tls"},
	}
	if !ShouldFail(fs, SeverityExpiring) {
		t.Error("should fail at expiring threshold")
	}
	if !ShouldFail(fs, SeverityMissingTLS) {
		t.Error("should fail at missing_tls threshold")
	}
	if ShouldFail(fs, SeverityExpired) {
		t.Error("should NOT fail at expired threshold (max is missing_tls)")
	}
	if ShouldFail(fs, SeverityOK) {
		t.Error("SeverityOK threshold must never fail")
	}
	if ShouldFail(nil, SeverityExpiring) {
		t.Error("no findings must not fail")
	}
}

func TestParseSeverity(t *testing.T) {
	for _, name := range []string{"expiring", "missing_tls", "bad_secret", "missing_secret", "expired"} {
		if _, err := ParseSeverity(name); err != nil {
			t.Errorf("ParseSeverity(%q) error: %v", name, err)
		}
	}
	if _, err := ParseSeverity("ok"); err == nil {
		t.Error("ParseSeverity(ok) should error")
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Error("ParseSeverity(bogus) should error")
	}
}

// --- helpers ---

func now(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
}

func validCert(t *testing.T) []byte {
	t.Helper()
	ref := now(t)
	return makeCertPEM(t, "valid.example.com", ref.Add(-time.Hour), ref.Add(365*24*time.Hour))
}
