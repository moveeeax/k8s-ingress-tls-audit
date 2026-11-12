package audit

import (
	"errors"
	"net"
	"strings"
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

func tlsSecret(ns, name string, crt, key []byte) *Secret {
	return &Secret{Namespace: ns, Name: name, Type: "kubernetes.io/tls",
		Data: map[string][]byte{"tls.crt": crt, "tls.key": key}}
}

// validSecret returns a kubernetes.io/tls Secret holding a matching cert/key
// pair whose DNS SANs are hosts.
func validSecret(t *testing.T, ns, name string, hosts ...string) *Secret {
	t.Helper()
	crt, key := validPair(t, hosts...)
	return tlsSecret(ns, name, crt, key)
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
		"prod/a-tls": validSecret(t, "prod", "a-tls", "a.example.com"),
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
	expCrt, expKey := makeCertKeyPEM(t, certSpec{dnsNames: []string{"soon.example.com"},
		notBefore: ref.Add(-time.Hour), notAfter: ref.Add(10 * 24 * time.Hour)})
	oldCrt, oldKey := makeCertKeyPEM(t, certSpec{dnsNames: []string{"old.example.com"},
		notBefore: ref.Add(-100 * 24 * time.Hour), notAfter: ref.Add(-24 * time.Hour)})
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web",
		Hosts: []string{"soon.example.com", "old.example.com"},
		TLS: []IngressTLS{
			{Hosts: []string{"soon.example.com"}, SecretName: "soon-tls"},
			{Hosts: []string{"old.example.com"}, SecretName: "old-tls"},
		},
	}}, secrets: map[string]*Secret{
		"prod/soon-tls": tlsSecret("prod", "soon-tls", expCrt, expKey),
		"prod/old-tls":  tlsSecret("prod", "old-tls", oldCrt, oldKey),
	}}
	fs, _ := New(src, Options{ExpiryWindow: 30 * 24 * time.Hour, Now: fixedClock(ref)}).Run()
	if f := findByKind(fs, "expiring"); f == nil {
		t.Errorf("expected expiring finding, got %+v", fs)
	}
	if f := findByKind(fs, "expired"); f == nil {
		t.Errorf("expected expired finding, got %+v", fs)
	}
	if len(fs) != 2 {
		t.Errorf("expected exactly expiring+expired, got %+v", fs)
	}
}

func TestAudit_ValidCertNoFindings(t *testing.T) {
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web", Hosts: []string{"a.example.com"},
		TLS: []IngressTLS{{Hosts: []string{"a.example.com"}, SecretName: "a-tls"}},
	}}, secrets: map[string]*Secret{
		"prod/a-tls": validSecret(t, "prod", "a-tls", "a.example.com"),
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

func TestAudit_HostMismatch(t *testing.T) {
	ref := now(t)
	yearOut := ref.Add(365 * 24 * time.Hour)
	cases := []struct {
		name string
		spec certSpec
		host string
		want bool // true = host_mismatch expected
	}{
		{"exact SAN", certSpec{dnsNames: []string{"api.example.com"}}, "api.example.com", false},
		{"SAN match is case-insensitive", certSpec{dnsNames: []string{"API.example.com"}}, "api.example.com", false},
		{"copied from another host", certSpec{dnsNames: []string{"shop.example.com"}}, "api.example.com", true},
		{"wildcard covers one label", certSpec{dnsNames: []string{"*.example.com"}}, "api.example.com", false},
		{"wildcard does not cover apex", certSpec{dnsNames: []string{"*.example.com"}}, "example.com", true},
		{"wildcard one level too shallow", certSpec{dnsNames: []string{"*.example.com"}}, "api.eu.example.com", true},
		{"wildcard host needs wildcard SAN", certSpec{dnsNames: []string{"*.example.com"}}, "*.example.com", false},
		{"wildcard host not covered by a single name", certSpec{dnsNames: []string{"api.example.com"}}, "*.example.com", true},
		{"CN alone is ignored", certSpec{cn: "api.example.com"}, "api.example.com", true},
		{"IP host against IP SAN", certSpec{ips: []net.IP{net.ParseIP("10.0.0.1")}}, "10.0.0.1", false},
		{"IP host is not matched by a DNS SAN", certSpec{dnsNames: []string{"10.0.0.1"}}, "10.0.0.1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.spec.notBefore, tc.spec.notAfter = ref.Add(-time.Hour), yearOut
			crt, key := makeCertKeyPEM(t, tc.spec)
			src := &mapSource{ings: []Ingress{{
				Namespace: "prod", Name: "web", Hosts: []string{tc.host},
				TLS: []IngressTLS{{Hosts: []string{tc.host}, SecretName: "web-tls"}},
			}}, secrets: map[string]*Secret{"prod/web-tls": tlsSecret("prod", "web-tls", crt, key)}}
			fs, _ := New(src, Options{ExpiryWindow: 30 * 24 * time.Hour, Now: fixedClock(ref)}).Run()
			f := findByKind(fs, "host_mismatch")
			if tc.want {
				if f == nil {
					t.Fatalf("expected host_mismatch, got %+v", fs)
				}
				if f.Host != tc.host || f.Secret != "web-tls" || f.Severity != SeverityHostMismatch {
					t.Errorf("unexpected finding %+v", *f)
				}
			} else if len(fs) != 0 {
				t.Fatalf("expected no findings, got %+v", fs)
			}
		})
	}
}

func TestAudit_HostMismatchDetailListsSANs(t *testing.T) {
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web",
		Hosts: []string{"a.example.com", "c.example.com", "d.example.com"},
		TLS: []IngressTLS{{
			// c.example.com listed twice must yield one finding.
			Hosts:      []string{"a.example.com", "c.example.com", "c.example.com", "d.example.com"},
			SecretName: "web-tls",
		}},
	}}, secrets: map[string]*Secret{
		"prod/web-tls": validSecret(t, "prod", "web-tls", "a.example.com", "b.example.com"),
	}}
	fs, _ := New(src, Options{Now: fixedClock(now(t))}).Run()
	if len(fs) != 2 {
		t.Fatalf("expected 2 host_mismatch findings, got %+v", fs)
	}
	for i, host := range []string{"c.example.com", "d.example.com"} {
		if fs[i].Kind != "host_mismatch" || fs[i].Host != host {
			t.Errorf("finding %d = %+v, want host_mismatch for %s", i, fs[i], host)
		}
		if !strings.Contains(fs[i].Message, "SANs: a.example.com, b.example.com") {
			t.Errorf("message %q does not list the SANs", fs[i].Message)
		}
	}
}

func TestAudit_HostMismatchNoSANs(t *testing.T) {
	ref := now(t)
	crt, key := makeCertKeyPEM(t, certSpec{cn: "a.example.com", notBefore: ref.Add(-time.Hour), notAfter: ref.Add(24 * time.Hour * 365)})
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web", Hosts: []string{"a.example.com"},
		TLS: []IngressTLS{{Hosts: []string{"a.example.com"}, SecretName: "web-tls"}},
	}}, secrets: map[string]*Secret{"prod/web-tls": tlsSecret("prod", "web-tls", crt, key)}}
	fs, _ := New(src, Options{Now: fixedClock(ref)}).Run()
	f := findByKind(fs, "host_mismatch")
	if f == nil || !strings.Contains(f.Message, "no DNS or IP SANs") {
		t.Fatalf("expected host_mismatch noting missing SANs, got %+v", fs)
	}
}

func TestAudit_ExpiredAndHostMismatch(t *testing.T) {
	ref := now(t)
	crt, key := makeCertKeyPEM(t, certSpec{dnsNames: []string{"old.example.com"},
		notBefore: ref.Add(-100 * 24 * time.Hour), notAfter: ref.Add(-24 * time.Hour)})
	src := &mapSource{ings: []Ingress{{
		Namespace: "prod", Name: "web", Hosts: []string{"new.example.com"},
		TLS: []IngressTLS{{Hosts: []string{"new.example.com"}, SecretName: "web-tls"}},
	}}, secrets: map[string]*Secret{"prod/web-tls": tlsSecret("prod", "web-tls", crt, key)}}
	fs, _ := New(src, Options{Now: fixedClock(ref)}).Run()
	if findByKind(fs, "expired") == nil || findByKind(fs, "host_mismatch") == nil {
		t.Fatalf("expected both expired and host_mismatch, got %+v", fs)
	}
}

func TestAudit_KeyPairMismatch(t *testing.T) {
	crt, _ := validPair(t, "a.example.com")
	_, otherKey := validPair(t, "a.example.com")
	cases := map[string][]byte{
		"key from another cert": otherKey,
		"key is not PEM":        []byte("key"),
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			src := &mapSource{ings: []Ingress{{
				Namespace: "prod", Name: "web", Hosts: []string{"b.example.com"},
				TLS: []IngressTLS{{Hosts: []string{"b.example.com"}, SecretName: "web-tls"}},
			}}, secrets: map[string]*Secret{"prod/web-tls": tlsSecret("prod", "web-tls", crt, key)}}
			fs, _ := New(src, Options{Now: fixedClock(now(t))}).Run()
			// The broken pair short-circuits: no host_mismatch for b.example.com.
			if len(fs) != 1 || fs[0].Kind != "bad_secret" || !strings.Contains(fs[0].Message, "key pair") {
				t.Fatalf("expected a single key-pair bad_secret, got %+v", fs)
			}
		})
	}
}

func TestSeverityOrder_HostMismatch(t *testing.T) {
	if !(SeverityMissingTLS < SeverityHostMismatch && SeverityHostMismatch < SeverityBadSecret) {
		t.Fatal("host_mismatch must rank between missing_tls and bad_secret")
	}
	if got := SeverityHostMismatch.String(); got != "host_mismatch" {
		t.Errorf("String() = %q, want host_mismatch", got)
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
	for _, name := range []string{"expiring", "missing_tls", "host_mismatch", "bad_secret", "missing_secret", "expired"} {
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

// validPair returns a certificate valid for a year from now(t), with hosts as
// its DNS SANs, plus the matching private key.
func validPair(t *testing.T, hosts ...string) (crt, key []byte) {
	t.Helper()
	ref := now(t)
	return makeCertKeyPEM(t, certSpec{dnsNames: hosts, notBefore: ref.Add(-time.Hour), notAfter: ref.Add(365 * 24 * time.Hour)})
}
