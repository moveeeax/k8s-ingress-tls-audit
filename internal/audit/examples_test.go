package audit

import (
	"testing"
	"time"
)

// TestExamples pins the findings for examples/manifests at the reference time
// the README uses (--now 2026-09-15T00:00:00Z --days 30), so the example keeps
// showing every finding kind no matter when the suite runs.
func TestExamples(t *testing.T) {
	ms, err := LoadDir("../../examples/manifests")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	ref := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	fs, err := New(ms, Options{ExpiryWindow: 30 * 24 * time.Hour, Now: fixedClock(ref)}).Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	type row struct{ kind, ingress, host, secret string }
	want := []row{
		{"bad_secret", "admin", "", "admin-tls"},
		{"missing_secret", "api", "", "api-tls"},
		{"missing_tls", "api", "legacy.example.com", ""},
		{"expiring", "promo", "", "soon-tls"},
		{"host_mismatch", "storefront", "www.example.com", "shop-tls"},
	}
	if len(fs) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(fs), len(want), fs)
	}
	for i, w := range want {
		f := fs[i]
		got := row{f.Kind, f.Ingress, f.Host, f.Secret}
		if got != w || f.Namespace != "prod" {
			t.Errorf("finding %d = %+v (namespace %q), want %+v in prod", i, got, f.Namespace, w)
		}
	}
}
