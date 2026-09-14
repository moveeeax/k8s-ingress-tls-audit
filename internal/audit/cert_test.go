package audit

import (
	"testing"
	"time"
)

func TestLeafCert(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pem := makeCertPEM(t, "example.com", now, now.Add(90*24*time.Hour))

	cert, err := leafCert(pem)
	if err != nil {
		t.Fatalf("leafCert: %v", err)
	}
	if cert.Subject.CommonName != "example.com" {
		t.Errorf("CN = %q, want example.com", cert.Subject.CommonName)
	}

	if _, err := leafCert([]byte("not a pem")); err == nil {
		t.Error("expected error for non-PEM input")
	}
	if _, err := leafCert([]byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n")); err == nil {
		t.Error("expected error for garbage certificate body")
	}
}

func TestClassifyCert(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	window := 30 * 24 * time.Hour

	cases := []struct {
		name     string
		notAfter time.Time
		want     certState
	}{
		{"valid: far future", now.Add(365 * 24 * time.Hour), certValid},
		{"valid: just outside window", now.Add(31 * 24 * time.Hour), certValid},
		{"expiring: inside window", now.Add(10 * 24 * time.Hour), certExpiring},
		{"expiring: right at now", now, certExpiring},
		{"expired: past", now.Add(-1 * time.Hour), certExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pem := makeCertPEM(t, "x", now.Add(-time.Hour), tc.notAfter)
			cert, err := leafCert(pem)
			if err != nil {
				t.Fatalf("leafCert: %v", err)
			}
			if got := classifyCert(cert, now, window); got != tc.want {
				t.Errorf("classifyCert = %v, want %v", got, tc.want)
			}
		})
	}
}
