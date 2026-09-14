package audit

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// leafCert decodes the first CERTIFICATE PEM block in tls.crt and returns the
// parsed leaf. The leaf is the first certificate in a TLS chain.
func leafCert(pemBytes []byte) (*x509.Certificate, error) {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no CERTIFICATE PEM block found")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return cert, nil
	}
}

// certState classifies a cert's validity relative to now and the expiry window.
type certState int

const (
	certValid certState = iota
	certExpiring
	certExpired
)

// classifyCert reports whether the cert is valid, expiring within window, or
// already expired, as of now.
func classifyCert(cert *x509.Certificate, now time.Time, window time.Duration) certState {
	switch {
	case now.After(cert.NotAfter):
		return certExpired
	case now.Add(window).After(cert.NotAfter):
		return certExpiring
	default:
		return certValid
	}
}
