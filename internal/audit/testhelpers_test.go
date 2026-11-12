package audit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// certSpec describes a test leaf certificate.
type certSpec struct {
	cn        string
	dnsNames  []string
	ips       []net.IP
	notBefore time.Time
	notAfter  time.Time
}

// makeCertKeyPEM generates a self-signed leaf certificate from spec and returns
// the PEM-encoded certificate and its PKCS#8 private key.
func makeCertKeyPEM(t *testing.T, spec certSpec) (crt, key []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: spec.cn},
		DNSNames:     spec.dnsNames,
		IPAddresses:  spec.ips,
		NotBefore:    spec.notBefore,
		NotAfter:     spec.notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	crt = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return crt, key
}

// makeCertPEM generates a self-signed leaf certificate for cn (also its only
// DNS SAN) valid over [notBefore, notAfter] and returns its PEM encoding.
func makeCertPEM(t *testing.T, cn string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	crt, _ := makeCertKeyPEM(t, certSpec{cn: cn, dnsNames: []string{cn}, notBefore: notBefore, notAfter: notAfter})
	return crt
}

// fixedClock returns a Clock that always reports t.
func fixedClock(t time.Time) Clock { return func() time.Time { return t } }
