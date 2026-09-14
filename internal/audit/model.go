// Package audit contains the provider-agnostic core of k8s-ingress-tls-audit.
//
// The auditor works on a small internal model (Ingress, Secret) rather than on
// client-go types directly, so the interesting logic — TLS coverage, secret
// resolution, certificate expiry — is testable without a live cluster and
// without pulling client-go into the unit tests.
package audit

import "time"

// Ingress is the minimal shape of a Kubernetes Ingress that the auditor needs.
type Ingress struct {
	Namespace string
	Name      string
	// Hosts are every host that appears under spec.rules[].host.
	Hosts []string
	// TLS mirrors spec.tls[].
	TLS []IngressTLS
}

// IngressTLS mirrors a single spec.tls entry.
type IngressTLS struct {
	Hosts      []string
	SecretName string
}

// Secret is the minimal shape of a Kubernetes Secret the auditor needs.
type Secret struct {
	Namespace string
	Name      string
	// Type is the Secret's .type (e.g. "kubernetes.io/tls").
	Type string
	// Data holds the base64-decoded values, keyed by data key ("tls.crt", "tls.key").
	Data map[string][]byte
}

// Source supplies the objects to audit. Live (client-go) and manifest (YAML on
// disk) modes both implement it.
type Source interface {
	Ingresses() ([]Ingress, error)
	// Secret returns the Secret named name in namespace ns, or (nil, nil) when
	// it does not exist.
	Secret(ns, name string) (*Secret, error)
}

// Clock returns "now"; injectable so expiry logic is deterministic in tests.
type Clock func() time.Time
