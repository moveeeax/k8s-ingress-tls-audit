package audit

import (
	"crypto/x509"
	"sort"
	"time"
)

// Options tune an audit run.
type Options struct {
	// ExpiryWindow flags certs whose NotAfter is within this duration of now.
	ExpiryWindow time.Duration
	// Now returns the reference time; defaults to time.Now when nil.
	Now Clock
}

// Auditor runs TLS checks against a Source.
type Auditor struct {
	src  Source
	opt  Options
	now  func() time.Time
}

// New builds an Auditor. A zero ExpiryWindow means "never flag as expiring".
func New(src Source, opt Options) *Auditor {
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	return &Auditor{src: src, opt: opt, now: now}
}

// Run audits every Ingress from the Source and returns findings sorted by
// (namespace, ingress, host).
func (a *Auditor) Run() ([]Finding, error) {
	ingresses, err := a.src.Ingresses()
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, ing := range ingresses {
		findings = append(findings, a.auditIngress(ing)...)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Namespace != findings[j].Namespace {
			return findings[i].Namespace < findings[j].Namespace
		}
		if findings[i].Ingress != findings[j].Ingress {
			return findings[i].Ingress < findings[j].Ingress
		}
		return findings[i].Host < findings[j].Host
	})
	return findings, nil
}

func (a *Auditor) auditIngress(ing Ingress) []Finding {
	var out []Finding

	// 1. Hosts not covered by any spec.tls entry.
	covered := map[string]bool{}
	for _, t := range ing.TLS {
		for _, h := range t.Hosts {
			covered[h] = true
		}
	}
	for _, h := range ing.Hosts {
		if !covered[h] {
			out = append(out, Finding{
				Namespace: ing.Namespace, Ingress: ing.Name, Host: h,
				Severity: SeverityMissingTLS, Kind: "missing_tls",
				Message: "host has no covering spec.tls entry (served plaintext)",
			})
		}
	}

	// 2. Each tls entry: resolve and validate the referenced Secret.
	for _, t := range ing.TLS {
		out = append(out, a.auditTLSEntry(ing, t)...)
	}
	return out
}

func (a *Auditor) auditTLSEntry(ing Ingress, t IngressTLS) []Finding {
	if t.SecretName == "" {
		return []Finding{{
			Namespace: ing.Namespace, Ingress: ing.Name,
			Severity: SeverityBadSecret, Kind: "bad_secret",
			Message: "spec.tls entry has an empty secretName",
		}}
	}

	sec, err := a.src.Secret(ing.Namespace, t.SecretName)
	if err != nil {
		return []Finding{{
			Namespace: ing.Namespace, Ingress: ing.Name, Secret: t.SecretName,
			Severity: SeverityBadSecret, Kind: "bad_secret",
			Message: "failed to read referenced Secret: " + err.Error(),
		}}
	}
	if sec == nil {
		return []Finding{{
			Namespace: ing.Namespace, Ingress: ing.Name, Secret: t.SecretName,
			Severity: SeverityMissingSecret, Kind: "missing_secret",
			Message: "referenced Secret does not exist (controller serves a fake cert)",
		}}
	}

	base := Finding{Namespace: ing.Namespace, Ingress: ing.Name, Secret: t.SecretName}

	if sec.Type != "" && sec.Type != "kubernetes.io/tls" {
		f := base
		f.Severity, f.Kind = SeverityBadSecret, "bad_secret"
		f.Message = "referenced Secret is type " + sec.Type + ", not kubernetes.io/tls"
		return []Finding{f}
	}
	crt, hasCrt := sec.Data["tls.crt"]
	_, hasKey := sec.Data["tls.key"]
	if !hasCrt || len(crt) == 0 || !hasKey {
		f := base
		f.Severity, f.Kind = SeverityBadSecret, "bad_secret"
		f.Message = "Secret is missing tls.crt and/or tls.key"
		return []Finding{f}
	}

	cert, err := leafCert(crt)
	if err != nil {
		f := base
		f.Severity, f.Kind = SeverityBadSecret, "bad_secret"
		f.Message = "tls.crt is not a valid certificate: " + err.Error()
		return []Finding{f}
	}
	return a.certFindings(base, cert)
}

func (a *Auditor) certFindings(base Finding, cert *x509.Certificate) []Finding {
	base.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	switch classifyCert(cert, a.now(), a.opt.ExpiryWindow) {
	case certExpired:
		base.Severity, base.Kind = SeverityExpired, "expired"
		base.Message = "certificate expired on " + base.NotAfter
		return []Finding{base}
	case certExpiring:
		base.Severity, base.Kind = SeverityExpiring, "expiring"
		base.Message = "certificate expires soon (" + base.NotAfter + ")"
		return []Finding{base}
	default:
		return nil
	}
}

// MaxSeverity returns the highest severity among findings, or SeverityOK.
func MaxSeverity(findings []Finding) Severity {
	max := SeverityOK
	for _, f := range findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// ShouldFail reports whether findings contain at least one at or above the
// failOn threshold — the CI-gate decision.
func ShouldFail(findings []Finding, failOn Severity) bool {
	if failOn == SeverityOK {
		return false
	}
	return MaxSeverity(findings) >= failOn
}
