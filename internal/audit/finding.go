package audit

import "fmt"

// Severity orders findings from least to most urgent. Higher value = worse.
type Severity int

const (
	// SeverityOK is used only as the baseline for --fail-on comparisons.
	SeverityOK Severity = iota
	// SeverityExpiring: a cert is valid but within the expiry window.
	SeverityExpiring
	// SeverityMissingTLS: a host has no covering spec.tls entry.
	SeverityMissingTLS
	// SeverityBadSecret: the referenced Secret exists but is unusable.
	SeverityBadSecret
	// SeverityMissingSecret: the referenced Secret does not exist.
	SeverityMissingSecret
	// SeverityExpired: a cert's NotAfter is in the past.
	SeverityExpired
)

var severityNames = map[Severity]string{
	SeverityOK:            "ok",
	SeverityExpiring:      "expiring",
	SeverityMissingTLS:    "missing_tls",
	SeverityBadSecret:     "bad_secret",
	SeverityMissingSecret: "missing_secret",
	SeverityExpired:       "expired",
}

var severityByName = func() map[string]Severity {
	m := make(map[string]Severity, len(severityNames))
	for k, v := range severityNames {
		m[v] = k
	}
	return m
}()

// String returns the lowercase name of the severity.
func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// ParseSeverity maps a --fail-on value to a Severity. It accepts the finding
// kinds plus "expiring" as the lowest actionable threshold.
func ParseSeverity(s string) (Severity, error) {
	if v, ok := severityByName[s]; ok && v != SeverityOK {
		return v, nil
	}
	return SeverityOK, fmt.Errorf("unknown severity %q (want one of: expiring, missing_tls, bad_secret, missing_secret, expired)", s)
}

// Finding is a single problem discovered on an Ingress.
type Finding struct {
	Namespace string   `json:"namespace"`
	Ingress   string   `json:"ingress"`
	Host      string   `json:"host,omitempty"`
	Secret    string   `json:"secret,omitempty"`
	Severity  Severity `json:"-"`
	Kind      string   `json:"kind"`
	Message   string   `json:"message"`
	// NotAfter is set for expiry-related findings.
	NotAfter string `json:"not_after,omitempty"`
}

// MarshalableFinding is Finding with the severity rendered as a string, used
// for JSON output.
type marshalableFinding struct {
	Namespace string `json:"namespace"`
	Ingress   string `json:"ingress"`
	Host      string `json:"host,omitempty"`
	Secret    string `json:"secret,omitempty"`
	Severity  string `json:"severity"`
	Kind      string `json:"kind"`
	Message   string `json:"message"`
	NotAfter  string `json:"not_after,omitempty"`
}
