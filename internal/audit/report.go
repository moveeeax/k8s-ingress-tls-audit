package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

// WriteTable renders findings as an aligned text table. When there are no
// findings it writes a single "clean" line.
func WriteTable(w io.Writer, findings []Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "OK: no TLS problems found")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SEVERITY\tNAMESPACE\tINGRESS\tHOST\tSECRET\tDETAIL"); err != nil {
		return err
	}
	for _, f := range findings {
		host := f.Host
		if host == "" {
			host = "-"
		}
		secret := f.Secret
		if secret == "" {
			secret = "-"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Severity, f.Namespace, f.Ingress, host, secret, f.Message); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// WriteJSON renders findings as a JSON array with severities as strings.
func WriteJSON(w io.Writer, findings []Finding) error {
	out := make([]marshalableFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, marshalableFinding{
			Namespace: f.Namespace, Ingress: f.Ingress, Host: f.Host,
			Secret: f.Secret, Severity: f.Severity.String(), Kind: f.Kind,
			Message: f.Message, NotAfter: f.NotAfter,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
