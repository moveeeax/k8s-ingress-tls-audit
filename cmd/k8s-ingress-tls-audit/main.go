// Command k8s-ingress-tls-audit scans Kubernetes Ingress resources — from a
// live cluster or from local manifests — for TLS misconfiguration and reports
// findings, with a CI-gating exit code.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/moveeeax/k8s-ingress-tls-audit/internal/audit"
	"github.com/moveeeax/k8s-ingress-tls-audit/internal/k8s"
)

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "v0.2.0"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

func newRootCmd() *cobra.Command {
	var (
		dir        string
		kubeconfig string
		namespace  string
		days       int
		jsonOut    bool
		failOn     string
	)

	cmd := &cobra.Command{
		Use:     "k8s-ingress-tls-audit",
		Short:   "Audit Kubernetes Ingress TLS: coverage, cert secrets, and expiry",
		Version: version,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var src audit.Source
			if dir != "" {
				ms, err := audit.LoadDir(dir)
				if err != nil {
					return err
				}
				src = ms
			} else {
				ls, err := k8s.NewLiveSource(kubeconfig, namespace)
				if err != nil {
					return err
				}
				src = ls
			}

			a := audit.New(src, audit.Options{ExpiryWindow: time.Duration(days) * 24 * time.Hour})
			findings, err := a.Run()
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if jsonOut {
				if err := audit.WriteJSON(out, findings); err != nil {
					return err
				}
			} else if err := audit.WriteTable(out, findings); err != nil {
				return err
			}

			threshold, err := audit.ParseSeverity(failOn)
			if err != nil {
				return err
			}
			if audit.ShouldFail(findings, threshold) {
				os.Exit(1)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&dir, "dir", "", "audit YAML manifests in this directory instead of a live cluster")
	f.StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig (live mode; default: standard resolution)")
	f.StringVarP(&namespace, "namespace", "n", "", "namespace to audit in live mode (default: all namespaces)")
	f.IntVar(&days, "days", 30, "flag certificates expiring within this many days")
	f.BoolVar(&jsonOut, "json", false, "emit findings as JSON")
	f.StringVar(&failOn, "fail-on", "missing_secret", "exit 1 when a finding at or above this severity exists (expiring|missing_tls|bad_secret|missing_secret|expired)")
	return cmd
}
