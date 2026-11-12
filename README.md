# k8s-ingress-tls-audit

[![ci](https://github.com/moveeeax/k8s-ingress-tls-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/k8s-ingress-tls-audit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Audit Kubernetes **Ingress** resources for TLS misconfiguration — from a live
cluster or a directory of manifests — and fail CI before a bad cert turns into a
502.

`kubectl` gives you no fast answer to *"is every Ingress in this namespace
correctly terminated with a valid, non-expiring cert?"*. Ingress TLS fails
quietly: a host with no matching `spec.tls` entry serves plaintext, a
`secretName` pointing at a deleted Secret makes the controller fall back to a
fake self-signed cert, a cert copied from another host does not list the
Ingress host in its SANs, and cert secrets expire while nobody is watching. This
tool answers that question in one command.

## What it checks

| Finding | Meaning |
| --- | --- |
| `missing_tls` | A `spec.rules[].host` has no covering `spec.tls` entry (served plaintext). |
| `missing_secret` | A `spec.tls` entry references a Secret that does not exist. |
| `host_mismatch` | A `spec.tls[].hosts` entry is not covered by the leaf certificate's SANs (browsers reject the cert). |
| `bad_secret` | The Secret exists but is the wrong type, is missing `tls.crt`/`tls.key`, `tls.crt` doesn't parse, or `tls.crt` and `tls.key` are not a matching key pair. |
| `expiring` | The leaf certificate's `NotAfter` is within `--days` (default 30). |
| `expired` | The leaf certificate has already expired. |

Host matching follows Go's `crypto/x509` `VerifyHostname`: only DNS and IP
SANs count (the Subject CN is ignored, as in browsers), a wildcard SAN such as
`*.example.com` covers exactly one label (`api.example.com`, not
`example.com` or `api.eu.example.com`), and a wildcard Ingress host such as
`*.example.com` needs that same wildcard SAN. When the key pair does not match,
only `bad_secret` is reported for that Secret, since the controller will not
use it.

## Install

```sh
go install github.com/moveeeax/k8s-ingress-tls-audit/cmd/k8s-ingress-tls-audit@latest
```

## Usage

Audit a live cluster (uses your current kubeconfig context):

```sh
k8s-ingress-tls-audit --namespace prod --days 30 --fail-on expiring
```

Audit local manifests (no cluster needed — great for pre-merge CI):

```sh
k8s-ingress-tls-audit --dir ./manifests --json
```

Running against the bundled examples (which contain intentional problems).
The `soon-tls` certificate expires on 2026-09-24, so the run pins the
reference time with `--now` to show it inside the 30-day `expiring` window; at
the current time it is reported as `expired`:

```console
$ k8s-ingress-tls-audit --dir examples/manifests --days 30 --now 2026-09-15T00:00:00Z
SEVERITY        NAMESPACE  INGRESS     HOST                SECRET     DETAIL
bad_secret      prod       admin       -                   admin-tls  referenced Secret is type Opaque, not kubernetes.io/tls
missing_secret  prod       api         -                   api-tls    referenced Secret does not exist (controller serves a fake cert)
missing_tls     prod       api         legacy.example.com  -          host has no covering spec.tls entry (served plaintext)
expiring        prod       promo       -                   soon-tls   certificate expires soon (2026-09-24T16:35:54Z)
host_mismatch   prod       storefront  www.example.com     shop-tls   certificate does not cover host (SANs: shop.example.com)
$ echo $?
1
```

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--dir` | *(off)* | Audit YAML manifests in this directory instead of a live cluster. |
| `--kubeconfig` | *(standard)* | Path to kubeconfig (live mode). |
| `-n`, `--namespace` | *(all)* | Namespace to audit in live mode. |
| `--days` | `30` | Flag certificates expiring within this many days. |
| `--json` | `false` | Emit findings as JSON. |
| `--now` | *(current time)* | Check expiry as of this RFC 3339 time, e.g. `2026-09-15T00:00:00Z`. Useful for reproducible runs, or to see what will have expired by a given date. |
| `--fail-on` | `missing_secret` | Exit `1` when a finding at or above this severity exists. One of `expiring`, `missing_tls`, `host_mismatch`, `bad_secret`, `missing_secret`, `expired`. |

Severity order (low → high): `expiring` < `missing_tls` < `host_mismatch` <
`bad_secret` < `missing_secret` < `expired`. `--fail-on` gates on that order, so
`--fail-on missing_tls` also fails on
`host_mismatch`/`bad_secret`/`missing_secret`/`expired`. The default
(`missing_secret`) does not fail on `host_mismatch`; pass
`--fail-on host_mismatch` or lower to gate on it.

## Gating in CI

```yaml
- name: Audit Ingress TLS
  run: |
    k8s-ingress-tls-audit --dir k8s/ --days 30 --fail-on expiring
```

The command exits `1` when any finding meets the threshold, so the step fails
the pipeline. Use `--json` to feed the findings into a report.

## How it works

The core auditor is provider-agnostic: it operates on a tiny internal model
(`Ingress`, `Secret`) behind a `Source` interface. The **manifest** source
parses YAML off disk; the **live** source lists objects with `client-go` using
your current kubeconfig context. Both feed the same checks, so the interesting
logic — TLS host coverage, secret resolution, key pair and SAN checks, and
`crypto/x509` expiry parsing —
is unit-tested without ever touching a cluster.

## Development

```sh
go build ./...
go test ./...
```

## License

MIT — see [LICENSE](LICENSE).
