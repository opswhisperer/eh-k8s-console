# Contributing

Issues and pull requests are welcome. This is an independent community project, not an ExtraHop
product. Please don't include anything confidential from ExtraHop or from your own environment
(hostnames, addresses, keys, certificates, logs) in issues, code or test data.

## Layout

| Path | What |
|---|---|
| `cmd/eh-k8s-console` | CLI: `serve`, `validate`, `certs check`, `hash-password`, `new-api-key` |
| `internal/discovery` | Finds the integration's objects and works out which workload reads which setting |
| `internal/model` | Every setting: type, docs, Helm path, read-only flags |
| `internal/validate` | Checks that turn a state (live or proposed) into findings |
| `internal/certs` | Sensor-certificate parsing, probing, verification and drift states |
| `internal/apply` | Plan, diff, dry-run, apply, history, rollback, annotations |
| `internal/policy` | The configurable filtering preview |
| `internal/logs`, `internal/ignore` | Log streaming, error signatures and ignore rules |
| `internal/auth` | OIDC, local users, API keys, proxy, sessions, CSRF |
| `internal/alerts` | Metrics, webhooks, Kubernetes Events |
| `internal/server` | HTTP API and the scan loop |
| `web/static` | The UI: plain HTML, CSS and JS, embedded in the binary |
| `deploy/` | Kustomize base, components and examples |
| `testdata/integration.json` | Sanitized manifests from a real sensor-generated install |

## Checks

```bash
gofmt -l .                     # must print nothing
go vet ./...
go test ./...
node --check web/static/app.js
for d in deploy/base deploy/examples/*/; do kubectl kustomize "$d" > /dev/null; done
```

Tests run against a fake Kubernetes API built from `testdata/integration.json`; no cluster is needed.

## Licensing

Contributions are accepted under the Apache License 2.0. When you add a Go dependency, run
`python3 hack/third_party_notices.py` to regenerate `THIRD_PARTY_NOTICES.md`, and check that the new
license is compatible with Apache-2.0.
