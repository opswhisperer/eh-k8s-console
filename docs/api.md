# HTTP API

The UI uses this JSON API, and so can scripts. Authenticate with an API key
(`Authorization: Bearer ehk_…`, see [auth.md](auth.md)) or a browser session. Send request
bodies as JSON with `Content-Type: application/json`; other content types are refused. The role column is
the minimum role needed. A request below that role gets `403`; one with no credentials gets `401`.

## Status

| Method and path | Role | Returns |
|---|---|---|
| `GET /healthz` | none | `200` while the scan loop is running. |
| `GET /readyz` | none | `200` after the first scan. |
| `GET /api/info` | none | Version, read-only flag, enabled features. |
| `GET /api/state` | viewer | The last scan: findings with counts, certificate assessment, workloads, Secrets (metadata only), recurring and ignored log errors, filtering mode. |
| `POST /api/scan` | operator | Runs a scan now. |
| `GET /api/certs` | viewer | Certificate assessment from the last scan. |
| `POST /api/certs/probe` | operator | Probes the sensor now and returns a fresh assessment. |

## Changing settings

Every change is planned first, then applied. Plans are free; applying needs the plan's hash, so you
apply exactly what you reviewed.

| Method and path | Role | Body / returns |
|---|---|---|
| `GET /api/settings` | viewer | Every setting with its value, type, docs, consumers and read-only flag. Secrets show length and pair status only. |
| `POST /api/plan` | viewer (admin for changes with `secrets`) | Body: a change (below). Returns the field changes, diffs, restarts, new and fixed findings, `blocked`, `hash` and `requiredRole`. |
| `POST /api/apply` | operator* | Body: `{"change": …, "hash": "<from plan>", "kind": "apply"}`. Returns the revision and the restarted workloads. `409` if the cluster changed since the plan. |
| `GET /api/rollout?names=Deployment/x,DaemonSet/y` | viewer | Rollout progress. |
| `GET /api/history` | viewer | Revisions, newest first. |
| `GET /api/history/{n}` | viewer | One revision, including the state before it. |
| `POST /api/history/{n}/rollback` | viewer | A plan (and its change) that restores the state before revision `n`. Apply it with `/api/apply`. |
| `POST /api/certs/candidate` | operator | Body: `{"mode": "ca-chain" or "full-chain"}` or `{"pem": "…"}`. Returns the bundle and whether it trusts the sensor. Apply it as a `sensorCert` change. |

\* Operators can apply changes to `sensorCert` and restarts. Every other change, and `force`, needs
admin. `requiredRole` in the plan says which applies.

A new `sensorCert` is checked on the server at apply time: it must trust the sensor's current
certificate (admins can `force` past that). An operator may store only certificates the sensor
presents, or the root that verified them, never an extra trust anchor.

A change:

```json
{
  "config":  { "skipNamespaces": "batch,ci" },
  "remove":  [],
  "secrets": [{ "name": "extrahop-kubernetes-integration-sensor-api-credentials", "key": "apiKey", "value": "…" }],
  "images":  { "extrahop-kubernetes-integration-exkpkt-forwarder/exkpkt": "public.ecr.aws/extrahop/kubernetes-traffic-forwarder:v1.2.3" },
  "restart": ["extrahop-kubernetes-integration-metadata-forwarder"],
  "reason":  "quiet batch namespaces",
  "force":   false
}
```

Example: change a list from a script.

```bash
B=https://ehconsole.example.com; H="Authorization: Bearer $EHK_KEY"; J="Content-Type: application/json"
CHANGE='{"config":{"skipNamespaces":"batch,ci"},"reason":"from CI"}'
HASH=$(curl -s -H "$H" -H "$J" -d "$CHANGE" $B/api/plan | jq -r 'if .blocked then error(.blockReason) else .hash end')
curl -s -H "$H" -H "$J" -d "{\"change\":$CHANGE,\"hash\":\"$HASH\"}" $B/api/apply
```

## Traffic filtering and annotations

| Method and path | Role | Body / returns |
|---|---|---|
| `GET /api/policy` | viewer | Rules, namespace lists, mode, annotated resources, and the preview (when `policy.order` is set). |
| `POST /api/policy/evaluate` | viewer | Body: `{"peers": [{"kind": "pod", "namespace": "a"}, {"kind": "external"}], "config": {…overrides}}`. `400` when the preview is off. |
| `GET /api/annotations` | viewer | Every resource carrying the mirror annotation. |
| `GET /api/pods?namespace=&selector=` | viewer | Pods in one namespace (required), with owner and current rule. Annotation editing must be enabled. |
| `GET /api/nodes` | viewer | Nodes and their current rule. |
| `POST /api/annotate` | operator* | Body: `{"targets": [{"kind": "Pod", "namespace": "a", "name": "p"}], "rule": "mirror" or "skip" or "", "mode": "now" or "persist" or "both", "dryRun": false}`, or `namespace` + `selector` in place of `targets`. |

\* `persist` and `both` change workload pod templates and need admin.

## Logs

| Method and path | Role | Returns |
|---|---|---|
| `GET /api/logs/stream?component=&pod=&tail=&previous=` | viewer | Server-sent events, one JSON log line per event (with `signature` and `ignoredBy` on warnings and errors). Up to 3 open streams per user, and 25 in total. |
| `GET /api/logs?since=1h&component=&format=text` | viewer | Recent lines as JSON, or as a text download. `since` is capped at 24h, 2 MiB per container and 100,000 lines. |
| `GET /api/events` | viewer | Kubernetes events for the integration's objects. |
| `GET /api/ignore` | viewer | Ignore rules and what each hid in the last window. |
| `POST /api/ignore/test` | viewer | Body: `{"pattern": "…"}`. Checks a pattern and lists what it would hide. |
| `POST /api/ignore` | operator | Body: `{"pattern": "…", "note": "…"}`. Adds a rule. |
| `POST /api/ignore/remove` | operator | Body: `{"pattern": "…"}`. Removes a console rule. |

## Export and alerts

| Method and path | Role | Returns |
|---|---|---|
| `GET /api/export/manifests` | viewer | ConfigMap and workload YAML (no Secrets). |
| `GET /api/export/helm-values?secrets=false` | viewer (admin with `secrets=true`) | A values file for the official Helm chart. |
| `POST /api/export` | viewer | Body: `{"change": …, "format": "helm" or "manifests"}`. The state a pending change would produce, for GitOps. |
| `POST /api/alerts/test` | admin | Sends a test notification to each webhook. |

## Sign-in endpoints

| Path | Use |
|---|---|
| `GET /auth/config` | The enabled modes, for the sign-in page. |
| `GET /auth/me` | The current identity. |
| `POST /auth/login` | Local sign-in: `{"username", "password"}`. |
| `GET /auth/oidc?next=/` | Starts OIDC sign-in. The callback is `/auth/callback`. |
| `POST /auth/logout` | Ends the session. Returns the provider's logout URL when there is one. |
