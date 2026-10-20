# Metrics and alerts

Each scan (every 5 minutes by default) produces **findings**, each with a severity of info, warning
or critical. Findings drive the dashboard, the metrics, the webhooks and Kubernetes Events.

## Metrics

`/metrics` is served on a separate port (`-metrics-listen`, default `:9090`) with no
authentication. Keep it inside the cluster. `components/prometheus` adds a ServiceMonitor for it.

| Metric | Labels | Meaning |
|---|---|---|
| `ehk_scan_success` | | 1 if the last scan worked. |
| `ehk_last_scan_timestamp_seconds` | | Time of the last scan. |
| `ehk_cert_state` | `state` | 1 for the current certificate state (see [certificates.md](certificates.md)). |
| `ehk_cert_not_after_seconds` | `source` (bundle or live), `role`, `subject`, `fingerprint`, `anchor` | Expiry of each certificate. |
| `ehk_cert_trusted_by_bundle` | | 1 if `sensorCert` trusts the sensor. |
| `ehk_cert_public_ca` | | 1 if the sensor's chain verifies against public roots. |
| `ehk_cert_leaf_changed` | | 1 if the sensor's leaf isn't the one in `sensorCert`. |
| `ehk_cert_probe_success` | | 1 if the sensor's certificate could be read. |
| `ehk_findings` | `severity`, `source`, `code` | Current findings. |
| `ehk_log_error_signatures` | `component`, `level`, `signature` | Recurring errors in the scan window (top 25, ignored ones excluded). |
| `ehk_workload_ready`, `ehk_workload_desired` | `workload`, `kind`, `component` | Pods per integration workload. |
| `ehk_pod_restarts` | `pod`, `component`, `node` | Container restarts. |

## Alert rules

`components/prometheus` ships these rules:

| Alert | Severity | Fires when |
|---|---|---|
| `EHSensorCertBroken` | critical | Certificate state is BROKEN, SNI_MISMATCH or INVALID_BUNDLE for 5 minutes. |
| `EHSensorCertExpiring` | warning | The sensor's certificate expires within 21 days. |
| `EHSensorCertExpiringSoon` | critical | It expires within 7 days. |
| `EHSensorCertRotated` | info | The sensor renewed its certificate and `sensorCert` still trusts it. |
| `EHSensorUnreachable` | warning | The sensor's certificate can't be read for 30 minutes. |
| `EHIntegrationConfigInvalid` | critical | Any critical config, network or runtime finding, for 10 minutes. |
| `EHComponentNotReady` | warning | A workload has fewer ready pods than desired for 15 minutes. |
| `EHComponentDown` | critical | A workload has no ready pods. |
| `EHForwarderErrorsHigh` | warning | One error message repeats more than 120 times an hour, for 30 minutes. |
| `EHConsoleNotScanning` | warning | The console hasn't completed a scan for 30 minutes. |

## Webhooks

A webhook is called only when a finding **starts or stops**, not on every scan:

- **Severity filter:** each webhook gets transitions at or above its `minSeverity`.
- **No repeats after restarts:** the state of what was sent is kept in ConfigMap `eh-k8s-console-alerts`, separately for each webhook.
- **Retries:** a failed delivery is retried on the next scan.

```yaml
alerts:
  events: true                 # Kubernetes Events on the integration ConfigMap
  webhooks:
    - name: apprise
      url: http://apprise.apprise.svc:8000/notify/ops
      format: apprise          # title, body, type, optional tag
      tag: ops
      minSeverity: warning
    - name: chat
      urlFrom: { file: /secrets/slack-webhook-url }   # URLs carrying a token come from a Secret
      format: slack            # {"text": …}
      minSeverity: critical
    - name: automation
      url: https://hooks.example.com/eh
      format: json             # {"cluster", "title", "transitions": [{status, finding}], "time"}
```

Admins can send a test notification from the History page, or with `POST /api/alerts/test`.

## Ignoring known-harmless errors

Recurring log errors become findings: info, or a warning at `logs.warnPerHour` (30 by default).
Some errors are harmless churn, and ignore rules hide them from findings, metrics and alerts. They
stay visible in the log viewer under "Ignored lines".

- **Rules in the config file** (`logs.ignore`, regular expressions on the normalized message) are read-only in the UI.
- **Rules added in the console** are stored in ConfigMap `eh-k8s-console-ignore`, with a note, who added them and when. Use "Ignore…" on any error line or recurring error: it suggests an exact pattern and previews what it would hide. Operators and admins can add and remove these.
- **Normalized messages:** ids, addresses, interface names and numbers are replaced, so one rule covers every repeat of a message.
