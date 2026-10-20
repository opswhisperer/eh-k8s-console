# Sensor certificate

The integration's forwarders connect to the sensor's management interface over TLS:

- metadata on port 443
- session keys on port 4873, when TLS decryption is on

They trust whatever certificates are in the ConfigMap key `sensorCert` (mounted as
`/certs/sensor.crt`), and they check the sensor's name against `serverNameOverride`.

**Any** certificate in `sensorCert` can anchor that trust. That decides what to store:

| The sensor's certificate | Store in `sensorCert` | When the sensor renews it |
|---|---|---|
| From a public or internal CA | The CA chain only | Keeps working. A leaf left in the bundle goes stale but does no harm. |
| Self-signed | That exact certificate | The forwarders stop trusting the sensor until `sensorCert` is updated. |

## What the console checks

Every scan, the console reads the chain the sensor presents and verifies it the same way the
forwarders do: the bundle as roots, and `serverNameOverride` as the name. The result is one state:

| State | Meaning |
|---|---|
| `OK` | The sensor presents the certificate stored in the bundle. |
| `ROTATED_TRUSTED` | The sensor renewed its certificate, and the bundle still trusts it. Informational. |
| `BROKEN` | The bundle doesn't trust the sensor's certificate. The forwarders can't connect. |
| `SNI_MISMATCH` | `serverNameOverride` isn't one of the certificate's names. |
| `UNREACHABLE` | The sensor couldn't be probed from the console's pod. |
| `INVALID_BUNDLE` | `sensorCert` is empty or unparseable. |

It also reports:

- **Expiry of the sensor's live certificate:** a warning under 21 days and critical under 7, by default. For an automatically renewed certificate, this means renewal is failing.
- **Expiry of the bundle certificate that anchors trust.** Expired certificates that don't anchor anything are reported as harmless.
- **Bundle contents:** a bundle that pins a leaf when the CA chain alone would do.
- **Session-key port:** whether it presents a different certificate from port 443.

## Updating `sensorCert`

On the Sensor certificate page:

- **Use the sensor's CA chain:** offered when the chain verifies against public roots. It stores the CA certificates the sensor presents plus the root that verified them, and survives every future renewal.
- **Use the full chain from the sensor:** the only option for a self-signed certificate. Check the fingerprint against the sensor's admin page before applying.
- **Paste certificates:** the bundle must trust the sensor's current certificate before it can be applied.

Each option becomes a normal change: you review the diff, then apply it. The console restarts only
the workloads that read `sensorCert`.

The server checks the bundle again at apply time, whatever the UI shows:

- **Any bundle:** it must trust the sensor's current certificate. Admins can force past this, for example while the sensor is down.
- **Operators:** they can store only certificates the sensor itself presents, or the root that verified them. Adding any other trust anchor needs an admin.

## Automatic updates

| Setting | Effect |
|---|---|
| `certs.autoSync: true` | When the sensor's chain changes and still verifies against public roots with a matching name, `sensorCert` is replaced with the CA chain. Never applies to self-signed certificates. |
| `certs.source: {kind, namespace, name, key}` | Keeps `sensorCert` equal to a key you manage elsewhere, such as a cert-manager `ca.crt` or a trust-manager bundle. A new value must trust the sensor before it's applied. |

## From the command line

```bash
eh-k8s-console certs check -exit-code    # 0 ok or info, 1 warning, 2 critical
```

Use it in a CronJob or in CI. `-json` prints the full assessment.
