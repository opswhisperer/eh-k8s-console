# Install with Kustomize

eh-k8s-console runs as one Deployment in the namespace of the ExtraHop Kubernetes integration,
usually `extrahop`. It finds the integration's objects by their standard names
(`extrahop-kubernetes-integration-*`), so it works with both the sensor-generated manifest and the
official Helm chart.

## Requirements

- The ExtraHop Kubernetes integration installed in the cluster.
- `kubectl` 1.27 or later (built-in Kustomize with components).
- Optional:
  - Gateway API or an Ingress controller, to reach the UI without a port-forward.
  - Prometheus Operator, for the ServiceMonitor and alert rules.
  - External Secrets Operator, to build the console's Secret from a secret store.

## 1. Choose a starting point

| Directory | Sign-in | Exposure | Extras |
|---|---|---|---|
| `deploy/base` | API keys only | port-forward | — |
| `deploy/examples/oidc-gateway` | OIDC + API keys | Gateway API `HTTPRoute` | annotation editing, Prometheus |
| `deploy/examples/oidc-ingress` | OIDC + API keys | Ingress (ingress-nginx) | — |
| `deploy/examples/local-users` | username/password | port-forward | — |
| `deploy/examples/proxy-auth` | authenticating proxy + API keys | your proxy | — |
| `deploy/examples/read-only` | API keys only | port-forward | no write access at all |

Copy the closest example into your own repo and edit it. Reference the base from there, either as a
remote base pinned to a release or as a local path:

```yaml
resources:
  - https://github.com/opswhisperer/eh-k8s-console//deploy/base?ref=v1.0.0
components:
  - https://github.com/opswhisperer/eh-k8s-console//deploy/components/prometheus?ref=v1.0.0
```

## 2. Create the Secret

The Deployment mounts Secret `eh-k8s-console` at `/secrets`. Each file named in `config.yaml` (for
example `sessionSecret: { file: /secrets/session-secret }`) is a key in that Secret. Create only
the keys your auth modes use. See [auth.md](auth.md) for the format of each key.

```bash
# API keys: the key goes to stdout (once); its entry is appended to api-keys.yaml
docker run --rm ghcr.io/opswhisperer/eh-k8s-console new-api-key -name ci -role viewer 2>> api-keys.yaml

kubectl create secret generic eh-k8s-console -n extrahop \
  --from-literal=session-secret="$(openssl rand -base64 48)" \
  --from-literal=oidc-client-secret='<client secret from your IdP>' \
  --from-file=api-keys.yaml=./api-keys.yaml
```

To build the same Secret from a secret store, add `deploy/components/external-secrets` and edit its
store name and remote keys.

The console refuses to start if a secret file named in its config is missing. It never falls back
to running without sign-in.

## 3. Apply

```bash
kubectl apply -k my-overlay/
kubectl -n extrahop rollout status deploy/eh-k8s-console
kubectl -n extrahop port-forward svc/eh-k8s-console 8080:80   # if not exposed yet
```

Check that it found the integration:

```bash
kubectl -n extrahop exec deploy/eh-k8s-console -- /eh-k8s-console validate
```

## Components

| Component | Adds |
|---|---|
| `components/annotations` | A ClusterRole to list and patch `extrahop.com/traffic-mirror-rule` on pods, workload pod templates and nodes. Also set `integration.annotations.enabled: true`, and scope it with `allowNamespaces` / `excludeNamespaces`. |
| `components/prometheus` | A ServiceMonitor for the metrics port and a PrometheusRule with the alerts in [alerts.md](alerts.md). Add your Prometheus' selector labels with a patch if it needs them. |
| `components/read-only` | Removes every write permission from the Role and starts the server with `-read-only`. |
| `components/external-secrets` | An ExternalSecret that builds Secret `eh-k8s-console`. |

## RBAC

The base grants only what the console uses:

- **Role in the integration namespace:**
  - read, create, update and delete on ConfigMaps (the integration ConfigMap, the console's history, alert state and ignore rules)
  - get and update on the three integration Secrets, by name only
  - read on pods, logs, services and events, plus create on events
  - read, update and patch on Deployments and DaemonSets
  - read on ExternalSecrets
- **ClusterRole:** read namespace names, to check the mirror and skip lists.

The annotations component adds cluster-wide get, list and patch on pods, nodes and workloads. Only
the annotation is ever patched.

## Exposure

- The UI and API listen on port 80 of Service `eh-k8s-console`.
- **Metrics:** port 9090 has no authentication. Keep it off public routes; the examples route port 80 only.
- **Streaming:** the log viewer uses server-sent events. Disable proxy buffering and allow long read timeouts (see the Ingress example).
- **TLS:** terminate it at your Gateway or Ingress, and set `baseURL` to the external `https://` URL. OIDC needs that for its callback, and cookies are marked `Secure` when `baseURL` is https.

## Images

Release images are published to `ghcr.io/opswhisperer/eh-k8s-console:<version>` for amd64 and
arm64. To build your own:

```bash
IMAGE=registry.example.com/eh-k8s-console ./build.sh 1.0.0
```

Then point your overlay at it with `images:`. The image runs as UID 65532 on a read-only root
filesystem, with every capability dropped.

## Upgrade and uninstall

- **Upgrade:** change the image tag (or `?ref=`) and `kubectl apply -k` again. The console keeps its state in ConfigMaps (history, alert state, ignore rules), so pods are disposable.
- **Uninstall:** `kubectl delete -k my-overlay/` removes the console. Its state ConfigMaps (`eh-k8s-console-rev-*`, `eh-k8s-console-alerts`, `eh-k8s-console-ignore`) aren't part of the overlay: delete them by hand if you want them gone. Nothing in the integration itself is removed.
