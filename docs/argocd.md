# Running with Argo CD

Argo CD can manage two things here, often both:

- **The ExtraHop Kubernetes integration:** its ConfigMap, Secrets and workloads, synced from your git repository. The console then must not change them live, and this page says how to change them instead.
- **The console itself:** its Deployment, config and RBAC. See [Deploying the console with Argo CD](#deploying-the-console-with-argo-cd).

## When Argo CD manages the integration

### What the console does

The console looks for Argo CD's tracking annotation, `argocd.argoproj.io/tracking-id`, on the integration's ConfigMap and workloads. When it finds it:

- **Changes are blocked.** Settings, the sensor certificate, images, args and rollbacks are all blocked. With self-heal on, Argo CD would put the git version back within seconds; without it, the next sync would. The plan shows the application's name and a note, and the UI shows a banner.
- **Restarts still work.** A rollout restart changes nothing in git. [Ignore its annotation](#ignore-the-consoles-restarts) so Argo CD doesn't undo it.
- **Admins can force a change.** That's only useful for an application without self-heal, and the next sync still reverts it.

The console detects annotation tracking only: the default since Argo CD 3.0, or `application.resourceTrackingMethod: annotation` or `annotation+label` in `argocd-cm`. With label tracking only (`app.kubernetes.io/instance`), the console can't tell that Argo CD is in charge, and a live change is reverted as described above. Switch to `annotation+label` to keep your labels and let the console see it.

### Making a change

1. **Plan it:** in the console, edit the settings or the certificate and check the plan: its findings, diff and the restarts it needs.
2. **Export it:** **Export → manifests** (or Helm values, for a Helm-based install) gives the state the change would produce. The API equivalent is `POST /api/export` ([API](api.md)).
3. **Commit it** to the repository Argo CD syncs from, and let Argo CD sync.
4. **Restart** the workloads the plan listed, from the console. Pods don't reread the ConfigMap by themselves.

Secrets stay out of git. If an ExternalSecret builds them, change the value in the secret store; the console already blocks a Secret an ExternalSecret owns.

**Keep the sensor's manifest untouched.** The sensor generates the integration's manifest, and you will download a new one for upgrades and for new keys or certificates. Commit it as it is, and put your own changes in Kustomize patches next to it, so a new manifest doesn't overwrite them:

```text
integration/
  kustomization.yaml     resources: vendor/…; patches: patches/…
  vendor/                the sensor's manifest, split per object (replaced on every update)
  patches/               your changes: traffic rules, namespaces, sensorCert, images
```

```yaml
# kustomization.yaml
resources:
  - vendor/configmap.yaml
  - vendor/forwarders.yaml
  # …
patches:
  - path: patches/settings.yaml
```

```yaml
# patches/settings.yaml: ConfigMap keys you changed with the console's plan
apiVersion: v1
kind: ConfigMap
metadata:
  name: extrahop-kubernetes-integration-cm
  namespace: extrahop
data:
  mirrorNamespaces: "shop,payments"
```

## Argo CD settings for the console's live writes

These are the things the console still writes live, with what each needs from Argo CD:

| The console writes | Where | What Argo CD needs |
|---|---|---|
| Restarts | annotation `kubectl.kubernetes.io/restartedAt` on the pod template of the integration's Deployments and DaemonSets | Ignore it, or self-heal reverts it and rolls the pods a second time |
| Mirror annotations (annotation editing, `components/annotations`) | `extrahop.com/traffic-mirror-rule` on pods, nodes and workload pod templates in other namespaces | Pods and nodes: nothing. On a workload another Argo CD application manages: put the annotation in that application's git, or ignore the key there |
| Its own state | ConfigMaps `eh-k8s-console-alerts`, `eh-k8s-console-ignore`, `eh-k8s-console-rev-NNNNN` (history), and Events | Not in git: ignore them as orphans, and never put them in git |

### Ignore the console's restarts

In `argocd-cm`, for every application:

```yaml
data:
  resource.customizations.ignoreDifferences.all: |
    jqPathExpressions:
    - .spec.template.metadata.annotations."kubectl.kubernetes.io/restartedAt"
```

Or only on the integration's Application, together with `RespectIgnoreDifferences=true`, so a sync leaves the field alone:

```yaml
spec:
  ignoreDifferences:
  - group: apps
    kind: Deployment
    jqPathExpressions: ['.spec.template.metadata.annotations."kubectl.kubernetes.io/restartedAt"']
  - group: apps
    kind: DaemonSet
    jqPathExpressions: ['.spec.template.metadata.annotations."kubectl.kubernetes.io/restartedAt"']
  syncPolicy:
    syncOptions: [RespectIgnoreDifferences=true]
```

The same goes for `kubectl rollout restart`, so you may have this already.

### Orphaned-resource warnings

If the AppProject warns about orphaned resources, add the console's state ConfigMaps to its ignore list:

```yaml
spec:
  orphanedResources:
    warn: true
    ignore:
    - {kind: ConfigMap, name: eh-k8s-console-alerts}
    - {kind: ConfigMap, name: eh-k8s-console-ignore}
    - {kind: ConfigMap, name: eh-k8s-console-rev-*}
```

## Deploying the console with Argo CD

Keep your overlay (see [Install](install.md), step 1) in git, referencing a release of the base:

```yaml
# kustomization.yaml in your repository
resources:
  - https://github.com/opswhisperer/eh-k8s-console//deploy/base?ref=v0.1.5
configMapGenerator:
  - name: eh-k8s-console-config
    behavior: replace
    files: [config.yaml]
generatorOptions:
  # each config change creates a new hashed ConfigMap: without prune, let Argo CD ignore the old ones
  annotations:
    argocd.argoproj.io/compare-options: IgnoreExtraneous
```

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: eh-k8s-console
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://git.example.com/you/eh-k8s-console-overlay.git
    targetRevision: main
    path: .
  destination:
    server: https://kubernetes.default.svc
    namespace: extrahop
  syncPolicy:
    automated: {selfHeal: true}
```

- **Upgrading:** bump `?ref=` (and the image tag, if you pin it) and let Argo CD sync.
- **Secrets:** the console's own Secret (`eh-k8s-console`: OIDC client secret, API key hashes) belongs in your secret store. `components/external-secrets` builds it from there.
- **One namespace, two applications:** the console and the integration can live in the same namespace under two Argo CD applications. The tracking annotation keeps their objects apart.
