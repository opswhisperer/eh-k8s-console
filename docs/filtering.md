# Traffic filtering

The ExtraHop Kubernetes integration decides which traffic to mirror from the settings described in
[ExtraHop's documentation](https://docs.extrahop.com/current/integrations-kubernetes/):

| Setting | Values |
|---|---|
| `kubernetesBaseTrafficRule` | `mirror` or `skip`, for resources that aren't scoped to a namespace. |
| `kubernetesNamespacedTrafficRule` | `mirror` or `skip`, for namespaced resources. |
| `mirrorNamespaces` | Namespaces to forward when the namespace rule is `skip`. |
| `skipNamespaces` | Namespaces to omit when the namespace rule is `mirror`. |
| `extrahop.com/traffic-mirror-rule` annotation | `mirror` or `skip` on a resource. It overrides the namespace settings. |

## What the console does

- **Presets:** "Mirror everything except…", "Mirror only listed namespaces", "Mirror only annotated workloads", and Custom. Each sets the rules and lists consistently.
- **Namespace lists:** pick from the namespaces that exist. Unknown or overlapping namespaces are flagged, and so is a list that has no effect under the current rule.
- **Restarts:** the rules and lists reach the coordinator as environment variables, so a change restarts the coordinator, and only the coordinator.
- **Annotations:** every annotated resource in the cluster is listed.
- **Annotation editing** (with `components/annotations`): set or remove the annotation on pods (by name or label selector), on workload pod templates, and on nodes.
  - Running pods change without a restart, but the annotation is lost when a pod is replaced.
  - A pod template keeps it, but rolls the workload.
  - Namespaces in `integration.annotations.excludeNamespaces` (by default `kube-system`, `kube-public` and `kube-node-lease`) can't be edited.

## The "what gets mirrored" preview

The preview shows, per namespace and for any pair of endpoints, whether traffic is mirrored and
which rule decided. How the rules combine depends on your traffic-forwarder version, so **the
console ships without an order and the preview is off**. To turn it on, list the steps your version
applies, first match first:

```yaml
policy:
  order:
    - annotation:skip
    - annotation:mirror
    - namespace:mirror-list
    - namespace:skip-list
    - namespace:rule
    - cluster:rule
  annotationKinds: [Pod]
```

The order above only illustrates the syntax. Use your version's documented behaviour.

| Step | Matches when a Kubernetes peer of the conversation… | Result |
|---|---|---|
| `annotation:skip` | carries the annotation `skip` | skip |
| `annotation:mirror` | carries the annotation `mirror` | mirror |
| `namespace:skip-list` | is a pod in Skip namespaces | skip |
| `namespace:mirror-list` | is a pod in Mirror namespaces | mirror |
| `namespace:rule` | is a pod | `kubernetesNamespacedTrafficRule` |
| `cluster:rule` | is any Kubernetes peer | `kubernetesBaseTrafficRule` |

`annotationKinds` lists the kinds whose annotation your version reads. Annotations on other kinds
are flagged in the console; leave it empty to skip that check.

## Namespace-list format

The documentation describes comma-separated lists. If your traffic-forwarder build expects spaces,
set `integration.listSeparator: " "`. The console then writes lists that way, and flags lists that
use the other form.
