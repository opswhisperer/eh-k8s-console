# Security

eh-k8s-console can change a cluster's ExtraHop integration and, with the annotations component,
patch annotations on workloads cluster-wide. Treat access to it like access to those objects.

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/opswhisperer/eh-k8s-console/security/advisories/new),
not in a public issue. This is a community project maintained in spare time, so there's no
response-time commitment, but reports are taken seriously.

This project isn't affiliated with ExtraHop Networks. Report vulnerabilities in ExtraHop products
to ExtraHop, not here.

## Design notes

- **Fails closed:** sign-in is required unless `auth.modes: [none]` is set. `none` refuses a non-loopback listen address without `-insecure-no-auth`, and answers only to loopback `Host` names (which defeats DNS rebinding). A configured secret file that's missing stops start-up rather than opening access.
- **Secrets:**
  - Secret values are never sent to the browser, written to logs, or stored in the change history.
  - Secrets are read only by name: the three integration Secrets, and the console's own.
  - API keys are stored as SHA-256 hashes, and local passwords as bcrypt.
- **Cookies and CSRF:**
  - Browser sessions are HMAC-signed cookies (`HttpOnly`, `SameSite=Lax`, `Secure` over https) with an issue time and an ID.
  - Logout revokes the session, and `auth.sessionsValidAfter` signs everyone out.
  - Every state-changing request without an API key must pass an origin check and send JSON.
- **Proxy headers:** identity headers are honoured only from `auth.proxy.trustedCIDRs`, only with the shared secret when one is configured, and never on requests that carry an `Authorization` header.
- **Annotation editing:** the annotations component ships ValidatingAdmissionPolicies, so the API server, not just the app, limits the console's cluster-wide patches to the mirror annotation.
- **Sensor certificate:** a new `sensorCert` is verified on the server. Operators can't add trust anchors the sensor doesn't present.
- **Resource limits:** API reads share a short-lived snapshot. Cluster lists are paged, and log fetches and streams are capped per request and per user.
- **Metrics:** `/metrics` has no auth and sits on its own port. Don't expose it publicly.
- **Changes:** every change is planned, dry-run by the API server, applied with optimistic concurrency, and audit-logged to stdout as JSON.
