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

- **Fails closed:** sign-in is required unless `auth.modes: [none]` is set, and `none` refuses a non-loopback address without `-insecure-no-auth`. A configured secret file that's missing stops start-up rather than opening access.
- **Secrets:**
  - Secret values are never sent to the browser, written to logs, or stored in the change history.
  - Secrets are read only by name: the three integration Secrets, and the console's own.
  - API keys are stored as SHA-256 hashes, and local passwords as bcrypt.
- **Cookies and CSRF:** browser sessions are HMAC-signed cookies (`HttpOnly`, `SameSite=Lax`, `Secure` over https). State-changing cookie requests must pass an origin check.
- **Proxy headers:** identity headers are honoured only from `auth.proxy.trustedCIDRs`.
- **Metrics:** `/metrics` has no auth and sits on its own port. Don't expose it publicly.
- **Changes:** every change is planned, dry-run by the API server, applied with optimistic concurrency, and audit-logged to stdout as JSON.
