# Sign-in, roles and secrets

Choose any combination of modes in `auth.modes`. Every request is checked by the server. The UI
only hides what you can't do; it doesn't enforce anything.

| Mode | For | How it signs in |
|---|---|---|
| `oidc` | People | Authorization code with PKCE against your identity provider. Groups map to roles. |
| `local` | People, without an IdP | Username and bcrypt password from a file. |
| `apikey` | Scripts, CI, monitoring | `Authorization: Bearer ehk_…`. Only SHA-256 hashes are stored. |
| `proxy` | People, behind an authenticating proxy | Identity headers set by the proxy, trusted only from listed addresses. |
| `none` | Local development | No sign-in. Refuses to listen on a non-loopback address unless started with `-insecure-no-auth`. |

## Roles

| Role | Can |
|---|---|
| `viewer` | See everything except secret values, preview changes, read logs, export manifests. |
| `operator` | Everything a viewer can, plus: refresh the sensor certificate, restart integration workloads, annotate running pods and nodes, and add or remove log ignore rules. |
| `admin` | Everything, including every setting, the integration Secrets, images, pod-template annotations, rollback, and forcing a blocked change. |

A signed-in user who matches no role mapping is refused, unless `auth.defaultRole` is set.

## Secrets

The config never contains a secret value. It names a file (or an environment variable) for each
one:

```yaml
auth:
  sessionSecret: { file: /secrets/session-secret }      # or { env: SESSION_SECRET }
```

- **Where the files come from:** the base Deployment mounts Secret `eh-k8s-console` at `/secrets`. Create it with `kubectl`, External Secrets (see `components/external-secrets`), Sealed Secrets, or a CSI secret store. The console doesn't care which.
- **Rotation:** the users file and API-key file are re-read when they change, so rotating the Secret takes effect within the kubelet's sync period (about a minute) without a restart.
- **Session secret:** `sessionSecret` signs session cookies. It must be at least 32 characters, for example `openssl rand -base64 48`. Without it, sessions end when the pod restarts.

## OIDC

```yaml
baseURL: https://ehconsole.example.com      # the callback is <baseURL>/auth/callback
auth:
  modes: [oidc, apikey]
  sessionSecret: { file: /secrets/session-secret }
  oidc:
    issuer: <issuer URL>
    clientID: eh-k8s-console
    clientSecret: { file: /secrets/oidc-client-secret }
    scopes: [openid, profile, email, groups]  # drop scopes your IdP doesn't offer
    groupsClaim: groups
    roles:
      platform-admins: admin
      platform-oncall: operator
      security-analysts: viewer
```

Register a confidential client that has:

- the redirect URI `https://<host>/auth/callback`
- the authorization-code grant
- a groups claim in the ID token

Provider notes:

| Provider | Issuer | Groups |
|---|---|---|
| Authentik | `https://auth.example.com/application/o/<slug>/` | The `profile` scope includes `groups`. Use `scopes: [openid, profile, email]`. |
| Keycloak | `https://kc.example.com/realms/<realm>` | Add a "Group Membership" mapper to the client (claim `groups`, full path off). |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | Set `groupMembershipClaims` in the app manifest. The claim holds group **object IDs**, so map those IDs in `roles`. |
| Dex | your Dex issuer | Add the `groups` scope. |
| Google | `https://accounts.google.com` | No groups claim. Use `defaultRole`, and restrict who can sign in on the Google side. |

Logout ends the console session and, when the provider supports it, the provider session too.

## Local users

```bash
eh-k8s-console hash-password            # reads the password from the terminal or stdin
```

```yaml
# users.yaml, a key in Secret eh-k8s-console
- username: alice
  passwordHash: '$2a$12$…'
  role: admin
- username: bob
  passwordHash: '$2a$12$…'
  role: viewer
```

```yaml
auth:
  modes: [local]
  sessionSecret: { file: /secrets/session-secret }
  local: { usersFile: /secrets/users.yaml }
```

Each client and username pair is limited to 10 sign-in attempts a minute, so one client can't lock everyone out behind a shared ingress. Failed attempts are logged. `baseURL` is required (it decides whether cookies are `Secure`).

## API keys

```bash
eh-k8s-console new-api-key -name ci -role viewer
```

This prints the key once (store it in your secret manager) and the entry for the keys file:

```yaml
# api-keys.yaml
- name: ci
  hash: 9f2c…      # sha256 of the key
  role: viewer
```

Use the key like this:

```bash
curl -H "Authorization: Bearer $EHK_KEY" https://ehconsole.example.com/api/state
```

API-key requests skip the browser's CSRF origin check, because they carry no cookie. To revoke a
key, remove its entry from the file. See [api.md](api.md) for the endpoints.

## Authenticating proxy

Use this when a proxy already handles sign-in, such as oauth2-proxy, Authentik or Authelia forward
auth, Pomerium, or Envoy Gateway `extAuth`.

```yaml
auth:
  modes: [proxy, apikey]
  proxy:
    trustedCIDRs: [10.244.0.0/16]      # where the proxy's requests come from
    sharedSecret: { file: /secrets/proxy-secret }     # strongly recommended, see below
    sharedSecretHeader: X-Console-Proxy-Secret
    userHeader: X-Forwarded-User
    groupsHeader: X-Forwarded-Groups   # comma- or pipe-separated
    emailHeader: X-Forwarded-Email
    roles: { platform-admins: admin }
  defaultRole: viewer
```

**Identity headers are only as trustworthy as the network path.** Anything that can reach the
console from inside `trustedCIDRs` can set them, and a pod CIDR includes every pod in the
cluster. Use both of these protections:

- **Shared secret:** configure the proxy to add `X-Console-Proxy-Secret: <secret>` to every request it forwards. The console then ignores identity headers on requests without it.
  - Envoy Gateway / Istio: `headersToAdd` on the route.
  - ingress-nginx: `nginx.ingress.kubernetes.io/configuration-snippet` with `proxy_set_header`.
  - oauth2-proxy: `--upstream` through a sidecar, or your ingress.
- **NetworkPolicy:** allow ingress to the console's port 8080 only from the proxy's pods. `deploy/examples/proxy-auth/networkpolicy.yaml` is a template.

Also:

- **Header names:**
  - oauth2-proxy: `X-Forwarded-User` and `X-Forwarded-Groups` (with `--pass-user-headers`).
  - Authentik forward auth: `X-authentik-username` and `X-authentik-groups`.
- **Strip client headers:** the proxy must remove these headers when they come from the client.
- **The `Authorization` header:** a request that carries one is treated as an API client. It gets an identity only from a valid console API key, never from proxy headers or a cookie. So don't configure the proxy to pass its own `Authorization` header upstream (oauth2-proxy: leave `--pass-authorization-header` and `--set-authorization-header` off).
- **Keeping API keys working:** if the proxy gates every path, route requests whose header starts with `Bearer ehk_` around it, and send everything else through it.

## CSRF and sessions

- **Cookies:** the session cookie is HMAC-signed, `HttpOnly` and `SameSite=Lax`, and `Secure` when `baseURL` is https. `baseURL` is required for OIDC and local sign-in.
- **Session lifetime:** sessions last `auth.sessionTTL` (8h by default).
- **Revocation:**
  - Signing out revokes the session on the server (for a single replica).
  - A local user removed from the users file, or given another role, is signed out or changed on their next request.
  - To sign everyone out, set `auth.sessionsValidAfter` to the current time (RFC 3339) and restart.
- **Origin check:** every state-changing request that doesn't use an API key (cookie, proxy headers, or no sign-in) must come from the console's own origin, and API bodies must be `Content-Type: application/json`.
- **No sign-in (`none`):** the console answers only to `localhost` / loopback `Host` names, which defeats DNS rebinding.
- **Security headers:** the UI is served with a Content-Security-Policy, `X-Content-Type-Options: nosniff` and `frame-ancestors 'none'`.
