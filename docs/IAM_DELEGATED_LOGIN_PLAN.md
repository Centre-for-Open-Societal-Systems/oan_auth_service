# IAM delegated login: design note

Why delegated login works the way it does. For usage and configuration see the
"Delegated login through the OpenG2P IAM service" section of `README.md`.

## Goal

Let staff sign in through the OpenG2P IAM service instead of a local password,
with no change to consumer apps and no knowledge of the identity provider behind
IAM (Keycloak, eSignet, ...).

## Decisions

- **IAM validates, we do not.** A token whose `iss` is not this site's issuer is
  sent to IAM's `GET /auth/get_user_profile`. IAM checks signature, issuer and
  expiry with its own per-provider config. This app holds no JWKS or provider
  config, so adding a provider needs no change here.
- **Provider-neutral principal.** IAM returns `sub`, `name` and `client_roles`.
  Nothing else is read. The principal is cached until the token's `exp`
  (`api/iam_tokens.py`).
- **Identity is `sub`, not email.** `sub` does not change when a person's email
  or username does. The local `User.name` is `sha256(sub)[:32]@iam.internal`:
  always a valid email, case-sensitive subs stay distinct (`api/iam_users.py`).
  The provider is not part of the hash because the principal does not carry it.
- **Roles come only from IAM.** The user's Frappe roles are set
  to exactly `client_roles[iam_application]`, limited to roles that exist in
  Frappe. A principal that yields no roles is rejected and its user is never
  created, so IAM authentication alone grants nothing. An unset
  `iam_application` is also rejected and logged. Because the principal is cached
  until the token's `exp`, a role change applies when the user gets a new token.
- **No local password, ever.** Delegated users are created without one, and the
  login, reset and temporary-password flows refuse them.
- **Bearer first, cookie for browsers.** Bearer is the primary path. Browsers
  may send the `X-Access-Token` cookie instead. Transport and issuer are
  independent: the cookie only adds the CSRF requirement (state-changing
  requests need an `X-CSRF-Token` header matching the cookie), and `iss` alone
  picks the verifier, so either kind of token may arrive either way. An expired
  token is a `401` on both paths; the client refreshes, this app never does
  (`api/middleware.py`). Cookie names follow IAM's: `iam_auth_cookie_prefix`
  mirrors iam_core's `auth_cookie_prefix` and must hold the same value.

## Known limits

- `aud` is not enforced by IAM, so a valid token for another application is
  accepted. The role requirement above is what keeps such callers out.
- A Bearer token works until its `exp`. To cut someone off sooner, disable
  their local `User`.
- IAM role names are used as-is, with no allowlist or deny-list. Whoever
  administers this application's client in the identity provider can grant any
  Frappe role that exists, including `System Manager`. Frappe has no built-in
  setting to block a role from external assignment. This trust in the IAM
  administrators is an accepted decision for now. Follow-up: an
  `iam_role_map` in site config (IAM role to Frappe role, fail closed) so
  privileged roles can only be granted by an explicit site-config entry.
- CSRF protection on cookie requests is a plain double-submit: the
  `X-CSRF-Token` header must equal the CSRF cookie. The token is random
  (`secrets.token_urlsafe(32)`, reissued by IAM on login and on token refresh)
  but not signed and not bound to the session. If IAM's cookies are set on a
  parent domain (`auth_cookie_domain`), a sibling subdomain can set both the
  cookie and the header itself and pass the check. Do not host untrusted
  subdomains under that cookie domain. IAM sets the CSRF cookie `SameSite=Lax`,
  `Secure` per `auth_cookie_secure`, not `HttpOnly` (the page must read it).
- A user whose last IAM role is removed is stripped of their Frappe roles and
  refused. The strip is committed only on safe methods (GET, HEAD, OPTIONS).
  On POST/PUT/DELETE Frappe rolls back the rejected request, so the strip is
  undone. The user stays refused (IAM grants no role), and the next safe-method
  request commits the strip.
- Rejected tokens are not cached, and validation is a synchronous call to IAM
  (5 second timeout). An unauthenticated caller can send JWT-shaped strings with
  a foreign `iss`, each causing one IAM call and holding a worker while IAM is
  slow. This app does not throttle it. Mitigation is a per-IP `rate-limiting`
  rule in Kong on the authenticated routes. Follow-up if IAM latency becomes a
  problem: a lower timeout and a circuit breaker around the IAM call.
