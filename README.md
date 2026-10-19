# oan_auth_service

JWT authentication service for OAN services, packaged as a Frappe app.

## Status

Scaffold only. Module structure, packaging, hooks and the refresh-token schema
are in place; every function body raises `NotImplementedError`.

## Why an app and not a library

The shared surface owns a doctype (`OAN User Refresh Token`). Frappe binds
doctypes to apps: `frappe.get_module_app` resolves a doctype's module through
`local.module_app`, which is built by walking the `modules.txt` of every
**installed app** (`frappe/__init__.py:1053`). A plain pip package has no
`modules.txt`, so it cannot own a doctype at all. Once login, registration and
refresh-token storage are shared, app-ness is forced.

## What it shares, and what it does not

Consumers share **code, not identity**. Each deployment has its own site, its
own database, its own `User` table and its own signing keys. A token minted by
one deployment is not valid at another — see the note in `api/jwt_keys.py` on
how tokens are signed RS256 so verifiers never hold a key that can mint.

## Three kinds of versioning

**1. API contract — `api/v1/`.** Endpoints are exposed only as Werkzeug-based REST routes, e.g. `POST /api/v1/auth/login`. There is no `/api/method/` RPC alias.

A breaking change to the login or refresh contract ships as `api/v2/` alongside `v1`, letting consumers migrate on their own schedule.

Internals stay outside the version segment: `api/jwt_keys.py`, `api/router.py`, and `api/middleware.py` are not part of the client contract. Rotating a key must not require a new API version, and shipping `v2` must not force a re-keying.

**2. Signing keys — `kid`.** Keys are indexed by `kid` in `site_config.json`, so a leaked secret can be rotated with no downtime and no client change. Details in `api/jwt_keys.py`.

**3. Releases — git tags.** Consumers must pin a **tag**, never a branch.
`apps.json` entries take a git ref in the `branch` field, and `git clone --branch` accepts a tag:

```json
[{ "url": "https://github.com/<org>/oan_auth_service.git", "branch": "v0.1.0" }]
```

This matters because the deployments are independent. Pinning a moving branch means two products silently build different auth logic with nothing recording which — the exact failure this app exists to prevent. Tag releases here; bump the pin in each consumer as a deliberate, reviewable commit.

## REST API Endpoints & Werkzeug Routing

Public URLs drop the `/api` prefix: clients call `/v1/...` and the gateway rewrites it to
the `/api/v1/...` routes below. Every consuming app follows the same rule; see
[`docs/API_CONVENTIONS.md`](docs/API_CONVENTIONS.md).

The app includes a declarative Werkzeug REST Router (`oan_auth_service.api.router.Router`) that compiles routes directly into Frappe's `API_URL_MAP`.

### V1 Auth REST Endpoints

| Method | REST Path                       | Description                              | Access                   |
| ------ | ------------------------------- | ---------------------------------------- | ------------------------ |
| `POST` | `/api/v1/auth/register`         | Register new account (no tokens issued)  | Public / Guest           |
| `POST` | `/api/v1/auth/login`            | Authenticate & issue token pair          | Public / Guest           |
| `POST` | `/api/v1/auth/refresh`          | Rotate single-use refresh token          | Public / Guest           |
| `POST` | `/api/v1/auth/logout`           | Revoke active refresh token              | Public / Guest           |
| `POST` | `/api/v1/auth/password/forgot`  | Initiate password recovery (SMS / email) | Public / Guest           |
| `POST` | `/api/v1/auth/password/reset`   | Complete password reset                  | Public / Guest           |
| `POST` | `/api/v1/auth/password/initial` | Replace a temporary password             | Public / Guest           |
| `GET`  | `/api/v1/auth/me`               | Current user profile & JWT claims        | Authenticated (`Bearer`) |
| `GET`  | `/api/v1/auth/keys`             | Public signing key metadata & algorithm  | Public / Guest           |
| `GET`  | `/api/v1/auth/health`           | Health check endpoint                    | Public / Guest           |

### V1 Admin REST Endpoints

All require a bearer token for a user holding `System Manager` or `Administrator`. `{id}` is the user id only; find a user by email or phone with the list filters, so personal data never lands in access logs.

| Method   | REST Path                                     | Description                                                                                |
| -------- | --------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `GET`    | `/api/v1/admin/users`                         | List users (`search`, `email`, `phone_number`, `role`, `enabled`, `page`, `page_size`)     |
| `POST`   | `/api/v1/admin/users`                         | Onboard a user with a temporary password; `201` + `Location`, no tokens                    |
| `GET`    | `/api/v1/admin/users/{id}`                    | User details, roles and app profiles                                                       |
| `PATCH`  | `/api/v1/admin/users/{id}`                    | Change name, login email, mobile; `{"enabled": false}` disables and revokes refresh tokens |
| `DELETE` | `/api/v1/admin/users/{id}/sessions`           | Revoke every refresh token                                                                 |
| `POST`   | `/api/v1/admin/users/{id}/temporary-password` | Issue a temporary password (a generated one is returned once)                              |
| `GET`    | `/api/v1/admin/users/{id}/roles`              | List the user's roles                                                                      |
| `POST`   | `/api/v1/admin/users/{id}/roles`              | Grant roles (`{"roles": [...]}`)                                                           |
| `DELETE` | `/api/v1/admin/users/{id}/roles/{role}`       | Revoke a role                                                                              |
| `GET`    | `/api/v1/admin/roles`                         | List assignable roles                                                                      |

There is no `DELETE` on a user: hard deletion would orphan records consuming apps linked to it. The `Administrator` account and the caller's own account cannot be disabled or have roles changed. Only the `Administrator` user may grant the `Administrator` role. Roles of IAM-delegated accounts are refused, since IAM overwrites them at login.

### HTTPS Transport Security

Transport security can be strictly enforced across all REST endpoints by setting in `site_config.json`:

```json
{
  "jwt_enforce_https": true
}
```

When enabled, any plain HTTP request is rejected with `403 Forbidden` (`HTTPS_REQUIRED`). All HTTPS responses automatically include `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and `X-Request-Id` headers.

### Defining REST Routes in Consuming Apps

Consuming apps (such as `oan_grievance_service`) can use the Werkzeug router to expose REST APIs:

```python
from oan_auth_service.api import prefixed

route = prefixed("/api/v1/grievance")


@route("/submit", methods=("POST",))
def submit_grievance(**kwargs): ...


@route("/<grievance_id>", methods=("GET",))
def get_grievance(grievance_id: str): ...
```

## Consuming this app

In the consumer's `hooks.py`:

```python
required_apps = ["oan_auth_service"]
```

so bench installs this app first and the refresh-token doctype exists before the consumer migrates. The consumer then registers its API namespace and exempt paths with `api.middleware.register_namespace()`.

A consumer can add its own claims to every access token with the `on_access_token_claims` hook. The handler takes `user` and `roles` and returns a dict. It cannot override `iss`, `sub`, `iat`, `exp`, `typ`, `jti`, `roles` or `scope`.

```python
on_access_token_claims = ["my_app.auth.access_token_claims"]
```

## Delegated login through the OpenG2P IAM service

Staff can sign in through the OpenG2P IAM service instead of a local password. This app never talks to the identity provider behind IAM (Keycloak, eSignet, ...), so it does not care which one is used. The frontend runs IAM's login flow. Its server then forwards the access token as `Authorization: Bearer <token>`. The same middleware accepts it next to this app's own tokens, so consumers need no change.

- **Validation.** A token whose `iss` is not this site's issuer is sent to IAM's `GET /auth/get_user_profile`. If IAM rejects it, so do we. If IAM accepts it, it returns a provider-neutral principal (`sub`, `name`, `client_roles`). The principal is cached until the token's `exp`.
- **Identity.** The local user is `<sha256(sub)[:32]>@iam.internal` (valid for any `sub`, case-sensitive), created on first login with no password. `sub` never changes when the person's email or username does.
- **No password, ever.** Login, password reset and temporary-password flows refuse these accounts, so removing someone from the identity provider cannot leave a local way in.
- **Roles.** IAM is the only source of these users' roles. Their Frappe roles are set to exactly `client_roles[iam_application]` (names used as-is, roles that do not exist in Frappe ignored). There is no allowlist: whoever administers this app's client in IAM can grant any existing Frappe role, including `System Manager`. See "Known limits" in `docs/IAM_DELEGATED_LOGIN_PLAN.md`. IAM's answer is cached until the token's `exp`, so a role change in IAM applies when the user gets a new token, not on the next request.
- **Bearer or cookie.** `Authorization: Bearer <token>` is the primary path and the only one for mobile and server-to-server callers. A browser may instead send the access token in the `X-Access-Token` cookie and no Authorization header. Where the token comes from only decides whether CSRF applies; its `iss` alone decides how it is verified, so the cookie may carry an IAM token or one of this app's own. Then:
  - an expired token gets a `401`, the same as over Bearer. Refreshing is the client's job (through IAM for IAM tokens); this app never refreshes or sets cookies;
  - state-changing requests (anything but GET, HEAD, OPTIONS) must repeat the `X-CSRF-Token` cookie as an `X-CSRF-Token` header;
  - the browser must send IAM's cookies to this host (IAM's cookie `Domain` has to cover it) and the API must allow credentialed CORS for the frontend origin; neither is configured by this app;
  - cookie names are IAM's, with `iam_auth_cookie_prefix` applied the way iam_core applies `auth_cookie_prefix`. Set it to the same value as the IAM deployment whose cookies reach this app (its `common_auth_cookie_prefix`); the default `""` matches IAM's default. The `X-CSRF-Token` header is never prefixed.
- **IAM outage.** If IAM is unreachable, times out or answers 5xx, the request gets a `503`, not a `401`, so a frontend retries instead of logging the user out. The outage is logged once a minute, not once per request.
- **Expiry.** A Bearer access token keeps working until its `exp`, as it does in every OpenG2P service. Refreshing a Bearer token is the caller's job, through IAM. To cut someone off sooner, disable their local `User`.

`site_config.json`:

```json
"iam_base_url": "https://iam.example.org",
"iam_application": "oan-grievance",
"iam_auth_cookie_prefix": ""
```

`iam_base_url` must be `https`: bearer tokens are sent there, so a plain `http` URL is refused (`401`). `localhost`, `127.0.0.1` and `::1` are allowed over `http` for local development.

For a trusted in-cluster IAM reachable only over `http`, set `"iam_allow_insecure_http": true`. Tokens then cross the network unencrypted, so use it on a private network only. A rejected URL is logged once an hour in Error Log, not per request.

`iam_auth_cookie_prefix` is optional; leave it unset unless IAM sets `common_auth_cookie_prefix`.

## Development

All commands run from `development/frappe-bench-16/`.

```bash
bench --site <site> install-app oan_auth_service

bench run-tests --app oan_auth_service

# After changing doctype JSON or patches.txt
bench migrate

# After changing hooks.py or fixtures
bench clear-cache
```

Lint from the repo root:

```bash
ruff check oan_auth_service/
ruff format oan_auth_service/
```

After adding or changing a route, regenerate the API artifacts, in this order (from the bench root):

```bash
env/bin/python apps/oan_auth_service/openapi/generate_openapi_spec.py
(cd apps/oan_auth_service/kong && ../../../env/bin/python generate_kong_config_from_spec.py)
env/bin/python apps/oan_auth_service/postman/generate_postman_collection.py
```

The Kong and Postman generators refuse to run when a route in the spec has no throttling tier (`TIER_OVERRIDES`) or no place in the request flow (`REQUEST_ORDER`).
