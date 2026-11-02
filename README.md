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
| `POST`   | `/api/v1/admin/users`                         | Onboard a user with a temporary password; `201`, no tokens                                 |
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

so bench installs this app first and the refresh-token doctype exists before the consumer migrates. The consumer then registers its API namespace with `api.middleware.register_namespace()`.

Each path in a namespace accepts exactly one scheme, declared on the route (`@route(..., auth=...)`):

| `auth`            | Accepts                                                                                                     | Refuses                                                                                                                                       |
| ----------------- | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `"jwt"` (default) | Bearer JWT (this app's or an IAM token), or an IAM access cookie                                            | `token`/`Basic` credentials and desk `sid` sessions, so no other way in skips `revocation_check`, `must_change_password` or the `scope` check |
| `"api_key"`       | A session Frappe set from `Authorization: token <key>:<secret>`; with `roles=[...]`, its user must hold one | Bearer, cookies, `sid` sessions, no credentials                                                                                               |
| `"public"`        | Nothing required (`allow_guest=True` is the older spelling)                                                 | —                                                                                                                                             |

A path takes one scheme for all its methods. Paths may carry `<param>` segments. A consumer that declares routes with this app's `rest`/`prefixed` calls `api.router.register_declared_paths()` after importing its route modules; one that keeps its own router passes `exempt_paths` and `api_key_paths` to `register_namespace()`.

A consumer can add its own claims to every access token with the `on_access_token_claims` hook. The handler takes `user` and `roles` and returns a dict. It cannot override `iss`, `sub`, `iat`, `exp`, `typ`, `jti`, `roles` or `scope`.

```python
on_access_token_claims = ["my_app.auth.access_token_claims"]
```

## Delegated login through the OpenG2P IAM services

People can sign in through an OpenG2P IAM service (staff, agent, beneficiary portal) instead of a local password. This app never talks to the identity provider behind IAM (Keycloak, eSignet, ...) for login, so it does not care which one is used. The frontend asks this app which login options exist, starts one through this app, and after IAM's callback forwards the access token as `Authorization: Bearer <token>`. The same middleware accepts it next to this app's own tokens, so consumers need no change. Design: `docs/IAM_LOGIN_DISCOVERY_PLAN.md`; end-to-end sequence: `docs/IAM_LOGIN_DISCOVERY_FLOW.md`.

### Login options: the `OAN IAM Service` DocType

One row is one button on the login page. Rows are edited in desk by a System Manager (the only role with DocPerm), with `track_changes` on. Nothing about IAM is configured in `site_config.json`.

| Field                                    | Meaning                                                                                                                                                                                                                           |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `key`                                    | Sent by the frontend (`staff`, `agent`, `bene`). `[a-z0-9-]+`, cannot change after saving. `local` is reserved for this app's own username and password login and takes no other field                                            |
| `enabled`, `label`, `icon`, `sort_order` | What the login page shows. A disabled row is hidden, cannot start a login, and its tokens are refused. `icon` must be a public file                                                                                               |
| `base_url`                               | IAM API root as this server reaches it. `https`, or `http` to loopback only. There is no opt-out                                                                                                                                  |
| `provider_id`                            | Row id in that IAM's `login_providers` table                                                                                                                                                                                      |
| `issuer`                                 | Exact `iss` of that provider's tokens, including the trailing slash if any. Unique among enabled rows                                                                                                                             |
| `client_id`                              | Optional. When set, a token whose `azp` differs is refused                                                                                                                                                                        |
| `application`                            | Keycloak client id whose `client_roles` become Frappe roles. A wrong value is silent apart from an Error Log warning: tokens validate with no roles                                                                               |
| `default_roles`                          | Frappe roles every user of this row gets, whatever the token says (eSignet tokens carry no roles). Granted to anyone the provider authenticates, so `System Manager`, `Administrator`, `Guest`, `All` and `Desk User` are refused |
| `cookie_prefix`                          | That IAM's `auth_cookie_prefix`                                                                                                                                                                                                   |
| `return_origins`                         | Frontend origins (`https://ui.example.org`, no path) allowed as `return_url`. Empty refuses every login on the row                                                                                                                |

Each IAM row needs `application` or at least one default role. Rows are cached (`oan_auth:iam_services`) and the cache is cleared on save and delete.

### Endpoints

- `GET /api/v1/auth/iam/providers` (guest): enabled rows in `sort_order`, `key`, `label` and `icon_url` only. No IAM call. Key `local` means "show the password form" (`POST /api/v1/auth/login`).
- `POST /api/v1/auth/iam/login {key, return_url}` (guest): checks `return_url`'s origin against the row's `return_origins` (IAM does not check it, so this is the open-redirect guard), calls IAM's `start_authentication_transaction`, and returns `{redirect_url, iam, cookie_prefix}`. Unknown, disabled or `local` key, or a bad `return_url`: `400`, no IAM call. IAM answered unusably: `502`. IAM down: `503`.
- `POST /api/v1/auth/refresh` and `POST /api/v1/auth/logout` serve IAM sessions too. Send exactly one of `refresh_token` (this app's session, unchanged) or `access_token` (an IAM token, expired is fine, in the body because the middleware would refuse an expired Bearer). The token's `iss` picks the row, as in validation; the client sends no key. This app's own issuer: `400`. Unknown issuer: `401`, no IAM call. Forward the row's `<prefix>X-Access-Token`, `X-ID-Token` and `X-Session-Id` cookies and relay every `Set-Cookie` of the response:
  - refresh calls IAM's `get_user_profile`, which refreshes from its session cookie, and returns `{refreshed}`; `401` when the session is over (log the user out), `503` when IAM is down (keep the session);
  - logout calls IAM's `/auth/logout` and the provider's `end_session_endpoint` server-to-server, and returns `{logged_out, provider_logout}`, plus `logout_url` for the browser when the provider call failed.
- `GET /api/v1/auth/me` also returns `login_option` and `cookie_prefix` (`local` and `null` for this app's tokens). A user who signed in through another OpenG2P UI arrives with IAM cookies only: the UI forwards them to `/me` and stores the answer as if the user had clicked that option.

A UI using these endpoints needs no IAM URL. One that has not switched can keep calling IAM directly; nothing here breaks that.

### Token validation

- **Routing by issuer.** A token whose `iss` is not this site's issuer must match the `issuer` of an enabled row exactly, or it gets a `401` with no IAM call. IAM accepts any issuer in its own table and skips `aud`, so this match is what separates staff, agent and beneficiary tokens. If the row has `client_id`, the token's `azp` must equal it.
- **Validation.** The row's IAM checks the token at `GET {base_url}/auth/get_user_profile` and returns a provider-neutral principal (`sub`, `name`, `client_roles`). The principal is cached per row and token until the token's `exp`. The row lookup runs before the cache, so disabling a row cuts its tokens off on the next request.
- **Identity.** The local user is `<sha256(f"{key}:{sub}")[:32]>@iam.internal`, created on first login with no password. Two providers' `sub` values cannot collide.
- **No password, ever.** Login, password reset and temporary-password flows refuse these accounts, so removing someone from the identity provider cannot leave a local way in.
- **Roles.** The row is the only source of these users' roles: exactly `default_roles` plus `client_roles[application]`, limited to roles that exist in Frappe. There is no allowlist for token roles: whoever administers the client in Keycloak can grant any existing Frappe role, including `System Manager`. A role change applies with the user's next token.
- **Bearer or cookie.** `Authorization: Bearer <token>` is the primary path and the only one for mobile and server-to-server callers. A browser may instead send the access token in an IAM access cookie, `<cookie_prefix>X-Access-Token` of any enabled row, tried in `sort_order`; the first one found wins. Where the token comes from only decides whether CSRF applies; its `iss` alone decides how it is verified. Then:
  - an expired token gets a `401`, the same as over Bearer;
  - state-changing requests must repeat the same prefix's `X-CSRF-Token` cookie as an `X-CSRF-Token` header (the header is never prefixed);
  - the browser must send IAM's cookies to this host and the API must allow credentialed CORS for the frontend origin; neither is configured by this app.
- **IAM outage.** If IAM is unreachable, times out or answers 5xx, the request gets a `503`, not a `401`, so a frontend retries instead of logging the user out. The outage is logged once a minute, not once per request.
- **Expiry.** A Bearer access token keeps working until its `exp`, as it does in every OpenG2P service. To cut someone off sooner, disable their local `User` or the row.

### Consumer hook after delegated login

A consumer app can act on a delegated login (map a Keycloak claim to its own records, check a registry) with a hook in its `hooks.py`:

```python
oan_auth_on_delegated_login = ["my_app.auth.on_delegated_login"]


def on_delegated_login(user: str, principal: dict, login_option: str) -> bool:
    ...  # return True if it changed anything
```

- `user` is the local `User`, already created, enabled and role-synced; `principal` is IAM's answer as received (claims only in the access token); `login_option` is the row key.
- It runs once per token, not per request, in app install order. It must be idempotent: two workers can run it for the same token.
- Raise `oan_auth_service.api.iam_users.LoginDenied(reason)` to refuse the login: `403`, nothing committed. Any other exception is logged and refuses the request with `503`, and the hook runs again on the next request.
- On GET the middleware commits when a hook returns `True`; other methods follow Frappe's commit-on-success.
- `frappe.local.oan_auth_login_option` holds the row key for the rest of the request.

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
