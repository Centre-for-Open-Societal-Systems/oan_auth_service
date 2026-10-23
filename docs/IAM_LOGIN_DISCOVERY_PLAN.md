# IAM login discovery: design and implementation plan

Status: steps 1 to 10 and 12 implemented. The frontend (step 11) is not. See
"Implementation notes" at the end for where the code differs from this text.

How this app tells a frontend which login options exist, lets the user pick one,
and starts that login, without the frontend hardcoding any IAM URL or provider
id.

Builds on the delegated login in `IAM_DELEGATED_LOGIN_PLAN.md` and
`IAM_DELEGATED_LOGIN_FLOW.md`.

## Problem

Today one deployment knows one IAM:

- This app: `iam_base_url`, `iam_application`, `iam_auth_cookie_prefix` in
  `site_config.json` (`config/settings.py`). Every token with a foreign `iss`
  goes to that one IAM (`api/iam_tokens.py`).
- The UI (`oan_grievance_ui`): `IAM_BASE_URL` and `IAM_LOGIN_PROVIDER_ID` as
  server env. The "Sign in as staff" button exists only if `IAM_BASE_URL` is set.

OpenG2P runs one IAM API per portal: staff (`iam-staff-portal-api`), agent
(`iam-agent-portal-api`) and beneficiary (`iam-bene-portal-api`). Each has its
own hostname, its own Keycloak realm or identity provider, and its own
`GET /auth/get_login_providers`. To offer a second login, the UI needs new env,
new code and a redeploy, and this app cannot validate tokens from a second IAM
at all.

## How OpenG2P IAM behaves (facts this design depends on)

Read from `iam-service` branch `1.4` (`a073fa2`) and the `openg2p-iam-service`
chart. Details and sources: `openg2p-developer/docs/agent-portal-login-flow.md`
and `openg2p-developer/docs/agent-cross-service-token-checks.md`.

- **IAM does not issue tokens.** Keycloak or eSignet signs them. IAM runs the
  OIDC code flow, stores the refresh token in Redis and sets cookies.
- **IAM validates a token by its `iss` alone.** It looks `iss` up in its
  `login_providers` table, fetches that issuer's public keys (JWKS) and checks
  signature, `iss` and `exp`. The `aud` check runs only when the row has
  `audiences`, and both chart templates leave it empty.
- **Staff and agent IAM share one `login_providers` table** in the chart
  (`IAM_STAFF_DB_DBNAME` and `IAM_AGENT_DB_DBNAME` both use `global.iamDB`). So
  the staff IAM accepts agent tokens and the agent IAM accepts staff tokens.
  Bene is not in the chart; the local setup gives it its own `iam_bene` database.
- **`get_login_providers` returns every row** of the table. `iam_core` does not
  filter by `user_type`. On a shared table, the staff IAM and the agent IAM both
  list the staff and the agent provider.
- **`get_user_profile` checks the token, not the session.** It returns the
  principal from the verified JWT. A token stays valid until `exp` even after
  logout, because nothing checks the refresh token or the Keycloak session.
- **Refresh needs IAM's cookies.** IAM refreshes an expired access token only
  from its own session cookie (`<prefix>X-Session-Id`). A Bearer-only call
  cannot be refreshed.
- **Logout is a browser redirect.** `GET /auth/logout` deletes the refresh token,
  clears the cookies and 302s to the provider's `end_session_endpoint` with
  `id_token_hint`. The user then lands on the provider row's
  `default_redirect_uri`.
- **Cookies are prefixed per portal** (`IAM_<PORTAL>_AUTH_COOKIE_PREFIX`, for
  example `agent-`). All IAMs set cookies on one parent domain, so a browser
  logged in to two portals sends both sets. The prefix keeps them apart.
- **CSRF exclusions** on every IAM API include `/auth/get_login_providers`,
  `/auth/start_authentication_transaction`, `/auth/callback` and `/auth/logout`.
  The server-to-server calls below hit only those paths.
- **IAM does not validate `redirect_uri`** passed to
  `start_authentication_transaction`.

## Goals

- One list of login options, stored in this app's database and edited by a
  System Manager. One row is one button on the login page.
- One public endpoint that returns the enabled options.
- One endpoint that starts the chosen option. The frontend sends the row's key
  (`staff`, `agent`, `bene`); it never sees an IAM URL or a provider id.
- Tokens are accepted only from issuers listed on an enabled row, and are
  checked by that row's IAM.
- No backward compatibility. Delegated login is not deployed yet, so the old
  `iam_base_url`, `iam_application` and `iam_auth_cookie_prefix` keys are
  removed, not migrated.

## Non-goals

- Talking to the identity providers for login. IAM still owns OIDC.
- Single sign-on across IAMs.
- Backchannel logout (see "Refresh and logout").

## Design

### Where the list lives

A DocType, `OAN IAM Service`, **one row per login option**.

This follows Frappe's own convention. Frappe's login page (`frappe/www/login.py`)
reads enabled `Social Login Key` rows and shows one button per row.

Compared with site config, a DocType gives:

- adding or disabling a login without a redeploy or shell access;
- an audit trail (`track_changes`, Version records);
- validation when a row is saved, not when the first login fails.

One row per option, rather than one row per IAM with a list of providers,
because:

- the login page needs exactly that list, so this app does not need to call
  `get_login_providers` at all;
- a shared `login_providers` table makes two IAMs list the same providers, and
  a per-row `provider_id` removes the duplicates without an allow-list;
- each provider has exactly one issuer, so the issuer becomes a field, not a
  table.

The cost: label and icon live in this table instead of coming from IAM, and a
provider added in IAM does not appear until someone adds a row. Two rows on the
same IAM repeat its `base_url`, `application` and `cookie_prefix`.

No IAM setting stays in `site_config.json`. Everything is on the rows.

**`base_url` must be `https`, or loopback.** The `iam_allow_insecure_http`
opt-out is removed, so bearer tokens never cross the network unencrypted.
`base_url` is the address this server uses to reach IAM, not the one the browser
sees. Inside a cluster IAM is usually a plain `http` service (OpenG2P's own
registry reaches the staff IAM at `http://commons-services-iam-staff-portal-api`),
so such a deployment must call IAM through its public `https` hostname instead,
or put TLS on the in-cluster service.

**Return origins are per row.** IAM redirects the browser to whatever
`return_url` the login call carries, without checking it. Without a check,
anyone can call the guest `/iam/login` endpoint with
`return_url=https://evil.example`, send the resulting `redirect_url` to a victim,
and the victim logs in at the real identity provider and then lands on the
attacker's page, which can ask for the password again. Tokens are not exposed
(IAM keeps them in cookies), but this is an open redirect. Each row lists the
frontend origins allowed to start its login, so the agent login can be limited
to the agent UI and the staff login to the staff UI. A row with no origins
refuses every login (fail closed): an empty list must never mean "any origin".

### DocType `OAN IAM Service`

Module `OAN Auth`. Named by `key` (`autoname: field:key`). `track_changes: 1`.

| Field            | Type                                     | Rules                                                                                                                                                                         |
| ---------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `key`            | Data                                     | Required, unique, `[a-z0-9-]+`, `set_only_once`. Sent by the frontend (`staff`, `agent`, `bene`, `local`). `local` is reserved for this app's own username and password login |
| `enabled`        | Check                                    | Disabled rows are invisible to discovery, login and token validation                                                                                                          |
| `label`          | Data                                     | Required. Button text                                                                                                                                                         |
| `icon`           | Attach Image                             | Optional. Must be a public file, because the providers endpoint is public                                                                                                     |
| `sort_order`     | Int                                      | Order of the buttons                                                                                                                                                          |
| `base_url`       | Data                                     | Not on `local`, required. IAM API as this server reaches it. `https`, or loopback                                                                                             |
| `provider_id`    | Int                                      | Not on `local`, required. The row id in that IAM's `login_providers` (staff `1`, agent `10` in the chart)                                                                     |
| `issuer`         | Data                                     | Not on `local`, required. Exact `iss` of tokens from this provider                                                                                                            |
| `client_id`      | Data                                     | Not on `local`, optional. When set, a token whose `azp` differs is refused                                                                                                    |
| `application`    | Data                                     | Not on `local`, optional. Keycloak client id whose roles become Frappe roles (`resource_access[application]`)                                                                 |
| `default_roles`  | Table MultiSelect `OAN IAM Service Role` | Not on `local`, optional. Frappe roles every user from this row gets, whatever the token says                                                                                 |
| `cookie_prefix`  | Data                                     | Not on `local`. That IAM's `auth_cookie_prefix`. Default empty                                                                                                                |
| `return_origins` | Small Text, one origin per line          | Not on `local`. Frontend origins allowed as `return_url`. Empty: every login on this row is refused                                                                           |

Child `OAN IAM Service Role`: `role` (Link `Role`, required).

`return_origins` lines: scheme, host
and optional port only, for example `https://grievance.example.org`. No path,
no trailing slash.

`issuer` must match the token exactly, including scheme, host and trailing
slash. Copy it from a real token or from IAM's `login_providers.issuer` column.
The IAM chart has separate internal and external issuer URLs
(`agentKeycloakIssuerUrl`, `agentKeycloakExternalIssuerUrl`); tokens carry the
external one.

`application` must equal the Keycloak client id the roles are assigned under. A
mismatch is silent: the token validates and carries no roles.

#### Roles for providers without roles (eSignet)

eSignet authenticates a person against the national ID system. Its tokens carry
identity (`sub`, and claims such as name or phone), never roles: there is no
`resource_access`. So `application` cannot give a farmer any role.

`default_roles` covers this. A user's Frappe roles are:

```
default_roles  ∪  (token roles under application, if application is set)
```

restricted, as today, to roles that exist in Frappe. For the `bene` row:
`application` empty, `default_roles = [Farmer]` (or whatever beneficiary role
the apps define). For the `staff` row: `application` set, `default_roles`
usually empty. `sync_roles` keeps setting the user's roles to exactly this set,
so removing a default role from the row removes it from users on their next
token.

`default_roles` is granted to **anyone the provider authenticates**. For eSignet
that is every resident with a national ID, not only registered farmers.
Therefore:

- a default role must carry only what any authenticated resident may do (file
  and track their own grievances, for example);
- `validate()` refuses `System Manager`, `Administrator`, `Guest`, `All`,
  `Desk User` and this app's own service roles as default roles;
- "is this person a registered farmer" is a separate check: a lookup of the
  person in the Farmer Registry at login. Not part of this plan (see Open
  questions).

No secrets are stored, so no `Password` field. IAM holds the client secrets.

DocPerm: `System Manager` only (read, write, create, delete). The app's own
roles get nothing.

`validate()`:

- `key` format;
- `local` row: every IAM field empty;
- every other row: `base_url`, `provider_id` and `issuer` set; `base_url` is
  `https` or loopback, with no path, query or fragment beyond the IAM API root;
- every other row: `application` or at least one `default_roles` entry, else
  its users would get no roles;
- `default_roles` contains none of the refused roles above;
- each `return_origins` entry is an origin only (scheme, host, optional port),
  `https` or loopback; an enabled non-`local` row with no origins saves with a
  warning, because its logins will be refused;
- an `issuer` belongs to only one enabled row.

`on_update` / `on_trash`: clear the cached list (`oan_auth:iam_services`).

Optional save-time check, as a warning that does not block the save:
`GET {base_url}/auth/get_login_providers` and confirm `provider_id` is in the
response. This catches a wrong `base_url` or id before the first login.

### Reading the rows

`config/settings.py` keeps its role as the one place that resolves settings:

- `iam_services()`: enabled rows ordered by `sort_order`, cached in Frappe cache
  until a row changes. `frappe.get_all` is fine here: `OAN IAM Service` is not
  bank-scoped.
- `iam_service(key)` and `iam_service_for_issuer(iss)`.

### Endpoints

Both are guest routes under `/api/v1/auth`, so the router adds them to the
exempt paths and the OpenAPI spec.

#### `GET /api/v1/auth/iam/providers`

Lists every enabled row, from the database only. No IAM call, so an IAM outage
does not hide buttons; it makes that button's login fail with `503`.

```json
{
  "status": "success",
  "data": {
    "providers": [
      { "key": "local", "label": "Sign in", "icon_url": "" },
      {
        "key": "staff",
        "label": "Sign in with Staff SSO",
        "icon_url": "/files/staff.png"
      },
      { "key": "agent", "label": "Sign in as field agent", "icon_url": "" },
      { "key": "bene", "label": "Login with eSignet", "icon_url": "" }
    ]
  }
}
```

- Only display fields are returned. Never `base_url`, `provider_id`, `issuer`,
  `client_id`, `application`, `default_roles` or `return_origins`.
- No enabled rows: `200` with an empty list.
- The `local` entry means "show the username and password form", which posts to
  the existing `POST /api/v1/auth/login`. No other key gets a form.

#### `POST /api/v1/auth/iam/login`

Starts the chosen login.

Body: `{"key": "staff", "return_url": "https://grievance.example.org/api/auth/staff/complete?returnUrl=/inbox"}`

1. Look up `key`. Unknown, disabled or `local` row: `400`. Do not call IAM.
2. `return_url` must be absolute and its origin must be in the row's
   `return_origins`, else `400`. A row with no origins refuses every login. IAM
   redirects to `return_url` unchecked, so this check is the open-redirect
   guard.
3. Server-to-server
   `POST {base_url}/auth/start_authentication_transaction?id=<provider_id>&redirect_uri=<return_url>`
   (5 s timeout, no redirects).
4. Accept only an `http`/`https` `redirectUrl` from IAM. Return
   `{"redirect_url": "...", "iam": "staff", "cookie_prefix": ""}`. IAM `4xx`:
   `502`. IAM unreachable, timed out or `5xx`: `503`.

`cookie_prefix` is returned because the UI must read the token from
`<cookie_prefix>X-Access-Token` after the callback, and a browser logged in to
two options holds two sets of IAM cookies. It is not secret.

The frontend then does `window.location = redirect_url`. The browser follows the
identity provider and IAM callback exactly as in `IAM_DELEGATED_LOGIN_FLOW.md`
phases 2 and 3.

`POST` returning JSON, not a `303`: one call shape works for a SPA, a Next.js
route handler and a mobile web view, and the frontend can show an error without
leaving the page.

### Why this app proxies the start call

The frontend could call each IAM's `start_authentication_transaction` itself.
Proxying is chosen because:

- the frontend would need every IAM's public URL and provider id, which is the
  hardcoding this removes;
- IAM does not validate `redirect_uri`, so one server-side allow-list here is
  safer than trusting every frontend to build it correctly;
- IAM has no CORS middleware, so a browser call would also need CORS for every
  frontend origin.

The callback is not proxied. Each IAM keeps `oauth_callback_url` pointing at its
own `/auth/callback`, and that IAM sets the session cookies on the parent
domain.

### Validating tokens from several IAMs

`api/iam_tokens.get_principal` changes from "the one IAM" to "the row for this
issuer". The issuer match is **strict**: IAM accepts any issuer in its own table
(no `aud` check, shared table), so this app's `issuer` field is the only thing
that decides which tokens are accepted.

1. `peek_issuer(token)` as today.
2. `iss == settings.issuer()`: own token, unchanged.
3. Otherwise `iam_service_for_issuer(iss)`. No match: `401`, no IAM call.
4. If the row has `client_id`, read `azp` from the unverified payload. Mismatch:
   `401`, no IAM call. Reading it unverified is safe because IAM verifies the
   same token in the next step and the request fails if it does not.
5. `GET {base_url}/auth/get_user_profile` on that row's IAM, same rules as today.
6. Cache key gains the row key: `oan_auth:iam_principal:{key}:{sha256(token)}`.
   TTL stays "until `exp`" (`_seconds_until_expiry`). This adds no revocation
   lag beyond IAM's own, because IAM also accepts the token until `exp`.
7. Return the principal with the row key attached, so provisioning reads that
   row's `application`.
8. If `application` is set and the principal has no roles under it, log a
   warning naming the row. This is the silent misconfiguration described above.
   A row that relies on `default_roles` alone (eSignet) does not warn.

Do the issuer lookup before reading the principal cache. Then disabling a row
cuts off that row's tokens on the next request, cached principals included, and
the principal cache needs no clearing.

Cookie path in `api/middleware.py`: try each enabled row's `cookie_prefix` in
`sort_order` and use the first `X-Access-Token` found. A browser logged in to
two portals sends both, and the first one wins. Routing still uses that token's
`iss`, so the wrong IAM is never asked, but the user may be treated as the
other portal's identity. Bearer remains the recommended path, and
`cookie_prefix` should be unique per IAM.

### Identity

The local user becomes `sha256(f"{key}:{sub}")[:32]@iam.internal` (today it is
`sha256(sub)[:32]`). The `sub` values of two identity providers can collide, so
the row key joins the hash. Nothing is deployed yet, so no existing user names
need to be kept.

This is why `key` is `set_only_once`: a renamed key would create new local
users. To replace a login, add a new row and disable the old one.

Two rows on the same IAM and issuer are not possible (issuer is unique among
enabled rows), so one identity never gets two local users through two buttons.

### Consumer hook after delegated login

Consumer apps need to act on a login beyond roles. Examples: turn a Keycloak
attribute into the user's records in the app (an office, a region, a desk), or
check that an eSignet user is in a registry before letting them in. Roles alone
cannot express this, and this app must not learn each consumer's data format.

So this app exposes one hook and forwards the principal. It never interprets
consumer claims.

**Registration.** A Frappe hook in the consumer app's `hooks.py`:

```python
oan_auth_on_delegated_login = ["my_app.auth.on_delegated_login"]
```

A `hooks.py` entry rather than a `register_namespace` argument: namespaces are
per URL prefix, while a user is provisioned once for all of them, so a
consumer's data must be current whichever API the user calls first. Every
installed app's hook runs, in app install order.

**Signature.**

```python
def on_delegated_login(user: str, principal: dict, login_option: str) -> bool:
    ...  # return True if it changed anything, so the middleware commits
```

- `user`: the local `User`, already created, enabled and role-synced.
- `principal`: IAM's `get_user_profile` answer, as received. IAM builds it from
  the access token's claims (`AuthPrincipal` allows extra fields), so a custom
  Keycloak claim arrives here if a protocol mapper adds it **to the access
  token**. This app calls IAM with the Bearer token only, so claims that are
  only in the ID token or userinfo never arrive. Check with a real token before
  relying on a claim.
- `login_option`: the row key (`staff`, `agent`, `bene`), so one hook can treat
  each login differently.

**When it runs.** `_provision_delegated_user` runs on every request, but the
hook runs **once per token**: only while no
`oan_auth:login_hook_done:{key}:{sha256(token)}` cache entry exists. After the
hooks succeed, that key is set with the same TTL as the principal (until
`exp`). So:

- a hook that fails runs again on the next request, instead of being skipped
  by the principal cache;
- a change in Keycloak reaches the consumer with the user's next token, the
  same lag as roles;
- a hook must be idempotent: two workers can run it for the same token at the
  same time.

**Denying.** A hook raises `oan_auth_service.api.iam_users.LoginDenied(reason)`
to refuse the login: `403` with that reason, nothing committed, done-key not
set. Any other exception is logged to Error Log and also refuses the request
(`503`), never grants it. A broken hook must not let a user in without the
checks it exists for.

**Transactions.** Same rules as role sync: on safe methods the middleware
commits when a hook returns `True`; on unsafe methods Frappe commits on success
and rolls back on failure.

**What consumers must handle themselves.**

- Data a hook writes from claims has Keycloak as its source of truth. The
  consumer must block manual edits of that data for delegated users, the way
  `api/v1/admin.py` blocks role edits.
- A claim removed in Keycloak must remove the consumer's records on the next
  token, not leave them behind. The hook sees the full current claim each time.
- Parse claims against a strict allowlist and refuse unknown values with
  `LoginDenied`. Never guess.
- Large claims make the access token large. Browsers drop cookies over about
  4 KB, which shows up in the UI as a missing access token cookie next to a
  present ID token cookie.

**When not to use it.** A check that needs no stored state can read
`frappe.local.oan_auth_claims` (set by the middleware on every request: `sub`, `name`
and `client_roles` only) in the consumer's own code. The person's other details reach
the consumer once per token, as the principal passed to its `oan_auth_on_delegated_login`
hook; store what is needed there. The cost: nothing is persisted, so every query that
depends on the claim must read it again.

### Refresh and logout

#### Refresh

This app only sees the Bearer token, so it cannot refresh: IAM refreshes from
its own session cookie. When the access token expires, the client must call the
issuing IAM with that IAM's cookies. `get_user_profile` on IAM refreshes and
returns new `Set-Cookie` headers.

That needs either the IAM's public URL in the frontend, or a proxy here. This
app proxies it inside its own `POST /api/v1/auth/refresh`, which serves both
kinds of session (see "One refresh, one logout" below). With
`{"access_token": "<IAM token>"}` it forwards the request's cookies of that
token's login option (only `<cookie_prefix>X-Access-Token`, `X-Session-Id` and
`X-ID-Token`) to `{base_url}/auth/get_user_profile` and relays IAM's
`Set-Cookie` headers unchanged. IAM already sets them on the shared parent
domain.

- IAM `200`: `{"refreshed": true}` when IAM set a new access cookie, `false`
  when the current token was still valid.
- IAM `401`/`403`: `401`, with any cookie-clearing headers relayed. The session
  is over; the UI logs the user out.
- No `<cookie_prefix>X-Session-Id` cookie: `401` without an IAM call.
- IAM down: `503`, keep the session. Other IAM `4xx`: `502`.

#### Logout

`POST /api/v1/auth/logout {"access_token": "<IAM token>"}`. This app does what
the browser redirect would do, so the user stays on the page:

1. Find the row by the token's issuer (same rule as the middleware).
2. `GET {base_url}/auth/logout` with the request's cookies and redirects off.
   IAM deletes the refresh token and answers `302` with `Set-Cookie` headers
   that clear its cookies.
3. Relay those `Set-Cookie` headers to the browser. Without this the browser
   keeps IAM's cookies.
4. Call the `Location` IAM returned (the provider's `end_session_endpoint` with
   `id_token_hint`) server-to-server, redirects off. This ends the Keycloak
   session. Without it the next login skips the password prompt.
5. Return `{"logged_out": true, "provider_logout": true}`.

If step 4 fails, return `{"logged_out": true, "provider_logout": false, "logout_url": "<Location>"}` and let the frontend send the browser there as a
fallback. If step 2 returns `401` (token expired and refresh failed), still
clear this app's state and return `logged_out: true`.

To verify before relying on step 4: that Keycloak ends the session from
`id_token_hint` without the browser's Keycloak cookie. If it does not, the
fallback is the only complete logout, and the endpoint should always return
`logout_url`.

#### One refresh, one logout

`POST /api/v1/auth/refresh` and `POST /api/v1/auth/logout` serve both kinds of
session. The body carries exactly one credential:

```
refresh_token   → this app's session: rotate or revoke, as before
access_token    → read its unverified iss:
                    this app's issuer      → 400, use refresh_token
                    an enabled row's issuer → that row's IAM, with that row's cookies
                    (and azp == client_id when the row sets one)
                    anything else          → 401, no IAM call
```

The client sends no `key`: the issuer decides, by the same rule the middleware
uses to validate. With two portals logged in, the token picks its own IAM and
cookies, so the first-prefix-wins ambiguity of the cookie path does not arise.
Routing costs an unverified base64 decode and a lookup in the cached rows.
Reading `iss` from an unverified, possibly expired token is safe here: a forged
`iss` only chooses which configured IAM receives the caller's own cookies, and
that IAM checks the session.

The IAM token travels in the body, not as `Authorization: Bearer`. The
middleware validates a Bearer token even on guest routes, and the token is
usually expired when these are called, so it would be refused first. Both are
guest routes for the same reason.

#### Backchannel logout

Not needed. IAM's backchannel logout only deletes the refresh token in Redis;
the access token stays valid until `exp` either way. It matters only for
logouts this app did not start (an admin ends the session in Keycloak, SSO
logout elsewhere). The agent IAM does not implement it.

Clearing local state in the frontend is not a logout. Without the IAM call the
refresh token stays in Redis (chart default TTL 2100 s) and the Keycloak session
stays open.

## Sessions across OpenG2P services

The Keycloak access token is the session, not anything this app issues. A user
may sign in through an OpenG2P UI (the registry UI, the agent UI) or through an
OAN UI, and either UI must then be able to call both the registry APIs and this
app's APIs with the same token. The registry accepts only Keycloak tokens it can
validate against IAM's provider table, so a token minted here would not work
there. This app is therefore one more relying service, like the registry API:

|                          | Registry API                              | This app                                         |
| ------------------------ | ----------------------------------------- | ------------------------------------------------ |
| Accepts                  | Keycloak token, Bearer or prefixed cookie | Same                                             |
| Issuer from              | Staff IAM's provider table                | `OAN IAM Service` rows                           |
| Roles                    | `resource_access[<its client>]`           | `client_roles[application]` plus `default_roles` |
| Session, refresh, logout | IAM                                       | IAM, proxied here                                |

Consequences:

- A user signed in elsewhere reaches an OAN UI with IAM cookies only, and no
  `login_option`. The UI forwards its cookies to `GET /api/v1/auth/me`; the
  middleware finds the session by trying each row's cookie prefix, and `/me`
  answers `login_option` and `cookie_prefix`. The UI stores them as if the user
  had clicked that option's button.
- An OAN UI calls registry APIs directly with the same Keycloak token. It needs
  the registry's URL (its own config), not IAM's.
- Logout ends the IAM and Keycloak session, so it signs the user out of the
  other OpenG2P UIs too. That is SSO working as intended.
- Users of this app's own password login have no Keycloak token and cannot call
  registry APIs.

## Frontend flow

See `IAM_LOGIN_UI_INTEGRATION_PLAN.md` for the UI side: the routes to build, the
session cookie the UI keeps (`key` and `cookie_prefix`), why roles come from
`GET /api/v1/auth/me` and not from the token, refresh, logout, and a security
checklist. The end-to-end sequence is in `IAM_LOGIN_DISCOVERY_FLOW.md`.

## Security

- **The rows are trust configuration.** This app sends users' bearer tokens to
  `base_url`, `issuer` decides which tokens are accepted, `application` and
  `default_roles` decide which roles are granted, and `return_origins` decides
  where the browser may be sent after login. Whoever can write `OAN IAM Service` can
  receive real tokens or grant any Frappe role. Therefore:
  - DocPerm is System Manager only, and the app's service roles never get any;
  - the admin API (`api/v1/admin.py`) must never list or edit this DocType's
    permissions. Today it scopes doctypes by name prefix (`_in_scope`), so a
    deployment with `service_prefix: "OAN"` would bring `OAN IAM Service` into
    scope. Add an explicit exclusion of every doctype in module `OAN Auth` to
    `_in_scope` for doctypes;
  - `track_changes` records every edit; Error Log records rejected saves.
- **Issuer match is strict.** IAM does not separate portals: with an empty
  `audiences` and a shared table, the staff IAM accepts agent tokens and the
  reverse. Routing by `iss` here is the separation. A forged `iss` only picks
  which IAM rejects the token, and an unknown `iss` never reaches an IAM.
- `client_id` adds a second check where IAM has none. Leave it empty for
  providers whose tokens carry no `azp` (check eSignet tokens before setting it).
- The providers endpoint is public. It returns display fields only.
- `return_url` is checked against the row's `return_origins`, and an empty list
  refuses the login. Never derive the allow-list from the request (`Host`,
  `Origin`).
- `base_url` is `https` or loopback, with no opt-out, so bearer tokens are never
  sent over plain `http`.
- `default_roles` go to anyone the provider authenticates. For eSignet that is
  every resident with a national ID, so default roles stay low-privilege and the
  privileged roles listed above are refused on save.
- Unknown keys are refused before any IAM call, so the login endpoint cannot be
  used to reach arbitrary URLs.
- Two rows with the same `application` can both grant the same Frappe roles. The
  existing "no role allowlist" limit applies per row.
- Rate limits: `/iam/providers` and `/iam/login` are unauthenticated, and
  `/iam/login` causes one IAM call per request.

## Gateway

Add to `AUTH_TIER_OVERRIDES` in `gateway_apisix.py`, or generation refuses the
new spec routes:

| Route                        | Tier               |
| ---------------------------- | ------------------ |
| `GET /v1/auth/iam/providers` | `auth-public-read` |
| `POST /v1/auth/iam/login`    | `auth-credentials` |

## Implementation steps

1. **DocType** (`oan_auth/doctype/`): `OAN IAM Service` with the `validate`,
   `on_update` and `on_trash` above. `bench migrate`.
2. **Settings** (`config/settings.py`): `iam_services()`, `iam_service(key)`,
   `iam_service_for_issuer(iss)`. Remove `iam_base_url()`, `iam_application()`,
   `iam_auth_cookie_prefix()` and `iam_allow_insecure_http()`, and their keys
   from `site_config.json`, `README.md` and `IAM_DELEGATED_LOGIN_FLOW.md`.
   `_require_https` keeps only `https` and loopback; drop its
   `iam_allow_insecure_http` test in `test_iam_delegated_login.py`.
3. **IAM client** (`api/iam_tokens.py`): take a row instead of reading
   `iam_base_url`. Add `start_login(row, return_url)` and `logout(row, cookies)`
   with the same timeout, https and outage-logging rules as `get_principal`.
   `cookie_name` takes the row's prefix.
4. **Endpoints** (`api/v1/auth.py`): `iam_providers` and `iam_login` with
   `@route(...)`, `@validate_request`, `@handle_api_errors`, `allow_guest=True`;
   `refresh` and `logout` take `access_token` and route it by issuer.
5. **Token routing** (`api/middleware.py`, `api/iam_tokens.py`): strict issuer
   lookup, `azp` check, new cache key, cookie prefixes, missing-roles warning.
6. **Provisioning** (`api/iam_users.py`): user name and roles take the row
   (identity hash with the row key; roles are `default_roles` plus the token's
   roles under `application`).
7. **Login hook** (`api/middleware.py`, `api/iam_users.py`): run every
   `oan_auth_on_delegated_login` hook once per token after role sync, with the
   done-key, `LoginDenied` and commit rules above.
8. **Admin guard** (`api/v1/admin.py`): exclude module `OAN Auth` doctypes.
9. **Gateway**: tier overrides above; regenerate gateway config.
10. **Spec and docs**: regenerate `openapi/` and `postman/`; update the
    "Delegated login" section of `README.md`, `API_DOCUMENTATION.md` and the
    config table in `IAM_DELEGATED_LOGIN_FLOW.md`.
11. **Frontend** (each UI, separate repo): follow
    `IAM_LOGIN_UI_INTEGRATION_PLAN.md`.
12. **Refresh proxy**: IAM sessions refresh through `POST /api/v1/auth/refresh`
    with `access_token`, routed by issuer.

Steps 1 to 10 and 12 ship in one PR. Step 11 follows, per UI. A UI that has
not switched keeps refreshing against IAM directly, which still works.

## Tests

In `tests/test_iam_delegated_login.py` (IAM calls mocked, as today), plus a new
`tests/test_iam_service.py` for the DocType:

- DocType: bad `key`; non-`local` row missing `base_url`, `provider_id` or
  `issuer`; non-`local` row with neither `application` nor `default_roles`;
  `System Manager` (or another refused role) in `default_roles`; `local` row with
  IAM fields; plain `http` `base_url`, with no opt-out; an origin with a path;
  issuer on two enabled rows are refused. A row with no `return_origins` saves
  with a warning. `key` cannot change after
  insert. Saving or deleting a row clears the cache. Only System Manager can
  write.
- Providers: enabled rows in `sort_order`; disabled rows hidden; no hidden field
  leaks; no IAM call is made.
- Login: valid key returns IAM's `redirectUrl`; unknown, disabled or `local` key
  gives `400` with no IAM call; `return_url` off the row's origins, relative,
  or on a row with no origins gives `400`; non-http `redirectUrl` from IAM is refused; IAM `5xx` gives `503`.
- Validation: token routed to the row whose `issuer` matches; unknown `iss`
  gives `401` without an IAM call; disabled row's tokens
  give `401`, cached principals included; `azp` mismatch gives `401` without an
  IAM call; per-row `application` decides the token roles; `default_roles` are
  granted with no roles in the token (eSignet); removing a default role removes
  it on the next token; `application` set but no roles logs the warning;
  same `sub` from two rows gives two local users.
- Logout: cookies forwarded; IAM `Set-Cookie` relayed; `end_session_endpoint`
  called; its failure returns `logout_url`; IAM `401` still returns
  `logged_out: true`.
- Login hook: runs once per token, not on every request; runs again after a
  failure; receives the row key and the full principal; `LoginDenied` gives
  `403` and commits nothing; another exception gives `503`, is logged and
  grants nothing; returning `True` on a GET commits; two installed hooks both
  run.
- Admin: `OAN IAM Service` stays out of admin permission endpoints even with
  `service_prefix: "OAN"`.
- Gateway: `test_gateway_apisix.py` passes with the new tier overrides.

## Open questions

- Should a frontend be able to ask for a subset (for example
  `GET /iam/providers?keys=staff,local`), or does every frontend of one
  deployment show the same list?
- Does Keycloak end the session from a server-side `end_session_endpoint` call
  with `id_token_hint` (logout step 4)? Test before choosing it over the browser
  redirect.
- Do eSignet tokens carry `azp`? Decides whether `client_id` can be set on the
  `bene` row.
- Should the `bene` login check that the person is a registered farmer (a
  Farmer Registry lookup by the eSignet identity) before granting the farmer
  role? Without it, every resident who passes eSignet gets `default_roles`.

## Implementation notes

Where the shipped code differs from the design above, and why:

- **No `/iam/logout` or `/iam/refresh`.** IAM sessions use the existing
  `/auth/logout` and `/auth/refresh`, routed by the token's issuer, not by a
  `key` from the client (see "One refresh, one logout"). Both are guest routes:
  they must work when the access token has expired. They read only the row's
  own IAM cookies and call only that row's IAM, so they grant nothing. Cost: a
  cross-site page can trigger a logout (logout CSRF).
- **Expired tokens are refused locally.** `get_principal` reads the unverified
  `exp` and refuses an expired token without calling IAM. Browsers keep sending
  expired cookies, and each used to cost an IAM call.
- **`GET /me` returns `login_option` and `cookie_prefix`** (`local` and `null`
  for this app's tokens). See "Sessions across OpenG2P services".
- **The row is passed, not attached to the principal.** `get_principal` takes
  the row and returns IAM's principal unchanged, so login hooks receive it "as
  received". The middleware passes the row to provisioning and sets
  `frappe.local.oan_auth_login_option` to its key.
- **Refused default roles** are `System Manager`, `Administrator`, `Guest`,
  `All` and `Desk User`. This app defines no service roles of its own, so
  there are none to add.
- **The save-time `get_login_providers` check** is not implemented. It was
  optional, and a network call inside `validate()` makes saves and tests
  depend on IAM being up.
- **Changing `key`** is dropped rather than refused: Frappe syncs an autoname
  field back to `name` before `set_only_once` runs. Either way it never
  changes.
- **IAM `4xx` and malformed answers** on login and logout are `502`
  (`BAD_GATEWAY`, added to the error vocabulary). The endpoints return these
  and `503` as envelopes rather than raising, so a guest cannot fill Error Log:
  each failure kind is logged once a minute.
- **Hook failures** are logged with `defer_insert`, because the refused
  request is rolled back and an inserted Error Log row would go with it.
- **Kong and Postman.** The generators also needed tiers and request order for
  the admin `/permissions` routes, which were missing before this change.
