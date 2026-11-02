# UI integration plan for IAM login discovery

Status: proposal. Not implemented.

How a service UI adds the login options of this app (`oan_auth_service`) to its
own login page: staff, agent and beneficiary logins through the OpenG2P IAM
services, next to the local username and password login.

Generic: applies to any UI that uses this app for authentication. The server
side of this design is `IAM_LOGIN_DISCOVERY_PLAN.md`; the end-to-end sequence is
`IAM_LOGIN_DISCOVERY_FLOW.md`.

## What the UI needs

- **A server-side part.** IAM puts the tokens in `HttpOnly` cookies, which page
  JavaScript cannot read. Something on the server (Next.js route handlers, a
  BFF, an edge function) must read them and send `Authorization: Bearer`. A
  UI that is only static files in the browser cannot do this login.
- **Same parent domain as IAM.** IAM sets its cookies on a parent domain (for
  example `.example.org`). The UI must be served under it, or the browser never
  sends IAM's cookies to the UI.
- **One URL in config:** this app's API base URL. No IAM URL, no provider id,
  no application name.
- **Its origin registered** in `return_origins` on every `OAN IAM Service` row
  it offers (for example `https://ui.example.org`). Done by a System Manager in
  this app, not in the UI.

## Why the UI needs the cookie prefix

IAM never hands the token to the UI directly. After login it sets three cookies
on the parent domain and redirects the browser to the UI:

- `<prefix>X-Access-Token`
- `<prefix>X-ID-Token`
- `<prefix>X-Session-Id`

Each IAM has its own prefix (empty for staff, `agent-` for agent, for example),
so a browser logged in to two options holds two sets. To send the right token,
the UI must know which name to read. The prefix is not secret; this app returns
it in the login response.

The alternative, forwarding all browser cookies to this app and letting it
pick, is not used: forwarding browser cookies to the API turns every API call
into a cookie-authenticated request and needs CSRF protection on all of them.
Bearer keeps API calls safe from CSRF.

## Session state the UI keeps

One `HttpOnly`, `Secure`, `SameSite=Lax` cookie on the UI's own origin, for
example `login_option`:

```json
{ "key": "agent", "cookie_prefix": "agent-" }
```

The UI needs it on every later request:

| Use                   | Needs                                                             |
| --------------------- | ----------------------------------------------------------------- |
| Find the access token | `cookie_prefix`                                                   |
| Refresh               | `cookie_prefix` (to find the token and forward the right cookies) |
| Logout                | `cookie_prefix`                                                   |

Refresh and logout send the token itself; this app picks the option from its
`iss`, so the UI never sends `key`. A session the UI did not start (the user
signed in through another OpenG2P UI) has no `login_option`: forward the
browser's cookies to `GET {API}/api/v1/auth/me`, which answers `login_option`
and `cookie_prefix`, and store those.

Set it in the login start route (step 2 below), before the browser leaves for
the identity provider. Clear it on logout and when the session ends.

## Routes to build

All are server-side routes of the UI. The browser only talks to these and to
the identity provider.

### 1. Login page

- `GET {API}/api/v1/auth/iam/providers`. Cache briefly (60 s) on the UI server
  if wanted.
- One button per entry: `label`, `icon_url`, in the order returned.
- `key == "local"`: show the existing username and password form instead of a
  button. No `local` entry: no form.
- Empty list: show a "no sign-in method configured" message.
- Each button is a **link** (page navigation) to the UI's login start route,
  not a `fetch`. The browser has to follow the identity provider's redirects.

### 2. Login start: `GET /auth/iam/login?key=<key>&returnUrl=<path>`

1. Rate limit per client.
2. Sanitise `returnUrl` to a same-origin path (no scheme, no `//`, no
   backslash). Default to the home route.
3. Build the landing URL, absolute, on the UI's own origin:
   `https://<ui>/auth/iam/complete?returnUrl=<path>`. It must be absolute
   because IAM redirects to it as given.
4. `POST {API}/api/v1/auth/iam/login {key, return_url: <landing URL>}`.
5. On `200 {redirect_url, iam, cookie_prefix}`: accept only an `https`
   `redirect_url` (or `http` on localhost in development), set the
   `login_option` cookie, answer `303` to `redirect_url`.
6. On error, back to the login page with a reason:

| This app answers | Meaning                                                                        | UI shows                                                                    |
| ---------------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| `400`            | Unknown or disabled key, or the UI origin is not in the row's `return_origins` | "This sign-in method is not available." Log it: it is a configuration error |
| `502`            | IAM refused the request                                                        | "Sign-in failed, try again."                                                |
| `503`            | IAM unreachable                                                                | "Sign-in is temporarily unavailable."                                       |

### 3. Landing: `GET /auth/iam/complete?returnUrl=<path>`

1. Read `login_option`. Missing: back to login with `login_failed`.
2. Read `<cookie_prefix>X-Access-Token`. Missing: back to login with
   `login_failed`. If `<cookie_prefix>X-ID-Token` is present but the access
   token is not, the browser dropped the access token cookie for being too
   large (over about 4 KB, from many roles or large custom claims): show
   `token_too_large` ("your account has too many roles, contact an
   administrator"), not a plain failure. Apply the same check in routes 4 and 7.
3. `GET {API}/api/v1/auth/me` with `Authorization: Bearer <token>`. This runs
   the full token check, creates the user on first login, and returns the
   user's roles in this app.
4. `401`, or `200` with no role this UI serves: back to login with `no_access`.
   **Do not** log the user out of IAM: their IAM session is valid for other
   apps.
5. Otherwise clear any local-login session cookies, so the two session kinds
   never mix, and answer a small HTML page with a meta refresh to the
   sanitised `returnUrl` or the home route for the roles.

Use a meta refresh, not a `30x`. The redirect chain started at the identity
provider, which is cross-site, and browsers withhold `SameSite=Strict` cookies
on every hop of such a chain. A navigation the page starts itself is
same-site.

Take roles from `/me`, not from the token. Identity providers without roles
(eSignet) put none in the token, and this app adds `default_roles` that the
token never shows. Decode the token only to read `exp`.

### 4. API proxy: `/proxy/*`

1. Read `login_option` and the access token. Missing: `401` to the browser.
2. If the decoded `exp` has passed, refresh first (route 5). This app caches
   its verdict until `exp`, so an expired token is a guaranteed `401`.
3. Forward with `Authorization: Bearer <token>`. **Do not forward browser
   cookies.**
4. On `401` from this app: refresh once and retry. If the refreshed token is
   identical to the old one, the `401` was a real answer: return it, no retry.
5. On `503`: return it as is. It means IAM is down, not that the session ended.
   Do not log the user out.
6. State-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`) need the UI's own
   same-origin check (`Sec-Fetch-Site`, or `Origin` against the UI host).

### 5. Refresh: called by routes 3 and 4, or by the browser before expiry

1. `POST {API}/api/v1/auth/refresh {access_token}` (the current token, expired
   is fine, in the body), forwarding only the IAM cookies of that option:
   `<prefix>X-Access-Token`, `<prefix>X-Session-Id`, `<prefix>X-ID-Token`.
   Local sessions call the same route with `refresh_token`.
2. Relay every `Set-Cookie` from the response to the browser unchanged. They
   carry IAM's cookie domain.
3. Failure (`401`): clear `login_option` and the IAM cookies the UI can clear,
   and send the user to login. `503`: keep the session, retry later.

A UI that has not switched can keep calling IAM's `GET /auth/get_user_profile`
with the same cookies directly; that still works, but needs IAM's URL in the
UI's config.

### 6. Logout: `POST /auth/logout`

1. Same-origin check, rate limit.
2. `POST {API}/api/v1/auth/logout {access_token}`, forwarding the option's IAM
   cookies. Local sessions call the same route with `refresh_token`.
3. Relay every `Set-Cookie` from the response. Clear the UI's own cookies
   (`login_option`, local session) first, then apply the relayed ones last,
   because they carry IAM's exact cookie domain.
4. Response `{provider_logout: true}`: done, stay on the page or show the login
   page.
5. Response with `logout_url`: send the browser there (`window.location`). It
   ends the identity provider's session and comes back to the page IAM has
   configured for that provider.
6. This app or IAM unreachable: clear local cookies anyway and show the login
   page. Logout is best effort.

Clearing cookies in the UI alone is not a logout. The refresh token would stay
in IAM and the identity provider session would stay open, so the next login
would skip the password.

### 7. Who am I: `GET /auth/me`

For the browser's own use (menus, route guards): proxy to
`{API}/api/v1/auth/me` with the Bearer token, with the same refresh rules as
route 4.

## Coexistence with local login

- Local login keeps its own routes and cookies, unchanged.
- At most one session kind is active. The landing route clears the local
  session; the local login clears `login_option`.
- If both are somehow present, decide once which wins (for example local) and
  apply it in one place that every route uses.
- An idle timeout the UI enforces itself applies to local sessions only. Do not
  end an IAM session on UI idle: that ends the user's single sign-on session
  for every other app behind the same identity provider.

## Security checklist

- [ ] Tokens never reach page JavaScript. Only `HttpOnly` cookies and
      server-side code.
- [ ] Every state-changing UI route has a same-origin check.
- [ ] `returnUrl` is sanitised to a same-origin path in the start route and
      again in the landing route.
- [ ] `redirect_url` from this app is accepted only with `https` (or `http` on
      localhost).
- [ ] Browser cookies are forwarded only to the refresh and logout endpoints,
      and only the IAM cookies of the active option.
- [ ] `Set-Cookie` from refresh and logout is relayed unchanged, not rebuilt.
- [ ] Access decisions use `/me`, never roles decoded from the token.
- [ ] `503` never logs the user out. `401` after one refresh does.
- [ ] Login start, logout and refresh are rate limited.
- [ ] Error reasons shown to the user do not echo server error text.

## Moving an existing single-IAM UI

A UI that today reads `IAM_BASE_URL`, `IAM_LOGIN_PROVIDER_ID`, an application
name and one cookie prefix from its env:

| Today                                                 | After                                                           |
| ----------------------------------------------------- | --------------------------------------------------------------- |
| "Sign in as staff" shown when `IAM_BASE_URL` is set   | Buttons from `/iam/providers`                                   |
| UI calls IAM `start_authentication_transaction`       | UI calls this app's `/iam/login`                                |
| One cookie prefix in env                              | `cookie_prefix` from the login response, kept in `login_option` |
| Landing route checks roles decoded from the token     | Landing route calls `/me`                                       |
| UI calls IAM `get_user_profile` to refresh            | UI calls this app's `/auth/refresh` with `access_token`         |
| UI calls IAM `/auth/logout`                           | UI calls this app's `/auth/logout` with `access_token`          |
| Env: IAM URL, provider id, application, cookie prefix | Env: none of these                                              |

Order: ship the new login, landing and logout routes; keep the IAM URL for
refresh; switch refresh when this app's endpoint is live; then remove the IAM
env.

## Tests

- Login page: renders one button per entry in order; `local` renders the form;
  empty list renders the message; this app down renders the page with an error,
  not a crash.
- Start: sanitised `returnUrl`; absolute landing URL on the UI origin;
  `login_option` set; `400`, `502` and `503` map to their reasons; a non-https
  `redirect_url` is refused.
- Landing: missing `login_option` or token gives `login_failed`; `/me` `401` or
  no usable role gives `no_access` without an IAM logout; success clears the
  local session and answers a meta refresh, not a `30x`.
- Two options logged in at once: the UI reads only the token named by
  `login_option`.
- Proxy: Bearer sent, browser cookies not sent; expired token refreshed first;
  `401` refreshed once then retried; identical refreshed token not retried;
  `503` passed through without logout; state-changing request from another
  origin refused.
- Refresh: only the option's cookies forwarded; `Set-Cookie` relayed; `401`
  ends the session; `503` keeps it.
- Logout: UI cookies cleared before relayed ones are applied; `logout_url`
  navigated to; failure still clears local cookies.
- Local login: unchanged; clears `login_option`.
