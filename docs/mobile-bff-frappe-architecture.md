# Mobile BFF on Frappe: Architecture

Status: proposal. Derived from three Postman artifacts:

- `oan_grievance_service/postman/oan_grievance_farmer_esignet_collection.json`
- `oan_a2c/postman/a2c-farmer.postman_collection.json`
- `consent-management/postman/consent-manager-beneficiary.postman_environment.json` (and its sibling collection)

## 1. Goal

One mobile app (farmer / beneficiary). One base URL. Three backends behind it:

| Backend         | Stack                | API shape             | What the farmer does                                        |
| --------------- | -------------------- | --------------------- | ----------------------------------------------------------- |
| Grievance       | Frappe               | `{base}/v1/...`       | Submit and track grievances, attachments, feedback, exports |
| A2C             | Frappe               | `{a2c}/api/v1/...`    | Dashboard, loan catalog, applications, consent-to-profile   |
| Consent Manager | OpenG2P (non-Frappe) | `{cm}/consent/v1/...` | List, view, revoke consents, receipts                       |

## 2. Findings from the Postman files

**Auth is already shared at the identity layer.** All three flows end at the same pattern: IAM -> eSignet (CSRF, oauth-details, send-otp, authenticate, auth-code) -> IAM `/auth/callback` -> session/access token.

**But the entry points differ:**

- Grievance starts login through `oan_auth_service`: `GET /v1/auth/iam/providers`, `POST /v1/auth/iam/login`, then `GET /v1/auth/me` provisions the Frappe user on first login. Also `POST /v1/auth/refresh` and `POST /v1/auth/logout`.
- A2C and Consent Manager call IAM directly: `GET {iam}/auth/get_login_providers`, `GET {iam}/auth/get_login_provider_redirect/{provider_id}`, `GET {iam}/auth/callback`, `GET {iam}/auth/get_user_profile`. A2C then calls `GET /api/v1/auth/me` and `GET /api/v1/me/dashboard`.

**Different API prefixes and envelopes.** `/v1/`, `/api/v1/`, `/consent/v1/my/`. Frappe responses use `{status, data, message, pagination}`. The Consent Manager envelope is not confirmed and must be checked.

**Mixed content types.** Grievance has multipart upload (`POST .../attachments`), binary streaming (`.../attachments/{id}/view`) and CSV/PDF export (`.../export?format=`). These matter for the proxy choice in section 5.

**Extra non-farmer calls in the collections.** Officer login and resolve actions (`5-0`, `5a`, `5c`) and the A2C test-only OTP inbox lookup (`6d-i`, `6d-ii`) are test helpers. The BFF must not expose them.

## 3. Target architecture

```
Mobile app
   |  HTTPS, one host: api.oan.example
   v
nginx (TLS, upload limits, rate limit, pass-through for heavy routes)
   |
   v
Frappe site: oan_mobile_gateway   <-- new app, the BFF
   |  auth: oan_auth_service (JWT middleware, IAM issuer/azp routing)
   |
   +--> /m/v1/grievance/*  --> Grievance Frappe   (/v1/...)
   +--> /m/v1/a2c/*        --> A2C Frappe         (/api/v1/...)
   +--> /m/v1/consent/*    --> Consent Manager    (/consent/v1/my/...)
   +--> /m/v1/home         --> aggregate (fan-out to all three)
   +--> /m/v1/auth/*       --> oan_auth_service (login, refresh, logout, me)
```

The BFF owns the mobile contract. Backends keep their own contracts and can change paths without an app release.

## 4. Auth design

1. App calls `GET /m/v1/auth/providers`, then `POST /m/v1/auth/login`. Both map to the existing `oan_auth_service` endpoints (`/v1/auth/iam/providers`, `/v1/auth/iam/login`).
2. App opens the returned eSignet URL in the system browser (AppAuth, PKCE). It does not use an embedded webview. A custom scheme or universal link returns the code to the app.
3. Callback exchange goes through IAM, then the BFF returns the access token and refresh token. Today IAM returns an access-token cookie. Mobile needs the token in the response body.
4. `GET /m/v1/auth/me` provisions the Frappe user on first login, as `1i` does today.
5. Every later call carries `Authorization: Bearer <token>`. The existing JWT middleware validates it and calls `frappe.set_user()`.
6. Tokens live in Keychain/Keystore. Refresh via `POST /m/v1/auth/refresh`.

**Per-backend credentials (decision needed, section 8):**

- If all three accept the same IAM realm/client token: forward `Authorization` as-is.
- If not: the BFF exchanges or maps the token per backend. Never forward a token to a backend that did not issue it or does not list it in `aud`.

## 5. Why Frappe, and where it hurts

**Frappe is a good fit for:**

- Reusing `oan_auth_service` (JWT middleware, login options, role sync, user provisioning).
- The existing three-decorator pattern (`whitelist`, `validate_request`, `handle_api_errors`) and the `success_response` envelope.
- Aggregate endpoints written in Python with Pydantic validation.
- Frappe RBAC, logging, and background jobs (retry queues, push fan-out).

**Frappe is a weak pure reverse proxy:**

- Each proxied request holds a gunicorn worker for the full upstream latency. Slow rural networks and large uploads exhaust workers fast.
- Frappe whitelisted methods return JSON envelopes. Binary streaming and multipart need `frappe.response` tricks and buffer in memory.
- Request/response header rewriting is limited.

**Decision: hybrid.**

| Route kind                                                         | Handled by                                                                                                     |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| Small JSON pass-through, auth, aggregation, envelope normalization | Frappe BFF                                                                                                     |
| Attachment upload, attachment view/download, CSV/PDF export        | nginx `proxy_pass` straight to the grievance backend, after an `auth_request` to the BFF to validate the token |

If traffic is low (pilot), put everything through Frappe first and split the heavy routes out later. The mobile contract stays the same either way.

## 6. Route map

| Mobile route                                           | Upstream                                                                                                         | Notes                                                 |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `GET /m/v1/auth/providers`                             | grievance auth `GET /v1/auth/iam/providers`                                                                      |                                                       |
| `POST /m/v1/auth/login`                                | `POST /v1/auth/iam/login`                                                                                        | return eSignet URL                                    |
| `GET /m/v1/auth/me`                                    | `GET /v1/auth/me`                                                                                                | provisions user                                       |
| `POST /m/v1/auth/refresh`, `/logout`                   | `POST /v1/auth/refresh`, `/logout`                                                                               |                                                       |
| `GET /m/v1/home`                                       | fan-out: A2C `/api/v1/me/dashboard`, grievance `/v1/grievances?page_size=5`, CM `/consent/v1/my/consents?size=5` | partial failure returns per-section errors            |
| `GET/POST /m/v1/grievance/grievances`                  | `/v1/grievances`                                                                                                 |                                                       |
| `GET /m/v1/grievance/grievances/{ticket}/timeline`     | `/v1/grievances/{ticket}/timeline`                                                                               |                                                       |
| `POST /m/v1/grievance/grievances/{ticket}/action`      | `/v1/grievances/{ticket}/action`                                                                                 | allow farmer actions only (reopen, close with rating) |
| `POST /m/v1/grievance/grievances/{ticket}/feedback`    | `/v1/grievances/{ticket}/feedback`                                                                               |                                                       |
| `GET /m/v1/grievance/options`, `/administrative-areas` | `/v1/submitters/options`, `/v1/administrative-areas`                                                             | cacheable                                             |
| attachments (upload, list, view, download, delete)     | `/v1/grievances/{ticket}/attachments`, `/v1/attachments/{id}/...`                                                | heavy, nginx path                                     |
| `GET /m/v1/grievance/grievances/{ticket}/export`       | `/v1/grievances/{ticket}/export`                                                                                 | heavy, nginx path                                     |
| `GET /m/v1/a2c/catalog/*`, saved products              | `/api/v1/catalog/*`                                                                                              |                                                       |
| `/m/v1/a2c/applications*`                              | `/api/v1/applications*`, `/api/v1/loan-applications/{id}/documents`                                              |                                                       |
| `/m/v1/a2c/consent/*`                                  | `/api/v1/consent/*` (farmers search, reasons, allowed-fields, otp, otp/verify, requests)                         | A2C-side consent for profile creation                 |
| `/m/v1/consent/consents*`                              | `/consent/v1/my/consents*`, `/my/receipts/{id}`                                                                  | Consent Manager; list, get, revoke, receipt           |

**Do not proxy:** officer login/actions, the OTP inbox helpers, `POST /consent/v1/consent-requests` (requester-side, not beneficiary).

Naming trap: "consent" exists twice. A2C consent creates the farmer profile. Consent Manager consent is the long-lived data-sharing record. Keep them in separate namespaces in the mobile API.

## 7. Cross-cutting rules

- **Response envelope:** BFF returns the Frappe envelope `{status, data, message, pagination}` on all routes. Wrap Consent Manager responses into it.
- **Errors:** map upstream 4xx/5xx to the BFF envelope. Hide upstream stack traces and hostnames.
- **Timeouts:** upstream calls use explicit connect/read timeouts (for example 3s/15s). Aggregates use per-section timeouts and return partial data.
- **Idempotency:** `Idempotency-Key` header on `POST /grievances`, `POST /applications`, and submit. The app retries on flaky networks.
- **Versioning:** `/m/v1/`. Add a min-app-version check (`X-App-Version`) for forced upgrades.
- **Rate limit and audit:** key by token `sub`. Log upstream, status, latency.
- **Push:** one device-token registration endpoint in the BFF. Upstream events arrive by webhook and a background job sends FCM/APNs.
- **Config:** upstream base URLs in `site_config.json` (`oan_mobile_gateway.upstreams`), not in code.
- **Tenant isolation:** if A2C is called with a bank-scoped user, that remains enforced by A2C. The BFF only serves farmers.

## 8. Open questions (resolve before building)

1. Do the IAM tokens for grievance, A2C and Consent Manager share one issuer/audience, or does each backend need its own token?
2. Does IAM return tokens in the response body for a mobile redirect, or only as a cookie? The Consent Manager env has both `bene_token` and `bene_access_token`, so clarify which one the API accepts.
3. Is the A2C `/api/v1/auth/me` call a separate login, or does it accept the grievance token?
4. Consent Manager response envelope and error format.
5. Expected peak concurrency and attachment sizes. This decides when to move heavy routes to nginx.
6. Where does the BFF run: on the grievance bench, the auth-service bench, or its own site?

## 9. Phased plan

1. **Skeleton:** new app `oan_mobile_gateway`, upstream client with timeouts, envelope normalization, JWT via `oan_auth_service`.
2. **Auth routes:** providers, login, me, refresh, logout, token in body for mobile.
3. **Pass-through routes:** grievance, then A2C, then Consent Manager.
4. **Aggregate:** `/m/v1/home`.
5. **Heavy routes:** nginx `auth_request` path for attachments and exports.
6. **Hardening:** idempotency, rate limit, push, min-version check.
