# Onboarding OAN Authentication Service to Kong Gateway

This guide covers deploying the OAN Authentication Service (`oan_auth_service`) REST API behind Kong Gateway, wiring authentication, rate-limiting, and managing declarative deployments via [decK](https://github.com/Kong/deck).

`kong.yml` is generated directly from `../openapi/openapi_v1.public.yaml` using `generate_kong_config_from_spec.py`.

---

## 1. Architecture

```
Client / Mobile App / Web  →  Kong Gateway  →  OAN Auth Service (Frappe)
                               TLS · authn ·      REST API (@route)
                               throttling ·       User authentication &
                               observability      token lifecycle
```

Kong operates in front of the auth service:

- **TLS Termination & Global Hygiene:** Handles SSL/TLS, CORS headers, request correlation IDs (`X-Request-Id`), and payload size limiting.
- **Pre-Auth Protection:** Strictly rate-limits sensitive authentication and session lifecycle endpoints (`/login`, `/register`, `/refresh`, `/logout`, `/forgot-password`, `/reset-password`) on client IP to prevent brute-force attacks and credential stuffing before traffic hits the database.
- **JWT Verification:** Authenticates `/api/v1/auth/me` and protected routes at the gateway level.

---

## 2. Declarative Deployment with decK (DB-less)

The API routing configuration is managed declaratively through `kong.yml`:

```bash
# 1. Regenerate OpenAPI spec (run inside bench or with bench python)
bench --site <site> execute openapi.generate_openapi_spec.main
# or: ../../env/bin/python3 ../openapi/generate_openapi_spec.py

# 2. Regenerate Kong declarative config
python3 generate_kong_config_from_spec.py

# 3. Validate configuration
deck validate -s kong.yml

# 4. Diff against live gateway
deck diff -s kong.yml --kong-addr https://kong-admin.internal:8001

# 5. Apply changes
deck sync -s kong.yml --kong-addr https://kong-admin.internal:8001
```

---

## 3. Throttling Tiers

| Tier                 | Keyed By  | Limit                 | Purpose                                                                                                                                     |
| :------------------- | :-------- | :-------------------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `public-auth`        | Client IP | 5 / min, 30 / hr      | Protects `/login`, `/register`, `/refresh`, `/logout`, `/forgot-password`, and `/reset-password` against brute-force / credential stuffing. |
| `authenticated-core` | Consumer  | 120 / min, 4,000 / hr | Signed-in user sessions (`/me`).                                                                                                            |
| `public-read`        | Client IP | 120 / min, 2,000 / hr | Health check, public key discovery (`/keys`), and metadata.                                                                                 |

Counters use `policy: redis` to ensure shared rate limits across all distributed Kong gateway nodes.

---

## 4. Configuration Placeholders

Before syncing `kong.yml` to production, populate:

1. **Upstream URL:** Replace `AUTH_UPSTREAM_URL` (defaults to `http://oan-auth.internal.svc:8000`) with your production service address.
2. **JWT Issuer & Secret:** In `consumers[0].jwt_secrets`:
   - **Key (`key`):** Must equal the site's `jwt_issuer` (the `iss` claim in issued JWTs). When `jwt_issuer` is omitted from `site_config.json`, the service falls back to the site name (e.g. `mysite.localhost`). If `key` and `iss` do not match, Kong's JWT plugin cannot match the consumer and will reject `/me` requests with `401 Unauthorized`.
   - **Secret (`secret`):** Set to the active HMAC secret matching `jwt_secret` (or `jwt_secrets[current_kid]`) in `site_config.json`.
3. **Redis Host/Port:** Ensure Kong's rate-limiting plugin references your central Redis instance in production environments.
