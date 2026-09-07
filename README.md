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
why HS256 makes shared key material a mistake rather than a shortcut.

## Three kinds of versioning

**1. API contract — `api/v1/`.** Endpoints live under a version segment, so the
public path is `/api/method/oan_auth_service.api.v1.auth.login`. A breaking
change to the login or refresh contract ships as `api/v2/` alongside `v1`,
letting consumers migrate on their own schedule.

Internals stay outside the version segment: `api/jwt_keys.py` and
`api/middleware.py` are not part of the client contract. Rotating a key must not
require a new API version, and shipping `v2` must not force a re-keying.

**2. Signing keys — `kid`.** Keys are indexed by `kid` in `site_config.json`, so
a leaked secret can be rotated with no downtime and no client change. Details in
`api/jwt_keys.py`.

**3. Releases — git tags.** Consumers must pin a **tag**, never a branch.
`apps.json` entries take a git ref in the `branch` field, and `git clone --branch` accepts a tag:

```json
[{ "url": "https://github.com/<org>/oan_auth_service.git", "branch": "v0.1.0" }]
```

This matters because the deployments are independent. Pinning a moving branch
means two products silently build different auth logic with nothing recording
which — the exact failure this app exists to prevent. Tag releases here; bump
the pin in each consumer as a deliberate, reviewable commit.

## Consuming this app

In the consumer's `hooks.py`:

```python
required_apps = ["oan_auth_service"]
```

so bench installs this app first and the refresh-token doctype exists before the
consumer migrates. The consumer then registers its API namespace and exempt
paths with `api.middleware.register_namespace()` — the middleware is registered
once here, and matches incoming paths against that registry, so this app never
needs to know its consumers by name.

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
