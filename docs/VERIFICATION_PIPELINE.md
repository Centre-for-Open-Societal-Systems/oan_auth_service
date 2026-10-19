# Verification Pipeline

Quality and security gates every OAN Frappe app runs, in three stages.

```
Developer workstation                                    GitHub Actions (CI)
┌───────────────────────┐   ┌────────────────────────┐   ┌─────────────────────────────┐
│ 1. Pre-commit hook    │ → │ 2. Pre-push hook       │ → │ 3. Pull request gates       │
│ (staged files, <2s)   │   │ (tests and Semgrep)    │   │ (clean containers)          │
├───────────────────────┤   ├────────────────────────┤   ├─────────────────────────────┤
│ • Ruff lint & format  │   │ • pre-commit all files │   │ • pre-commit action         │
│ • Prettier (JS & MD)  │   │ • bench run-tests      │   │ • Semgrep rules             │
│ • gitleaks            │   │ • Semgrep              │   │ • pip-audit                 │
│ • Syntax / AST checks │   │                        │   │ • Generated-file drift gate │
│ • EOF & merge markers │   │                        │   │ • MariaDB + Redis test run  │
└───────────────────────┘   └────────────────────────┘   └─────────────────────────────┘
```

## 1. Stage 1: Pre-Commit (`.pre-commit-config.yaml`)

1. **Repository hygiene (`pre-commit-hooks`)**: `check-merge-conflict`, `check-ast`,
   `check-json`, `check-yaml`, `check-toml`, `debug-statements`, `trailing-whitespace`,
   `end-of-file-fixer`.
   > [!NOTE]
   > DocType JSON is excluded from `end-of-file-fixer`, because Frappe writes it without
   > a trailing newline.
2. **Ruff**: import sort (`--select=I --fix`), lint, `ruff-format`.
3. **Prettier**: JS / Vue / SCSS and Markdown. Do not hand-pad tables in `docs/`.
4. **gitleaks**: blocks committed keys, tokens and certificates.

```bash
pip install pre-commit
pre-commit install
pre-commit install --hook-type pre-push   # optional, recommended
```

## 2. Stage 2: Pre-Push

1. `pre-commit run --all-files`.
2. `bench --site <site> run-tests --app <app_name>`.
3. Semgrep with `--error` against the Frappe rules
   (`https://github.com/frappe/semgrep-rules.git`), `r/python.lang.correctness`, and the
   OAN rules in `oan_auth_service/.semgrep/rules.yml`:

| Rule                              | Enforces                                                           |
| --------------------------------- | ------------------------------------------------------------------ |
| `oan-api-missing-error-handler`   | Every `@route` / `@rest` / `@root_route` has `@handle_api_errors`. |
| `oan-no-raw-sql-in-api-layer`     | No `frappe.db.sql` under `api/`.                                   |
| `oan-db-sql-formatted-string`     | No f-string, `+`, `.format()` or `%` SQL.                          |
| `oan-get-doc-in-loop`             | No `get_doc` / `get_value` inside loops in `api/` (N+1).           |
| `oan-dangling-frappe-whitelist`   | No `@frappe.whitelist()` in `api/` without a route decorator.      |
| `oan-translatable-throw-messages` | `frappe.throw` messages are wrapped in `_()`.                      |
| `oan-no-print-in-production-code` | No `print()` outside scripts and tests.                            |

Install script:

```bash
cat << 'EOF' > .git/hooks/pre-push
#!/bin/sh
APP_NAME="$(basename "$(git rev-parse --show-toplevel)")"
SITE="${OAN_TEST_SITE:-testsite.localhost}"

pre-commit run --all-files || exit 1

if command -v bench > /dev/null; then
    bench --site "$SITE" run-tests --app "$APP_NAME" || exit 1
fi

SEMGREP_BIN="$(command -v semgrep || echo ../../env/bin/semgrep)"
if [ -x "$SEMGREP_BIN" ]; then
    RULES_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/frappe-semgrep-rules"
    [ -d "$RULES_DIR/.git" ] || git clone --depth 1 https://github.com/frappe/semgrep-rules.git "$RULES_DIR" || exit 1
    PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python SEMGREP_SEND_METRICS=off \
      "$SEMGREP_BIN" scan --config "$RULES_DIR/rules" --config r/python.lang.correctness \
        --config ../oan_auth_service/.semgrep/rules.yml --error || exit 1
fi
EOF
chmod +x .git/hooks/pre-push
```

## 3. Stage 3: CI (`.github/workflows/`)

- **Linter and security** (`linter.yml` / `linters.yml`): `pre-commit/action`,
  `semgrep ci --metrics=off`, `pip-audit` on `pyproject.toml` dependencies.
- **Generated-file drift** (`generated-files.yml`): runs all generators and fails on
  `git diff --exit-code -- openapi/ apisix/ kong/ postman/`.
- **Tests** (`ci.yml`): `mariadb:11.8` and `redis:alpine` services, pinned Frappe branch
  (`version-16`), dependency apps installed first (`oan_auth_service` before consumers),
  fresh site, `bench migrate`, full `run-tests`. `cancel-in-progress: true` per PR.
