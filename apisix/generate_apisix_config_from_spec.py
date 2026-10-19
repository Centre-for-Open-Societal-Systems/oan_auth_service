#!/usr/bin/env python3
"""
generate_apisix_config_from_spec.py

Generates the ADC gateway configuration (adc.yaml) and the APISIX Ingress Controller
resources (k8s/templates, the oan-auth-gateway Helm chart) for the OAN Authentication
Service directly from openapi_v1.public.yaml. Routes are grouped by throttling tier, see
oan_auth_service/gateway_apisix.py.

Usage:
    python3 apisix/generate_apisix_config_from_spec.py
    adc lint -f apisix/adc.yaml
"""

from pathlib import Path

from oan_auth_service import gateway_apisix as gw

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
SPEC_PATH = REPO_ROOT / "openapi" / "openapi_v1.public.yaml"
OUTPUT_PATH = SCRIPT_DIR / "adc.yaml"
K8S_DIR = SCRIPT_DIR / "k8s" / "templates"
APP = "oan-auth"
# Hosts are written as ${VAR} placeholders that ADC fills in from its own environment at
# `adc diff|sync`, so one committed adc.yaml serves every deployment. Ports stay numbers:
# the schema wants integers, and a quoted placeholder is a string.
SITE_NAME = "${FRAPPE_SITE_NAME}"

API_UPSTREAM = gw.upstream(
	host_env="OAN_AUTH_UPSTREAM_HOST",
	host_default="oan-auth.internal.svc",
	port_env="OAN_AUTH_UPSTREAM_PORT",
	port_default=8000,
	# Frappe picks the site from the Host header, so send the site name, not the gateway's.
	pass_host="rewrite",
	upstream_host=SITE_NAME,
	timeout={"connect": 5, "send": 20, "read": 20},
	retries=2,
)
API_UPSTREAM["nodes"][0]["host"] = "${OAN_AUTH_UPSTREAM_HOST}"

# `${NAME}` placeholders in the ADC document become these chart values.
HELM_VALUES = {
	"OAN_AUTH_UPSTREAM_HOST": ".Values.web.serviceName",
	"FRAPPE_SITE_NAME": ".Values.siteName",
	"WEB_PORT": ".Values.web.port",
}
HELM_REQUIRED = {"OAN_AUTH_UPSTREAM_HOST", "FRAPPE_SITE_NAME", "APISIX_REDIS_HOST"}
HELM_BACKENDS = {f"{APP}-service-v1": ("${OAN_AUTH_UPSTREAM_HOST}", "${WEB_PORT}")}

# ---------------------------------------------------------------------------
# Throttling tiers
# ---------------------------------------------------------------------------
TIERS = {
	"public-auth": {
		"limit_by": "ip",
		"minute": 5,
		"hour": 30,
		"policy": "redis",
		"fail_open": False,
		"note": "Credential-sensitive endpoints (login, register, logout, reset). Tight IP limits to prevent stuffing. Rejects requests when the limiter store is down.",
	},
	"authenticated-core": {
		"limit_by": "consumer",
		"minute": 120,
		"hour": 4000,
		"policy": "redis",
		"note": "Logged-in user calls (e.g. /me) and token refresh. Cheap and frequent.",
	},
	"admin": {
		"limit_by": "consumer",
		"minute": 60,
		"hour": 1000,
		"policy": "redis",
		"note": "Admin user and role management. Low volume. Keyed per IP while GATEWAY_JWT is off; per token once the gateway verifies tokens.",
	},
	"public-read": {
		"limit_by": "ip",
		"minute": 120,
		"hour": 2000,
		"policy": "redis",
		"note": "Public discovery and health check endpoints.",
	},
}

# ---------------------------------------------------------------------------
# Explicit Tier assignments per route
# ---------------------------------------------------------------------------
TIER_OVERRIDES = {
	("POST", "/v1/auth/register"): "public-auth",
	("POST", "/v1/auth/login"): "public-auth",
	("POST", "/v1/auth/refresh"): "authenticated-core",
	("POST", "/v1/auth/logout"): "public-auth",
	("POST", "/v1/auth/forgot-password"): "public-auth",
	("POST", "/v1/auth/reset-password"): "public-auth",
	("POST", "/v1/auth/password/forgot"): "public-auth",
	("POST", "/v1/auth/password/reset"): "public-auth",
	("POST", "/v1/auth/password/initial"): "public-auth",
	("GET", "/v1/auth/me"): "authenticated-core",
	("GET", "/v1/auth/keys"): "public-read",
	("GET", "/v1/auth/health"): "public-read",
	("GET", "/v1/auth/metadata"): "public-read",
	("GET", "/v1/admin/users"): "admin",
	("POST", "/v1/admin/users"): "admin",
	("GET", "/v1/admin/users/{user_id}"): "admin",
	("PATCH", "/v1/admin/users/{user_id}"): "admin",
	("DELETE", "/v1/admin/users/{user_id}/sessions"): "admin",
	("POST", "/v1/admin/users/{user_id}/temporary-password"): "admin",
	("GET", "/v1/admin/users/{user_id}/roles"): "admin",
	("POST", "/v1/admin/users/{user_id}/roles"): "admin",
	("DELETE", "/v1/admin/users/{user_id}/roles/{role}"): "admin",
	("GET", "/v1/admin/roles"): "admin",
	("GET", "/v1/admin/permissions"): "admin",
	("PUT", "/v1/admin/permissions"): "admin",
	("DELETE", "/v1/admin/permissions"): "admin",
	("POST", "/v1/admin/permissions/reset"): "admin",
	("GET", "/v1/notifications"): "authenticated-core",
	("PATCH", "/v1/notifications"): "authenticated-core",
	("DELETE", "/v1/notifications"): "authenticated-core",
	("GET", "/v1/notifications/{notification_id}"): "authenticated-core",
	("PATCH", "/v1/notifications/{notification_id}"): "authenticated-core",
	("DELETE", "/v1/notifications/{notification_id}"): "authenticated-core",
}


# False: the gateway does not verify tokens. Frappe's auth_hooks middleware does, and it
# also accepts OpenG2P IAM tokens, which a gateway jwt-auth check would refuse. Set True
# only for a deployment that issues oan_auth_service tokens exclusively.
GATEWAY_JWT = False


# Verifies the RS256 bearer tokens oan_auth_service mints. This repo owns the issuer
# consumer; other apps on the same bench reuse it. Emitted only when GATEWAY_JWT is on.
def consumers():
	public_key = gw.env("OAN_AUTH_JWT_PUBLIC_KEY", "")
	if GATEWAY_JWT and not public_key:
		raise SystemExit("GATEWAY_JWT is on: set OAN_AUTH_JWT_PUBLIC_KEY (PEM) to generate the consumer.")
	return [
		{
			"username": "oan-auth-jwt-issuer",
			"plugins": {
				"jwt-auth": {
					"key": gw.env("OAN_JWT_ISSUER", "oan-auth"),
					"algorithm": "RS256",
					"public_key": public_key,
				}
			},
		}
	]


def main():
	spec = gw.load_spec(SPEC_PATH)
	routes = gw.reconcile(gw.spec_routes(spec), TIER_OVERRIDES)
	doc = gw.build_document(
		routes,
		app=APP,
		tiers=TIERS,
		api_upstream=API_UPSTREAM,
		service_plugins=gw.service_plugins(
			methods="GET,POST,PATCH,DELETE,OPTIONS", credentials=True, max_body_mb=5
		),
		consumers=consumers() if GATEWAY_JWT else None,
		gateway_jwt=GATEWAY_JWT,
	)
	provenance = [
		f"Source Spec: {spec['info']['title']} v{spec['info']['version']}",
		"Generated by generate_apisix_config_from_spec.py -- do not hand-edit;",
		"change the OpenAPI spec or TIER_OVERRIDES and re-run.",
	]
	gw.write_document(
		doc, OUTPUT_PATH, ["OAN Authentication Service ADC config (adc lint|validate|diff|sync)", *provenance]
	)
	gw.write_helm_templates(
		doc,
		K8S_DIR,
		["OAN Authentication Service APISIX Ingress Controller resources", *provenance],
		app=APP,
		backends=HELM_BACKENDS,
		values=HELM_VALUES,
		required=HELM_REQUIRED,
		ints={"WEB_PORT"},
	)
	gw.report(OUTPUT_PATH, routes, doc, spec)


if __name__ == "__main__":
	main()
