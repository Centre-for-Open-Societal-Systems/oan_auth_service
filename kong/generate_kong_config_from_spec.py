#!/usr/bin/env python3
"""generate_kong_config_from_spec.py.

Generates the declarative Kong gateway configuration (kong.yml) for the
OAN Authentication Service directly from openapi_v1.public.yaml.

Usage:
    python3 generate_kong_config_from_spec.py > kong.yml
    deck validate -s kong.yml
    deck sync -s kong.yml
"""

import re
import sys
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
SPEC_PATH = REPO_ROOT / "openapi" / "openapi_v1.public.yaml"
OUTPUT_PATH = SCRIPT_DIR / "kong.yml"
AUTH_UPSTREAM_URL = "http://oan-auth.internal.svc:8000"

# ---------------------------------------------------------------------------
# Throttling tiers
# ---------------------------------------------------------------------------
TIERS = {
	"public-auth": {
		"limit_by": "ip",
		"minute": 5,
		"hour": 30,
		"policy": "redis",
		"note": "Credential-sensitive endpoints (login, register, logout, reset). Tight IP limits to prevent stuffing.",
	},
	"authenticated-core": {
		"limit_by": "consumer",
		"minute": 120,
		"hour": 4000,
		"policy": "redis",
		"note": "Logged-in user calls (e.g. /me). Cheap and frequent.",
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
	("POST", "/api/v1/auth/register"): "public-auth",
	("POST", "/api/v1/auth/login"): "public-auth",
	("POST", "/api/v1/auth/refresh"): "public-auth",
	("POST", "/api/v1/auth/logout"): "public-auth",
	("POST", "/api/v1/auth/forgot-password"): "public-auth",
	("POST", "/api/v1/auth/reset-password"): "public-auth",
	("GET", "/api/v1/auth/me"): "authenticated-core",
	("GET", "/api/v1/auth/keys"): "public-read",
	("GET", "/api/v1/auth/health"): "public-read",
	("GET", "/api/v1/auth/metadata"): "public-read",
}


def load_spec(path):
	with open(path) as f:  # nosemgrep
		return yaml.safe_load(f)


def spec_routes(spec):
	tag_to_domain = {t["name"]: f"d{i + 1:02d}" for i, t in enumerate(spec["tags"])}
	routes = []
	for path, methods in spec["paths"].items():
		for method, op in methods.items():
			method = method.upper()
			security = op.get("security", spec.get("security", []))
			if not security or security == []:
				auth = "public"
			elif any("BearerAuth" in s for s in security):
				auth = "bearer"
			else:
				auth = "custom"
			tag = (op.get("tags") or [None])[0]
			domain = tag_to_domain.get(tag, "d00")
			routes.append(
				{
					"method": method,
					"path": path,
					"auth": auth,
					"domain": domain,
					"tag": tag,
					"operation_id": op.get("operationId"),
				}
			)
	return routes


def reconcile(routes):
	spec_keys = {(r["method"], r["path"]) for r in routes}
	override_keys = set(TIER_OVERRIDES.keys())

	missing_overrides = spec_keys - override_keys
	stale_overrides = override_keys - spec_keys

	if missing_overrides or stale_overrides:
		msg = ["Spec <-> TIER_OVERRIDES mismatch -- refusing to generate kong.yml.", ""]
		if missing_overrides:
			msg.append(f"In the spec but with no assigned throttling tier ({len(missing_overrides)}):")
			for m, p in sorted(missing_overrides):
				msg.append(f"  {m} {p}")
		if stale_overrides:
			msg.append(f"In TIER_OVERRIDES but no longer in the spec ({len(stale_overrides)}):")
			for m, p in sorted(stale_overrides):
				msg.append(f"  {m} {p}")
		msg.append("")
		msg.append("Assign a tier for each route and re-run.")
		raise SystemExit("\n".join(msg))

	for r in routes:
		r["tier"] = TIER_OVERRIDES[(r["method"], r["path"])]
	return routes


def to_kong_regex(path: str) -> str:
	if "{" not in path:
		return f"~{path}$"
	regex = re.sub(r"\{(\w+)\}", r"(?<\1>[^/]+)", path)
	return f"~{regex}$"


def route_name(method: str, path: str) -> str:
	slug = re.sub(r"[{}]", "", path).strip("/").replace("/", "-")
	return f"{method.lower()}-{slug}"[:120]


def build_config(routes):
	service = {
		"name": "oan-auth-service-v1",
		"url": AUTH_UPSTREAM_URL,
		"connect_timeout": 5000,
		"write_timeout": 15000,
		"read_timeout": 15000,
		"retries": 2,
		"tags": ["oan", "auth", "v1"],
		"plugins": [
			{
				"name": "cors",
				"config": {
					"origins": [
						"http://localhost:8000",
						"https://app.openagrinet.org",
						"https://auth.openagrinet.org",
					],
					"methods": ["GET", "POST", "OPTIONS"],
					"headers": ["Authorization", "Content-Type", "X-Request-Id"],
					"credentials": True,
					"max_age": 3600,
				},
			},
			{
				"name": "request-size-limiting",
				"config": {"allowed_payload_size": 5},  # MB
			},
			{
				"name": "correlation-id",
				"config": {"header_name": "X-Request-Id", "generator": "uuid", "echo_downstream": True},
			},
			{
				"name": "prometheus",
				"config": {"status_code_metrics": True, "latency_metrics": True, "bandwidth_metrics": True},
			},
		],
		"routes": [],
	}

	for r in routes:
		method, path, auth, domain, tier = r["method"], r["path"], r["auth"], r["domain"], r["tier"]
		kong_path = to_kong_regex(path)
		depth = path.count("/")
		route = {
			"name": route_name(method, path),
			"methods": [method],
			"paths": [kong_path],
			"strip_path": False,
			"regex_priority": depth,
			"tags": ["oan", "auth", "v1", domain, tier, auth],
			"plugins": [],
		}

		t = TIERS[tier]
		route["plugins"].append(
			{
				"name": "rate-limiting",
				"config": {
					"minute": t["minute"],
					"hour": t["hour"],
					"limit_by": t["limit_by"],
					"policy": t["policy"],
					"fault_tolerant": True,
					"hide_client_headers": False,
				},
			}
		)

		if auth == "bearer":
			route["plugins"].append(
				{
					"name": "jwt",
					"config": {
						"claims_to_verify": ["exp"],
						"key_claim_name": "iss",
						"header_names": ["Authorization"],
					},
				}
			)

		service["routes"].append(route)

	consumers = [
		{
			"username": "oan-auth-jwt-issuer",
			"tags": ["oan", "auth", "issuer"],
			"jwt_secrets": [
				{
					"algorithm": "HS256",
					"key": "oan-auth",
					"secret": "REPLACE_WITH_OAN_AUTH_JWT_SECRET",
				}
			],
		},
		{
			"username": "oan-web-client",
			"tags": ["oan", "client", "frontend"],
		},
	]

	doc = {
		"_format_version": "3.0",
		"_transform": True,
		"services": [service],
		"consumers": consumers,
	}
	return doc


def main():
	spec = load_spec(SPEC_PATH)
	routes = reconcile(spec_routes(spec))
	doc = build_config(routes)

	with open(OUTPUT_PATH, "w") as f:  # nosemgrep
		f.write("# OAN Authentication Service Kong Declarative Config\n")
		f.write(f"# Source Spec: {spec['info']['title']} v{spec['info']['version']}\n")
		f.write("# Generated by generate_kong_config_from_spec.py -- do not hand-edit;\n")
		f.write("# change the OpenAPI spec or TIER_OVERRIDES and re-run.\n")
		yaml.safe_dump(doc, f, sort_keys=False, default_flow_style=False, width=100)

	by_method = {}
	for r in routes:
		by_method[r["method"]] = by_method.get(r["method"], 0) + 1
	print(
		f"Wrote {OUTPUT_PATH.name}: {len(routes)} routes from {len(spec['paths'])} paths "
		f"({len(spec['tags'])} domains) -- methods: {by_method}",
		file=sys.stderr,
	)


if __name__ == "__main__":
	main()
