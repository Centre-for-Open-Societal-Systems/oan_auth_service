"""Build an ADC (APISIX Declarative CLI) config from an OpenAPI spec.

Shared by every Frappe app on the bench that fronts its REST API with APISIX
(oan_auth_service, oan_grievance_service). Each app keeps its own throttling tiers and
its own `(method, path) -> tier` table, and calls `build_document` with them. The output
is `adc.yaml`, which `adc lint|validate|diff|sync` apply to an APISIX running in etcd mode.

Routes are grouped by policy, not by URL: one route per (tier, auth, method), carrying
every path of that group in `uris`. A path is added to the gateway by assigning it a tier.

ADC has no plugin_config entity and no env-var substitution, so each route carries its
tier's plugins inline, and environment-specific values (upstream address, CORS origins,
Redis host) are read from the environment when the file is generated. The committed file
holds the development defaults; the deploy pipeline regenerates it with the real values.
"""

import copy
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

# `limit_by` in a tier maps to an nginx variable. Bearer calls are keyed by the token,
# not by consumer: every JWT maps to the one issuer consumer, so a consumer key would put
# all users into one shared bucket. Only used when the gateway verifies the token itself.
LIMIT_KEYS = {"ip": "remote_addr", "consumer": "http_authorization"}


# Public URLs drop Frappe's `/api` prefix (docs/API_CONVENTIONS.md): clients call
# `/v1/...`, the gateway rewrites to `/api/v1/...`, which is the only namespace Frappe
# dispatches to its REST handler (frappe/app.py) and the JWT middleware accepts.
UPSTREAM_PREFIX = "/api"


def env(name: str, default: str) -> str:
	"""Deployment-specific value: the environment wins, else the development default."""
	return os.environ.get(name) or default


def public_path(path: str) -> str:
	"""`/api/v1/x` -> `/v1/x`. Paths outside `/api/` are returned unchanged."""
	return path[len(UPSTREAM_PREFIX) :] if path.startswith(UPSTREAM_PREFIX + "/") else path


def publicize_spec(doc: dict[str, Any], servers: list[dict[str, str]]) -> dict[str, Any]:
	"""Turn an internal spec (Frappe paths, bench server) into the public contract:
	paths without `/api`, servers pointing at the gateway. operationIds are untouched."""
	out = dict(doc)
	out["servers"] = servers
	out["paths"] = {public_path(p): ops for p, ops in doc["paths"].items()}
	return out


def load_spec(path: Path) -> dict[str, Any]:
	with open(path) as f:  # nosemgrep: frappe-security-file-traversal
		return yaml.safe_load(f)


def spec_routes(spec: dict[str, Any]) -> list[dict[str, Any]]:
	"""One entry per operation in the spec, with the auth scheme the gateway must apply."""
	tag_to_domain = {t["name"]: f"d{i + 1:02d}" for i, t in enumerate(spec["tags"])}
	routes = []
	for path, methods in spec["paths"].items():
		for method, op in methods.items():
			security = op.get("security", spec.get("security", []))
			if not security:
				auth = "public"
			elif security == [{"FrappeTokenAuth": []}]:
				# Frappe checks the API key and secret itself; the gateway passes the header on.
				auth = "frappe-token"
			elif any("BearerAuth" in s for s in security):
				auth = "bearer"
			else:
				auth = "custom"
			tag = (op.get("tags") or [None])[0]
			routes.append(
				{
					"method": method.upper(),
					"path": path,
					"auth": auth,
					"domain": tag_to_domain.get(tag, "d00"),
					"operation_id": op.get("operationId"),
				}
			)
	return routes


def reconcile(
	routes: list[dict[str, Any]], tier_overrides: dict[tuple[str, str], str]
) -> list[dict[str, Any]]:
	"""Refuse to generate when the spec and the tier table disagree, so no endpoint
	reaches the gateway without a deliberate throttling tier."""
	spec_keys = {(r["method"], r["path"]) for r in routes}
	override_keys = set(tier_overrides)
	missing, stale = spec_keys - override_keys, override_keys - spec_keys
	if missing or stale:
		msg = ["Spec <-> TIER_OVERRIDES mismatch -- refusing to generate adc.yaml.", ""]
		if missing:
			msg.append(f"In the spec but with no assigned throttling tier ({len(missing)}):")
			msg.extend(f"  {m} {p}" for m, p in sorted(missing))
		if stale:
			msg.append(f"In TIER_OVERRIDES but no longer in the spec ({len(stale)}):")
			msg.extend(f"  {m} {p}" for m, p in sorted(stale))
		msg += ["", "Assign a tier for each route and re-run."]
		raise SystemExit("\n".join(msg))
	for r in routes:
		r["tier"] = tier_overrides[(r["method"], r["path"])]
	return routes


def to_apisix_uri(path: str) -> str:
	"""OpenAPI `{name}` -> radixtree `:name`. Needs `router.http:
	radixtree_uri_with_parameter` in the gateway's config.yaml."""
	return re.sub(r"\{(\w+)\}", r":\1", path)


def limit_count(tier: dict[str, Any], gateway_jwt: bool) -> dict[str, Any]:
	# An unverified Authorization header is attacker-chosen, so keying on it would hand
	# every forged value a fresh bucket. Without gateway JWT checks, limit by address.
	var = LIMIT_KEYS[tier["limit_by"]] if gateway_jwt else LIMIT_KEYS["ip"]
	return {
		# limit-count refuses two rules with the same key (they would share a counter),
		# so each window gets its own suffix. Written `$var`, not `${var}`: ADC expands
		# `${...}` from the environment when it loads the file, which empties the key.
		"rules": [
			{"count": tier["minute"], "time_window": 60, "key": f"${var}:min"},
			{"count": tier["hour"], "time_window": 3600, "key": f"${var}:hour"},
		],
		"rejected_code": 429,
		"show_limit_quota_header": True,
		"policy": "redis",
		"redis_host": env("APISIX_REDIS_HOST", "redis"),
		"redis_port": int(env("APISIX_REDIS_PORT", "6379")),
		# Same as Kong's fault_tolerant: keep serving if the limiter store is down.
		"allow_degradation": True,
	}


def jwt_auth() -> dict[str, Any]:
	return {"header": "authorization", "key_claim_name": "iss", "hide_credentials": False}


def upstream(
	*, host_env: str, host_default: str, port_env: str, port_default: int, **extra
) -> dict[str, Any]:
	"""A single-node upstream. `host`/`port` come from the environment."""
	return {
		"scheme": "http",
		"nodes": [
			{
				"host": env(host_env, host_default),
				"port": int(env(port_env, str(port_default))),
				"weight": 1,
			}
		],
		**extra,
	}


def build_document(
	routes: list[dict[str, Any]],
	*,
	app: str,
	tiers: dict[str, dict[str, Any]],
	api_upstream: dict[str, Any],
	service_plugins: dict[str, Any],
	extra_services: list[dict[str, Any]] | None = None,
	consumers: list[dict[str, Any]] | None = None,
	gateway_jwt: bool = False,
) -> dict[str, Any]:
	"""Assemble the adc.yaml document for one app.

	Everything carries the label `app: <app>`, so `adc sync --label-selector app=<app>`
	touches only this app's resources and several apps can share one APISIX.

	`gateway_jwt=False` (default): the gateway rate-limits, caps bodies and handles CORS,
	but does not verify tokens. Bearer routes are passed to Frappe, whose `auth_hooks`
	middleware accepts both oan_auth_service tokens and OpenG2P IAM tokens. `True` adds
	`jwt-auth` on bearer routes, which only accepts tokens from the `consumers` given.

	Route paths come from the public spec (`/v1/...`), the only spelling the gateway
	serves. A service-level `proxy-rewrite` sends them to Frappe as `/api/v1/...`.
	"""
	labels = {"app": app}

	groups: dict[tuple[str, str, str], list[str]] = {}
	for r in routes:
		groups.setdefault((r["tier"], r["auth"], r["method"]), []).append(to_apisix_uri(r["path"]))

	adc_routes = []
	for (tier, auth, method), uris in sorted(groups.items()):
		plugins = {"limit-count": limit_count(tiers[tier], gateway_jwt)}
		if auth == "bearer" and gateway_jwt:
			plugins["jwt-auth"] = jwt_auth()
		adc_routes.append(
			{
				"name": f"{app}-{tier}-{auth}-{method.lower()}",
				"description": tiers[tier].get("note", tier),
				"labels": {**labels, "tier": tier, "auth": auth},
				"uris": sorted(set(uris)),
				"methods": [method],
				"plugins": plugins,
			}
		)

	# Browsers send CORS preflights as OPTIONS, which no spec operation declares, so
	# without a route of their own they would 404 before the service's cors plugin runs.
	# Scoped to this app's own first path segments so two apps' preflight routes never
	# share a uri. No tier plugins: a preflight carries no credentials.
	# `/x/*` does not match `/x` itself, so list the collection root too.
	roots = {"/".join(r["path"].split("/")[:3]) for r in routes}
	adc_routes.append(
		{
			"name": f"{app}-cors-preflight",
			"labels": {**labels, "tier": "preflight", "auth": "public"},
			"uris": sorted(roots | {root + "/*" for root in roots}),
			"methods": ["OPTIONS"],
		}
	)

	service = {
		"name": f"{app}-service-v1",
		"labels": labels,
		"upstream": api_upstream,
		"plugins": {
			**service_plugins,
			# Public `/v1/...` -> Frappe `/api/v1/...`.
			"proxy-rewrite": {"regex_uri": ["^/(v[0-9]+)/(.*)", UPSTREAM_PREFIX + "/$1/$2"]},
		},
		"routes": adc_routes,
	}

	doc: dict[str, Any] = {"services": [service, *(extra_services or [])]}
	if gateway_jwt and consumers:
		doc["consumers"] = [{**c, "labels": labels} for c in consumers]
	return doc


def service_plugins(
	*, methods: str, credentials: bool, max_body_mb: int, cors_origins: str | None = None
) -> dict[str, Any]:
	"""Plugins applied to every route of the service: CORS and body cap. `request-id` and
	`prometheus` are global rules in the central, DevOps-owned adc.yaml."""
	return {
		"cors": {
			# `allow_origins` must not be the default `*`; the regex list is the allowlist.
			"allow_origins": "null",
			"allow_origins_by_regex": [
				cors_origins or env("CORS_ORIGINS_REGEX", r"https?://localhost(:[0-9]+)?")
			],
			"allow_methods": methods,
			"allow_headers": "Authorization,Content-Type,X-Request-Id,X-CSRF-Token",
			"allow_credential": credentials,
			"max_age": 3600,
		},
		"client-control": {"max_body_size": max_body_mb * 1024 * 1024},
	}


def socket_service(
	*,
	app: str,
	upstream: dict[str, Any],
	session_cookies: list[dict[str, Any]],
	browser_origins: list[str],
	frappe_web_origin: str,
	site_name: str,
	limit: dict[str, Any],
) -> dict[str, Any]:
	"""The realtime service in front of Frappe's Node socket.io server (`bench socketio`).

	Frappe's socket server knows two credentials: an `Authorization` header, or the desk
	`sid` cookie. It forwards one of them to `frappe.realtime.get_user_info` on the host
	named by the handshake's `Origin`, after checking that `Origin` and `Host` name the
	same host. A browser cannot set headers on a WebSocket, and its session token is in a
	cookie Frappe does not read, so the gateway does the translation:

	- A native client sends `Authorization: Bearer`. It is passed on unchanged.
	- A browser sends a session cookie. One route per entry in `session_cookies` copies
	  that cookie into `Authorization: Bearer`. The entries are tried in order: a route
	  matches only when no earlier entry's cookie is present.

	Frappe still verifies the token: get_user_info runs through this app's auth_hooks.

	The browser routes match only an `Origin` in `browser_origins`. A cookie is sent by
	the browser on its own, so without this check any site could open a socket as the
	signed-in user (cross-site WebSocket hijacking). Frappe's own Origin check cannot
	do this, because the gateway replaces the Origin. Requests that match no route,
	including a cookie from another origin, get a 404 from the gateway.

	`Origin` is set to `frappe_web_origin`, never to a client value such as `$host`.
	Node sends the token and its socket secret to that address, so a client-chosen
	value would let anyone point that request at a server of their own. `Host` is set to
	the same host, to pass Frappe's check. The `Cookie` header is always removed, so the
	desk `sid` never reaches Node through the gateway.

	Each `session_cookies` entry: `name` (route suffix), `cookie` (holds the token),
	`require` (other cookies that must be present, optional).
	"""
	labels = {"app": app}
	web_host = re.sub(r"^\w+://", "", frappe_web_origin).split("/")[0].split(":")[0]

	def rewrite(authorization: str | None) -> dict[str, Any]:
		headers: dict[str, Any] = {
			"set": {"Origin": frappe_web_origin, "X-Frappe-Site-Name": site_name},
			"remove": ["Cookie"],
		}
		if authorization:
			headers["set"]["Authorization"] = authorization
		return {"host": web_host, "headers": headers}

	def cookie_var(name: str) -> str:
		# `$name` when the name allows it. A name with `-` needs `${...}` in APISIX; ADC
		# leaves `${...}` alone when the name is not a plain word, so it survives the load.
		return f"$cookie_{name}" if re.fullmatch(r"\w+", name) else "${cookie_" + name + "}"

	def route(name: str, auth: str, vars_: list[list[Any]], authorization: str | None, priority: int):
		return {
			"name": f"{app}-realtime-socket-io-{name}",
			"labels": {**labels, "tier": "realtime", "auth": auth},
			"uris": ["/socket.io/", "/socket.io/*"],
			"vars": vars_,
			"priority": priority,
			"enable_websocket": True,
			"plugins": {
				# Handshakes, not messages: each connection is one request.
				"limit-count": copy.deepcopy(limit),
				"proxy-rewrite": rewrite(authorization),
			},
		}

	# A header wins over a cookie, as in Frappe's own socket server.
	routes = [route("bearer", "bearer", [["http_authorization", "~~", "^Bearer .+"]], None, 10)]
	earlier: list[str] = []
	for entry in session_cookies:
		cookie = entry["cookie"]
		vars_: list[list[Any]] = [["http_origin", "in", list(browser_origins)]]
		vars_ += [[f"cookie_{c}", "~~", ".+"] for c in [cookie, *entry.get("require", [])]]
		vars_ += [[f"cookie_{c}", "!", "~~", ".+"] for c in earlier]
		routes.append(route(f"cookie-{entry['name']}", "cookie", vars_, f"Bearer {cookie_var(cookie)}", 0))
		earlier.append(cookie)

	return {
		"name": f"{app}-realtime-v1",
		"labels": labels,
		"upstream": upstream,
		"routes": routes,
	}


def write_document(doc: dict[str, Any], path: Path, header_lines: list[str]) -> None:
	with open(path, "w") as f:  # nosemgrep: frappe-security-file-traversal
		for line in header_lines:
			f.write(f"# {line}\n")
		yaml.safe_dump(doc, f, sort_keys=False, default_flow_style=False, width=100)


def report(path: Path, routes: list[dict[str, Any]], doc: dict[str, Any], spec: dict[str, Any]) -> None:
	n_routes = sum(len(s.get("routes", [])) for s in doc["services"])
	sys.stderr.write(
		f"Wrote {path.name}: {len(routes)} operations from {len(spec['paths'])} paths -> "
		f"{n_routes} routes in {len(doc['services'])} service(s)\n"
	)
