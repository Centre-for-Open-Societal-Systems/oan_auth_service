"""Build an ADC (APISIX Declarative CLI) config from an OpenAPI spec.

Shared by every Frappe app that fronts its REST API with APISIX (oan_grievance_service,
oan_a2c). Each app keeps its own throttling tiers and its own `(method, path) -> tier`
table, and calls `build_document` with them. The output is `adc.yaml`, which
`adc lint|validate|diff|sync` apply to an APISIX running in etcd mode, and the app's
Ingress Controller chart (`write_helm_templates`).

oan_auth_service is a library installed into each app's bench, not a service of its own,
so it has no gateway config. Its endpoints are served by every bench that installs it,
and each app adds them to its own config with `with_auth_routes`.

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


# ---------------------------------------------------------------------------
# oan_auth_service's own endpoints
# ---------------------------------------------------------------------------
# Owned here, added to each app's config by `with_auth_routes` and pointed at that app's
# Frappe. Tiers are prefixed `auth-` so they never collide with an app's own tier names.
AUTH_SPEC_PATH = Path(__file__).resolve().parent.parent / "openapi" / "openapi_v1.public.yaml"
AUTH_TIERS = {
	"auth-credentials": {
		"limit_by": "ip",
		"minute": 5,
		"hour": 30,
		"policy": "redis",
		"fail_open": False,
		"note": "Credential-sensitive endpoints (login, register, logout, reset). Tight IP limits to prevent stuffing. Rejects requests when the limiter store is down.",
	},
	"auth-session": {
		"limit_by": "consumer",
		"minute": 120,
		"hour": 4000,
		"policy": "redis",
		"note": "Logged-in user calls (e.g. /me) and token refresh. Cheap and frequent.",
	},
	"auth-admin": {
		"limit_by": "consumer",
		"minute": 60,
		"hour": 1000,
		"policy": "redis",
		"note": "Admin user and role management. Low volume. Keyed per IP while GATEWAY_JWT is off; per token once the gateway verifies tokens.",
	},
	"auth-public-read": {
		"limit_by": "ip",
		"minute": 120,
		"hour": 2000,
		"policy": "redis",
		"note": "Public discovery and health check endpoints.",
	},
}

AUTH_TIER_OVERRIDES = {
	("POST", "/v1/auth/register"): "auth-credentials",
	("POST", "/v1/auth/login"): "auth-credentials",
	("POST", "/v1/auth/refresh"): "auth-session",
	("POST", "/v1/auth/logout"): "auth-credentials",
	("POST", "/v1/auth/forgot-password"): "auth-credentials",
	("POST", "/v1/auth/reset-password"): "auth-credentials",
	("POST", "/v1/auth/password/forgot"): "auth-credentials",
	("POST", "/v1/auth/password/reset"): "auth-credentials",
	("POST", "/v1/auth/password/initial"): "auth-credentials",
	("GET", "/v1/auth/me"): "auth-session",
	("GET", "/v1/auth/keys"): "auth-public-read",
	("GET", "/v1/auth/health"): "auth-public-read",
	("GET", "/v1/auth/metadata"): "auth-public-read",
	("GET", "/v1/auth/iam/providers"): "auth-public-read",
	("POST", "/v1/auth/iam/login"): "auth-credentials",
	("GET", "/v1/admin/users"): "auth-admin",
	("POST", "/v1/admin/users"): "auth-admin",
	("GET", "/v1/admin/users/{user_id}"): "auth-admin",
	("PATCH", "/v1/admin/users/{user_id}"): "auth-admin",
	("DELETE", "/v1/admin/users/{user_id}/sessions"): "auth-admin",
	("POST", "/v1/admin/users/{user_id}/temporary-password"): "auth-admin",
	("GET", "/v1/admin/users/{user_id}/roles"): "auth-admin",
	("POST", "/v1/admin/users/{user_id}/roles"): "auth-admin",
	("DELETE", "/v1/admin/users/{user_id}/roles/{role}"): "auth-admin",
	("GET", "/v1/admin/roles"): "auth-admin",
	("GET", "/v1/admin/permissions"): "auth-admin",
	("PUT", "/v1/admin/permissions"): "auth-admin",
	("DELETE", "/v1/admin/permissions"): "auth-admin",
	("POST", "/v1/admin/permissions/reset"): "auth-admin",
	("GET", "/v1/notifications"): "auth-session",
	("PATCH", "/v1/notifications"): "auth-session",
	("DELETE", "/v1/notifications"): "auth-session",
	("GET", "/v1/notifications/{notification_id}"): "auth-session",
	("PATCH", "/v1/notifications/{notification_id}"): "auth-session",
	("DELETE", "/v1/notifications/{notification_id}"): "auth-session",
}


def with_auth_routes(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
	"""An app's reconciled routes plus oan_auth_service's. Refuses a (method, path) both
	declare, which would give one URL two routes."""
	auth = reconcile(spec_routes(load_spec(AUTH_SPEC_PATH)), AUTH_TIER_OVERRIDES)
	clash = {(r["method"], r["path"]) for r in routes} & {(r["method"], r["path"]) for r in auth}
	if clash:
		raise SystemExit(
			"Declared by both the app and oan_auth_service:\n"
			+ "\n".join(f"  {m} {p}" for m, p in sorted(clash))
		)
	return routes + auth


def jwt_issuer_consumer() -> dict[str, Any]:
	"""Verifies the RS256 bearer tokens oan_auth_service mints. Needed only by an app that
	sets `gateway_jwt=True`."""
	public_key = env("OAN_AUTH_JWT_PUBLIC_KEY", "")
	if not public_key:
		raise SystemExit("gateway_jwt is on: set OAN_AUTH_JWT_PUBLIC_KEY (PEM) to generate the consumer.")
	return {
		"username": "oan-auth-jwt-issuer",
		"plugins": {
			"jwt-auth": {
				"key": env("OAN_JWT_ISSUER", "oan-auth"),
				"algorithm": "RS256",
				"public_key": public_key,
			}
		},
	}


def to_apisix_uri(path: str) -> str:
	"""OpenAPI `{name}` -> radixtree `:name`. Needs `router.http:
	radixtree_uri_with_parameter` in the gateway's config.yaml."""
	return re.sub(r"\{(\w+)\}", r":\1", path)


def limit_count(tier: dict[str, Any], gateway_jwt: bool, auth: str = "bearer") -> dict[str, Any]:
	# An unverified Authorization header is attacker-chosen, so keying on it would hand
	# every forged value a fresh bucket. Without gateway JWT checks, limit by address.
	# A route that takes no bearer token (such as refresh, which sends its token in the
	# body) has no Authorization header to key on, so it would put every caller in one
	# shared bucket: limit it by address as well.
	by_token = gateway_jwt and auth == "bearer"
	var = LIMIT_KEYS[tier["limit_by"]] if by_token else LIMIT_KEYS["ip"]
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
		# When the limiter store is down, `fail_open` tiers keep serving (Kong's
		# fault_tolerant). Tiers that set it False reject instead, so an outage cannot
		# be used to brute-force credentials.
		"allow_degradation": tier.get("fail_open", True),
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
		plugins = {"limit-count": limit_count(tiers[tier], gateway_jwt, auth)}
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
	`prometheus` are gateway-wide global rules, owned by the central gateway config
	(oan-helm `environments/<env>/values/apisix.yaml`), not by the apps."""
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


# ---------------------------------------------------------------------------
# Kubernetes: the same document as APISIX Ingress Controller resources
# ---------------------------------------------------------------------------
# Written as Helm templates for the app's gateway chart. `${NAME}` placeholders in the
# document become `.Values` expressions, and one-item sentinel lists become loops over a
# values list. The values themselves live in the deployment repository (oan-helm).
HELM_COMMON_VALUES = {
	"APISIX_REDIS_HOST": ".Values.redis.host",
	"INGRESS_CLASS_NAME": ".Values.ingressClassName",
}
HELM_LISTS = {
	"__HOSTS__": ".Values.hosts",
	"__REALTIME_ORIGINS__": ".Values.realtimeAllowedOrigins",
	"__CORS_ORIGIN_REGEXES__": ".Values.corsOriginRegexes",
	"__IP_ALLOWLIST__": ".Values.ipAllowlist",
}
EXPR_OPS = {"~~": "RegexMatch", "~*": "RegexMatchCaseInsensitive", "in": "In", "==": "Equal"}
EXPR_NEGATED = {
	"RegexMatch": "RegexNotMatch",
	"RegexMatchCaseInsensitive": "RegexNotMatchCaseInsensitive",
	"In": "NotIn",
	"Equal": "NotEqual",
}


def to_expr(var: list) -> dict[str, Any]:
	"""An ADC `vars` entry (`[name, op, value]`, `[name, "!", op, value]`) as an ApisixRoute expr."""
	name, *rest = var
	negate = rest[0] == "!"
	op, value = rest[1:] if negate else rest
	op = EXPR_OPS[op]
	if negate:
		op = EXPR_NEGATED[op]
	if name == "http_origin":
		value = ["__REALTIME_ORIGINS__"]
	return {
		"subject": {"scope": "Variable", "name": name},
		"op": op,
		("set" if op in ("In", "NotIn") else "value"): value,
	}


def to_crd_plugins(plugins: dict[str, Any]) -> list[dict[str, Any]]:
	out = []
	for name, config in plugins.items():
		config = copy.deepcopy(config)
		if "redis_host" in config:
			config["redis_host"] = "${APISIX_REDIS_HOST}"
		if name == "cors":
			config["allow_origins_by_regex"] = ["__CORS_ORIGIN_REGEXES__"]
		if name == "ip-restriction":
			config["whitelist"] = ["__IP_ALLOWLIST__"]
		if name == "consumer-restriction":
			# The Ingress Controller names an ApisixConsumer's APISIX consumer
			# `<namespace>_<name>`.
			config["whitelist"] = [f"{{{{ .Release.Namespace }}}}_{c}" for c in config["whitelist"]]
		out.append({"name": name, "enable": True, "config": config})
	return out


def to_crd_route(
	route: dict[str, Any], shared_plugins: dict[str, Any], backend: dict[str, Any]
) -> dict[str, Any]:
	match: dict[str, Any] = {"hosts": ["__HOSTS__"], "paths": route["uris"]}
	if "methods" in route:
		match["methods"] = route["methods"]
	if route.get("vars"):
		match["exprs"] = [to_expr(v) for v in route["vars"]]
	rule: dict[str, Any] = {"name": route["name"]}
	if "priority" in route:
		rule["priority"] = route["priority"]
	if route.get("enable_websocket"):
		rule["websocket"] = True
	rule["match"] = match
	# Route plugins win over the service's, as in ADC.
	rule["plugins"] = to_crd_plugins({**shared_plugins, **route.get("plugins", {})})
	rule["backends"] = [dict(backend)]
	return rule


def to_crd_upstream(
	service: dict[str, Any],
	service_name: str,
	labels: dict[str, str],
	external: tuple[str, str] | None = None,
) -> dict[str, Any]:
	"""Named after the Kubernetes Service it configures. `external` is the
	`(host, port)` placeholders of a node outside the cluster, see helm_external."""
	up = service["upstream"]
	spec: dict[str, Any] = {}
	if external:
		spec["externalNodes"] = [{"type": "Domain", "name": external[0], "port": external[1]}]
	spec |= {"scheme": up["scheme"], "passHost": up["pass_host"]}
	if "upstream_host" in up:
		spec["upstreamHost"] = up["upstream_host"]
	spec["retries"] = up["retries"]
	spec["timeout"] = {k: f"{v}s" for k, v in up["timeout"].items()}
	return {
		"apiVersion": "apisix.apache.org/v2",
		"kind": "ApisixUpstream",
		"metadata": {"name": service_name, "labels": labels},
		"spec": spec,
	}


def to_crd_consumer(consumer: dict[str, Any], labels: dict[str, str]) -> dict[str, Any]:
	"""A key-auth consumer. Its key is read from the Secret named after the consumer
	(key `key`), provisioned in the release namespace outside Git."""
	if set(consumer.get("plugins", {})) != {"key-auth"}:
		raise SystemExit(f"Consumer {consumer['username']}: only key-auth consumers are supported.")
	return {
		"apiVersion": "apisix.apache.org/v2",
		"kind": "ApisixConsumer",
		"metadata": {"name": consumer["username"], "labels": labels},
		"spec": {
			"ingressClassName": "${INGRESS_CLASS_NAME}",
			"authParameter": {"keyAuth": {"secretRef": {"name": consumer["username"]}}},
		},
	}


def helm_render(text: str, values: dict[str, str], required: set[str], ints: set[str]) -> str:
	"""Swap the `${NAME}` placeholders and list sentinels for Helm expressions.

	Only names in `values` are replaced: nginx variables such as `${cookie_x}` stay.
	A name in `required` fails the render when unset; a name in `ints` is left unquoted.
	"""
	for sentinel, path in HELM_LISTS.items():
		loop = rf"{{{{- range {path} }}}}\n\1- {{{{ . | quote }}}}\n{{{{- end }}}}"
		if sentinel == "__HOSTS__":
			# No hosts: drop the key, so the route matches any host.
			text = re.sub(
				rf"^( *)hosts:\n *- {sentinel}$",
				rf"{{{{- if {path} }}}}\n\1hosts:\n" + loop + r"\n{{- end }}",
				text,
				flags=re.M,
			)
		else:
			text = re.sub(rf"^( *)- {sentinel}$", loop, text, flags=re.M)
	out = []
	for line in text.split("\n"):
		whole = re.fullmatch(r"(\s*(?:- )?(?:[^\s:][^:]*:\s+)?)\$\{(\w+)\}", line)
		if whole and whole[2] in values:
			expr = values[whole[2]]
			if whole[2] in required:
				expr = f'required "{expr.removeprefix(".Values.")} is required" {expr}'
			quote = "" if whole[2] in ints else " | quote"
			line = f"{whole[1]}{{{{ {expr}{quote} }}}}"
		else:
			line = re.sub(
				r"\$\{(\w+)\}",
				lambda m: f"{{{{ {values[m[1]]} }}}}" if m[1] in values else m[0],
				line,
			)
		out.append(line)
	return "\n".join(out)


def helm_external(text: str, backends: list[tuple[str, str, str]], values: dict[str, str]) -> str:
	"""Make each external-capable backend switch on its external host value.

	Set (a non-empty list of hosts): the ApisixUpstream lists every host as a node, with
	the app's optional `healthCheck` block copied from its values, and routes reference
	that upstream by name, so APISIX balances across an app in another cluster. Unset: the
	externalNodes block is dropped and routes keep `backends`, so the controller resolves
	the in-cluster Service.
	"""
	for name, port, host in backends:
		cond = values[host.strip("${}")]
		n, p, h = (re.escape(s) for s in (name, port, host))
		port_expr = "$" + values[port.strip("${}")]
		text, routes = re.subn(
			rf"^( *)backends:\n\1- serviceName: {n}\n\1  servicePort: {p}$",
			rf"{{{{- if {cond} }}}}\n\1upstreams:\n\1- name: {name}\n{{{{- else }}}}\n"
			rf"\1backends:\n\1- serviceName: {name}\n\1  servicePort: {port}\n{{{{- end }}}}",
			text,
			flags=re.M,
		)

		def node_list(m: re.Match) -> str:
			i = m[1]
			scope = cond.rsplit(".", 1)[0]
			return (
				f"{{{{- if {cond} }}}}\n{i}externalNodes:\n{{{{- range {cond} }}}}\n"
				f"{i}- type: Domain\n{i}  name: {{{{ . | quote }}}}\n{i}  port: {{{{ {port_expr} }}}}\n{{{{- end }}}}\n"
				f"{{{{- with {scope}.healthCheck }}}}\n{i}healthCheck:\n"
				f"{{{{- toYaml . | nindent {len(i) + 2} }}}}\n{{{{- end }}}}\n{{{{- end }}}}\n"
			)

		text, nodes = re.subn(
			rf"^( *)externalNodes:\n\1- type: Domain\n\1  name: {h}\n\1  port: {p}\n",
			node_list,
			text,
			flags=re.M,
		)
		if not routes and not nodes:
			raise SystemExit(f"No route or upstream found for external backend {name}.")
	return text


def write_helm_templates(
	doc: dict[str, Any],
	out_dir: Path,
	header_lines: list[str],
	*,
	app: str,
	backends: dict[str, tuple[str, ...]],
	values: dict[str, str],
	required: set[str],
	ints: set[str],
) -> None:
	"""The ADC document as APISIX Ingress Controller resources, in Helm template form.

	One ApisixRoute per ADC service, one ApisixUpstream per backend Service carrying the
	service's upstream settings (rewritten Host, timeouts, retries), and one
	ApisixConsumer per consumer. `backends` maps each ADC service name to the
	`(service name, port)` placeholders of its Kubernetes Service, plus optionally an
	external host placeholder for a gateway in another cluster (see helm_external).
	`values` maps the app's own placeholders to `.Values` paths, on top of
	HELM_COMMON_VALUES.
	"""
	labels = {"app": app}
	routes, upstreams, external = [], [], []
	for service in doc["services"]:
		svc_name, svc_port, *ext_host = backends[service["name"]]
		backend = {"serviceName": svc_name, "servicePort": svc_port}
		if ext_host:
			external.append((svc_name, svc_port, ext_host[0]))
		routes.append(
			{
				"apiVersion": "apisix.apache.org/v2",
				"kind": "ApisixRoute",
				"metadata": {"name": service["name"], "labels": labels},
				"spec": {
					"ingressClassName": "${INGRESS_CLASS_NAME}",
					"http": [to_crd_route(r, service.get("plugins", {}), backend) for r in service["routes"]],
				},
			}
		)
		upstreams.append(
			to_crd_upstream(service, svc_name, labels, (ext_host[0], svc_port) if ext_host else None)
		)
	consumers = [to_crd_consumer(c, labels) for c in doc.get("consumers", [])]

	values = {**HELM_COMMON_VALUES, **values}
	out_dir.mkdir(parents=True, exist_ok=True)
	header = "".join(f"# {line}\n" for line in header_lines)
	files = {"apisix-route.yaml": routes, "apisix-upstream.yaml": upstreams}
	if consumers:
		files["apisix-consumer.yaml"] = consumers
	for filename, resources in files.items():
		body = "---\n".join(
			yaml.safe_dump(r, sort_keys=False, default_flow_style=False, width=100) for r in resources
		)
		if filename != "apisix-consumer.yaml":
			body = helm_external(body, external, values)
		(out_dir / filename).write_text(header + helm_render(body, values, required, ints))
