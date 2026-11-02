"""Expose plain Python functions as REST routes on Frappe's own URL map.

Frappe does nearly all of this already, so this module only fills the gaps it
leaves. `frappe/api/__init__.py` matches the request against `API_URL_MAP` and
calls `endpoint(**path_args)`; `frappe/app.py::process_response` adds CORS,
Cache-Control, request-id and any headers left in `frappe.local.response_headers`;
`frappe/app.py::handle_exception` maps a raised exception's `http_status_code`
onto the response. None of that is repeated here.

Three things Frappe does *not* do for a custom rule, which is all this module is:

1. Pass anything but path parameters. Body and query live in `frappe.form_dict`,
   which Frappe has already parsed correctly — for a JSON request it holds the
   body alone, for a form request the query and form merged
   (`frappe/app.py::make_form_dict`).
2. Leave a returned dict alone. Frappe nests it under `frappe.response["data"]`,
   which would double-wrap the envelope `handle_api_errors` builds. Returning a
   Response avoids that.
3. Tell the middleware how each path authenticates. A route declares exactly
   one scheme, `auth="jwt"` (the default), `"api_key"` or `"public"`, and is
   registered with the middleware under it, so the two can never drift apart.

TLS, HSTS and transport security headers belong to nginx. 404/405 belong to
Frappe's matcher. Neither appears here.
"""

import threading
from collections.abc import Callable
from functools import wraps

import frappe
from werkzeug.exceptions import NotFound
from werkzeug.routing import Rule
from werkzeug.wrappers import Response

from oan_auth_service.api.middleware import (
	AUTH_API_KEY,
	AUTH_JWT,
	AUTH_KINDS,
	AUTH_PUBLIC,
	register_namespace,
)

# The namespace this app owns. Registered with the middleware, which matches
# incoming paths by longest prefix.
NAMESPACE = "/api/v1"

_rules: list[Rule] = []
_exempt_paths: set[str] = set()
# path -> roles one of which the API key's user must hold (empty: any).
_api_key_paths: dict[str, tuple[str, ...]] = {}
# Same, for paths that also take a JWT (transitional).
_jwt_or_api_key_paths: dict[str, tuple[str, ...]] = {}
# path -> (auth, roles), to refuse one path declared with two schemes.
_path_auth: dict[str, tuple[str, tuple[str, ...]]] = {}


def rest(
	path: str,
	methods: tuple[str, ...] = ("POST",),
	allow_guest: bool = False,
	status: int = 200,
	summary: str | None = None,
	description: str | None = None,
	tier: str | None = None,
	auth: str | tuple[str, ...] | None = None,
	roles: list[str] | tuple[str, ...] | None = None,
) -> Callable:
	"""Expose `fn` at `path`, and return `fn` unchanged.

	`auth` is the one scheme the path accepts: `"jwt"` (default), `"api_key"`
	(a Frappe API key, as the gateway sends for partners) or `"public"`.
	`roles` applies to `"api_key"` only: the key's user must hold one of them.
	`auth=("jwt", "api_key")` takes either, for callers moving from API keys to
	JWTs; it is a transition, not a design (see the middleware docstring).
	`allow_guest=True` is the older spelling of `auth="public"`. A path takes one
	scheme for all its methods, because the middleware decides by path.

	The wrapper is registered as the rule's endpoint; the module-level name stays
	bound to the original function, so any direct caller is unaffected by the
	function also being routed.

	Exceptions are deliberately not caught. Endpoints carry `@handle_api_errors`,
	which turns them into envelopes already, and anything escaping that is better
	served by Frappe's `handle_exception` than by a second copy of it here.
	"""

	auth, roles = _resolve_auth(path, auth, allow_guest, roles)

	def decorator(fn: Callable) -> Callable:
		@wraps(fn)  # gives readable debug names
		def endpoint(**path_args):
			# The only installed-app check needed: API_URL_MAP is shared by every
			# site a worker serves, so these rules match on sites without this app.
			if "oan_auth_service" not in frappe.get_installed_apps():
				raise NotFound()

			params = {**frappe.form_dict, **path_args}
			filtered_args = frappe.get_newargs(fn, params)
			result = fn(**filtered_args)

			if isinstance(result, Response):
				return result

			code = frappe.local.response.pop("http_status_code", None) or status

			res = Response(
				frappe.as_json(result, indent=None),
				status=code,
				content_type="application/json",
			)
			# This service's correlation id, honoured from the caller's inbound
			# header and repeated in the envelope. Frappe's X-Frappe-Request-Id is
			# a separate, internally generated trace id.
			if req_id := getattr(frappe.local, "request_id", None):
				res.headers["X-Request-Id"] = req_id
			return res

		endpoint._route = {
			"path": path,
			"methods": tuple(m.upper() for m in methods),
			"summary": summary,
			"description": description,
			"allow_guest": auth == AUTH_PUBLIC,
			"auth": auth,
			"roles": roles,
			"status": status,
			"tier": tier,
		}
		_rules.append(Rule(path, endpoint=endpoint, methods=[m.upper() for m in methods]))
		_path_auth[path] = (auth, roles)
		if auth == AUTH_PUBLIC:
			_exempt_paths.add(path)
		elif auth == AUTH_API_KEY:
			_api_key_paths[path] = roles
		elif auth == (AUTH_JWT, AUTH_API_KEY):
			_jwt_or_api_key_paths[path] = roles
		return fn

	return decorator


def _resolve_auth(path: str, auth, allow_guest: bool, roles) -> tuple[str | tuple[str, str], tuple[str, ...]]:
	"""Validate a route's declared scheme at import time, where a mistake is cheapest.

	Returns a single scheme as a string, or `("jwt", "api_key")`, the one
	combination allowed: `public` combines with nothing.
	"""
	if allow_guest:
		if auth not in (None, AUTH_PUBLIC):
			raise ValueError(f"{path}: allow_guest=True conflicts with auth={auth!r}")
		auth = AUTH_PUBLIC
	auth = auth or AUTH_JWT
	if isinstance(auth, list | tuple):
		if len(auth) == 2 and set(auth) == {AUTH_JWT, AUTH_API_KEY}:
			auth = (AUTH_JWT, AUTH_API_KEY)
		elif len(auth) == 1:
			auth = auth[0]
		else:
			raise ValueError(f"{path}: the only combined scheme is ('jwt', 'api_key'), not {auth!r}")
	if auth != (AUTH_JWT, AUTH_API_KEY) and auth not in AUTH_KINDS:
		raise ValueError(f"{path}: auth must be one of {AUTH_KINDS}, not {auth!r}")
	roles = tuple(roles or ())
	if roles and auth not in (AUTH_API_KEY, (AUTH_JWT, AUTH_API_KEY)):
		raise ValueError(f"{path}: roles apply to routes taking an API key only")
	previous = _path_auth.get(path)
	if previous is not None and previous != (auth, roles):
		raise ValueError(f"{path}: already declared with auth={previous[0]!r}; one scheme per path")
	return auth, roles


def prefixed(prefix: str) -> Callable:
	"""Return a `rest` bound to a path prefix, so routes group without repetition."""

	def bound(path: str, **kwargs) -> Callable:
		return rest(prefix + path, **kwargs)

	return bound


_REGISTERED = False
_REGISTRATION_LOCK = threading.Lock()


def ensure_routes_registered() -> None:
	"""Add every declared rule to Frappe's URL map and claim the namespace.

	Wired as a `before_request` hook. The rule list and the middleware registry
	are per-process in-memory state, so this has to run in each worker rather
	than once at install time. Frappe only runs hooks of apps installed on the
	current site, so no installed-app check is needed here.
	"""
	global _REGISTERED
	if _REGISTERED:
		return

	# This runs on the first request and the dev server is threaded. Two requests
	# arriving together both found _REGISTERED unset, both walked the list, and
	# the second add raised "url rule already bound" and answered 500.
	with _REGISTRATION_LOCK:
		if _REGISTERED:
			return

		import frappe.api

		# Importing the endpoint module is what executes the `rest(...)` calls.
		from oan_auth_service.api.v1 import admin, auth, notifications

		# An unbound copy each time: a Rule binds to one map only, and another app
		# sharing this list may already have added it. Rules compare by pattern, so
		# the membership check is enough to skip those.
		for rule in _rules:
			if rule not in frappe.api.API_URL_MAP._rules:
				frappe.api.API_URL_MAP.add(rule.empty())

		# Bare paths only: the middleware already retries with the trailing slash
		# stripped, so registering both spellings would be redundant.
		register_declared_paths()
		_REGISTERED = True


def register_declared_paths(prefix: str = NAMESPACE) -> None:
	"""Register every path declared through `rest` so far with the middleware, by scheme.

	A consumer that declares its routes with this module's `rest` calls this after
	importing its route modules, so its public and API-key paths are registered
	too. Registration is additive, so calling it again is safe.
	"""
	register_namespace(
		prefix=prefix,
		exempt_paths=sorted(_exempt_paths),
		api_key_paths=dict(_api_key_paths),
		jwt_or_api_key_paths=dict(_jwt_or_api_key_paths),
	)
