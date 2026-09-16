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
3. Tell the JWT middleware which paths are reachable without a token. Routes
   declared `allow_guest=True` are registered as exempt paths, so the two can
   never drift apart.

TLS, HSTS and transport security headers belong to nginx. 404/405 belong to
Frappe's matcher. Neither appears here.
"""

from collections.abc import Callable
from functools import wraps

import frappe
from werkzeug.routing import Rule
from werkzeug.wrappers import Response

from oan_auth_service.api.middleware import register_namespace

# The namespace this app owns. Registered with the middleware, which matches
# incoming paths by longest prefix.
NAMESPACE = "/api/v1"

_rules: list[Rule] = []
_exempt_paths: set[str] = set()


def rest(
	path: str,
	methods: tuple[str, ...] = ("POST",),
	allow_guest: bool = False,
	status: int = 200,
	summary: str | None = None,
) -> Callable:
	"""Expose `fn` at `path`, and return `fn` unchanged.

	The wrapper is registered as the rule's endpoint; the module-level name stays
	bound to the original function, so the RPC surface (`@frappe.whitelist`) and
	any direct caller are unaffected by the function also being routed.

	Exceptions are deliberately not caught. Endpoints carry `@handle_api_errors`,
	which turns them into envelopes already, and anything escaping that is better
	served by Frappe's `handle_exception` than by a second copy of it here.
	"""

	def decorator(fn: Callable) -> Callable:
		@wraps(fn)
		def endpoint(**path_args):
			params = {**frappe.form_dict, **path_args}
			params.pop("cmd", None)
			result = frappe.call(fn, **params)

			if isinstance(result, Response):
				return result

			code = status
			response = getattr(frappe.local, "response", None)
			if response and response.get("http_status_code"):
				code = response.pop("http_status_code")

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
			"allow_guest": allow_guest,
		}
		_rules.append(Rule(path, endpoint=endpoint, methods=[m.upper() for m in methods]))
		if allow_guest:
			_exempt_paths.add(path)
		return fn

	return decorator


def prefixed(prefix: str) -> Callable:
	"""Return a `rest` bound to a path prefix, so routes group without repetition."""

	def bound(path: str, **kwargs) -> Callable:
		return rest(prefix + path, **kwargs)

	return bound


def registered_routes() -> list[dict]:
	"""Metadata for every declared route. For diagnostics and spec generation."""
	return [rule.endpoint._route for rule in _rules]


_REGISTERED = False


def ensure_routes_registered() -> None:
	"""Add every declared rule to Frappe's URL map and claim the namespace.

	Wired as a `before_request` hook. The rule list and the middleware registry
	are per-process in-memory state, so this has to run in each worker rather
	than once at install time.
	"""
	global _REGISTERED
	if _REGISTERED:
		return

	import frappe.api

	# Importing the endpoint module is what executes the `rest(...)` calls.
	from oan_auth_service.api.v1 import auth

	for rule in _rules:
		frappe.api.API_URL_MAP.add(rule)

	# Bare paths only: the middleware already retries with the trailing slash
	# stripped, so registering both spellings would be redundant.
	register_namespace(prefix=NAMESPACE, exempt_paths=sorted(_exempt_paths))
	_REGISTERED = True
