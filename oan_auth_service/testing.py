"""Test helpers shared by every app that depends on oan_auth_service.

Plain functions, no base class: callers keep whatever test class they already
use. Each app owns its own URL map, so `api_request` takes that app's dispatcher
rather than importing one.
"""

import json as jsonlib

import frappe
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request, Response

from oan_auth_service.api import tokens
from oan_auth_service.api.middleware import validate_jwt_request


def bearer_for(user: str) -> str:
	"""A signed access token for `user`, carrying the roles the server resolves for them.

	The site needs JWT key material (`jwt_private_keys`, `jwt_current_kid`), as
	`oan_auth_service.tests.utils.configured_keys` provides.
	"""
	token, _ttl = tokens.issue_access_token(user, tokens.resolve_roles(user))
	return token


def api_request(
	dispatch,
	method: str,
	path: str,
	json: dict | None = None,
	query: dict | None = None,
	user: str | None = None,
	token: str | None = None,
	headers: dict | None = None,
) -> Response:
	"""Send one request through the JWT middleware and `dispatch`, as the gateway would.

	`user` mints a token for that user; `token` sends one as given; neither sends
	no credentials. `dispatch` is the app's `dispatch_rest_request`. The session
	user is restored afterwards, so one call cannot leak a login into the next.
	"""
	request_headers = dict(headers or {})
	if user and not token:
		token = bearer_for(user)
	if token:
		request_headers["Authorization"] = f"Bearer {token}"

	builder = EnvironBuilder(
		path=path,
		method=method.upper(),
		json=json,
		query_string=query,
		headers=request_headers,
	)
	request = Request(builder.get_environ())

	previous_user = frappe.session.user
	frappe.set_user("Guest")  # nosemgrep: frappe-semgrep-rules.rules.security.frappe-setuser
	frappe.local.request = request
	frappe.local.request_ip = "127.0.0.1"
	frappe.local.form_dict = frappe._dict({**(query or {}), **(json or {})})
	frappe.local.response = frappe._dict({})
	try:
		try:
			validate_jwt_request(request)
		except Exception as exc:
			return _error_response(exc)
		return dispatch(request)
	finally:
		frappe.set_user(previous_user)  # nosemgrep: frappe-semgrep-rules.rules.security.frappe-setuser


def _error_response(exc: Exception) -> Response:
	"""What Frappe's `handle_exception` would send for an error raised by the middleware."""
	status = getattr(exc, "http_status_code", None) or 500
	body = {"status": "error", "message": str(exc), "code": type(exc).__name__}
	return Response(jsonlib.dumps(body), status=status, mimetype="application/json")
