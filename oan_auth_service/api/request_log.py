"""Request and response logging, and the correlation id every other log line leans on.

Two Frappe hooks (see hooks.py), for every OAN app on the site:

`begin` is a `before_request` hook. Frappe runs those before the auth hooks, so a request the
auth layer refuses still has a correlation id, a start time, and a place in the log. It adopts
a plain `X-Request-Id` from the caller (the gateway, or a client tracing its own call) and
otherwise mints one. The envelope helpers in `utils.py` read the same `frappe.local.request_id`,
so the id is the `request_id` in the response body and the `X-Request-Id` response header.

`end` is an `after_request` hook. Frappe runs those in a `finally`, so it sees every outcome:
handled envelopes, auth refusals and the framework's own error pages. It writes one
`http.request` event and, for 401, 403 and 429, a `security.*` event.

Frappe starts the session (`HTTPRequest()`) before it runs `before_request` hooks, and
maintenance mode stops a request before them too. A CSRF or session failure, or a site in
maintenance, therefore never reaches `begin`. `end` still runs for it: it adopts or mints the id
there, returns it in the header, and logs the request without a duration (nothing started the
clock), so those requests are not invisible.

What is logged: method, scrubbed path, status, duration, sizes, the masked user and client
address, a trimmed user agent, the *names* of the parameters and body fields, and the error
`code` of a failed response. Never logged: any request or response body, any header value other
than the user agent, any query or form value, the response `message` (an error message can echo
what the caller sent), or a credential.

`oan_slow_request_ms` in site config (default 2000) is the duration above which a request is
logged as slow, at WARNING.
"""

import json
import logging
import re
import time

import frappe
from frappe.utils import flt

from oan_auth_service.api import operational_log as oplog
from oan_auth_service.api.middleware import _match_namespace
from oan_auth_service.api.router import NAMESPACE

CORRELATION_HEADER = "X-Request-Id"
DEFAULT_SLOW_REQUEST_MS = 2000

MAX_LOGGED_NAMES = 30
MAX_ERROR_BODY = 64 * 1024
USER_AGENT_LENGTH = 120

# Uptime monitors hit these every few seconds; a healthy answer is a DEBUG line.
_QUIET_LAST_SEGMENTS = ("health", "ping")
_KNOWN_SCHEMES = {"bearer", "basic", "token"}
_ERROR_CODE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,59}")

# Where a failed sign-in names the account it was for (`usr` on login, password reset).
_IDENTITY_PARAMS = ("usr", "username", "email")


def in_scope(path: str) -> bool:
	"""Whether `path` belongs to an OAN app: the shared REST namespace, or one an app registered.

	Desk pages, assets and Frappe's own methods (the socket server's user lookup is registered by
	an app so a bearer token resolves, but it is not an API call worth a line) are left alone.
	"""
	if path.startswith(f"{NAMESPACE}/"):
		return True
	return not path.startswith("/api/method/frappe.") and _match_namespace(path) is not None


def begin() -> None:
	"""`before_request`: give the request its correlation id and start the clock."""
	try:
		request = frappe.local.request
		if not in_scope(request.path):
			return
		frappe.local.oan_request_started = time.perf_counter()
		oplog.ensure_correlation_id(request.headers.get(CORRELATION_HEADER))
	except Exception:
		# A logging fault must never turn into a failed request.
		pass


def end(response=None, request=None) -> None:
	"""`after_request`: return the id to the caller and log how the request went."""
	if response is None or request is None:
		return
	try:
		if not in_scope(request.path):
			return
		started = getattr(frappe.local, "oan_request_started", None)
		# `begin` did not run if the request failed before before_request hooks (see above).
		oplog.ensure_correlation_id(request.headers.get(CORRELATION_HEADER))
		cid = oplog.correlation_id()
		if cid and CORRELATION_HEADER not in response.headers:
			response.headers[CORRELATION_HEADER] = cid
		duration_ms = None if started is None else round((time.perf_counter() - started) * 1000, 1)
		_log(request, response, duration_ms)
	except Exception:
		pass


def _session_user() -> str | None:
	"""The session's user, or None when the request failed before a session was set up."""
	session = getattr(frappe.local, "session", None)
	return getattr(session, "user", None) if session else None


def _log(request, response, duration_ms: float | None) -> None:
	status = response.status_code
	# A missing, non-numeric, zero or negative setting means the default.
	threshold = max(flt(frappe.conf.get("oan_slow_request_ms")), 0) or DEFAULT_SLOW_REQUEST_MS
	slow = duration_ms is not None and duration_ms >= threshold

	if status >= 500:
		level = logging.ERROR
	elif status >= 400 or slow:
		level = logging.WARNING
	elif request.path.rsplit("/", 1)[-1] in _QUIET_LAST_SEGMENTS:
		level = logging.DEBUG
	else:
		level = logging.INFO

	# Nothing below is built unless a line will be written: at ERROR a busy site pays only
	# for the clock and the id.
	logger = oplog.get_logger()
	logs_request = logger.isEnabledFor(level)
	logs_security = status in (401, 403, 429) and logger.isEnabledFor(logging.WARNING)
	if not (logs_request or logs_security):
		return
	error_code = _error_code(response) if status >= 400 else None

	if logs_request:
		oplog.emit(
			"http.request",
			level,
			method=request.method,
			path=oplog.scrub_path(request.path),
			status=status,
			duration_ms=duration_ms,
			slow=True if slow else None,
			error_code=error_code,
			user=_session_user(),
			client_ip=oplog.mask_ip(getattr(frappe.local, "request_ip", None)),
			user_agent=_user_agent(request),
			request_bytes=request.content_length,
			response_bytes=response.content_length,
			param_names=_param_names(),
		)

	if logs_security:
		_log_security(request, status, error_code)


def _log_security(request, status: int, error_code: str | None) -> None:
	"""A refused request, for whoever watches for guessing and misuse.

	The reason the auth layer had for refusing is not available here (it tells the caller
	nothing on purpose, and keeps the detail in its own Error Log), so this records what
	the request looked like instead: which scheme it tried, from where, and for which account.
	"""
	event = {401: "auth_failure", 403: "permission_denied", 429: "rate_limited"}[status]
	oplog.emit(
		f"security.{event}",
		logging.WARNING,
		method=request.method,
		path=oplog.scrub_path(request.path),
		status=status,
		error_code=error_code,
		auth_scheme=_auth_scheme(request),
		client_ip=oplog.mask_ip(getattr(frappe.local, "request_ip", None)),
		user_agent=_user_agent(request),
		attempted_user=_attempted_identity() if status == 401 else None,
	)


def _auth_scheme(request) -> str:
	"""Which kind of credential was offered, never the credential."""
	header = request.headers.get("Authorization", "")
	scheme = header.split(" ", 1)[0].lower() if header else ""
	if scheme in _KNOWN_SCHEMES:
		return scheme
	if scheme:
		return "other"
	return "cookie" if request.cookies else "none"


def _attempted_identity() -> str | None:
	form = getattr(frappe.local, "form_dict", None) or {}
	for name in _IDENTITY_PARAMS:
		value = form.get(name)
		if isinstance(value, str) and 0 < len(value) <= 254:
			return value
	return None


def _user_agent(request) -> str | None:
	agent = request.headers.get("User-Agent")
	return oplog.scrub_text(agent, USER_AGENT_LENGTH) if agent else None


def _param_names() -> list[str] | None:
	"""The names, never the values, of everything the caller sent (query string and body)."""
	form = getattr(frappe.local, "form_dict", None)
	if not form:
		return None
	names = sorted(str(name)[:40] for name in form if name != "cmd")
	return names[:MAX_LOGGED_NAMES] or None


def _error_code(response) -> str | None:
	"""The `code` of an error envelope (or Frappe's `exc_type`), and nothing else from the body.

	Only a small, buffered JSON error is read, so a download or a stream costs nothing.
	"""
	try:
		if response.direct_passthrough or response.mimetype != "application/json":
			return None
		if (response.content_length or 0) > MAX_ERROR_BODY:
			return None
		body = json.loads(response.get_data())
	except Exception:
		return None
	if not isinstance(body, dict):
		return None
	for key in ("code", "exc_type"):
		value = body.get(key)
		if isinstance(value, str) and _ERROR_CODE.fullmatch(value):
			return value
	return None
