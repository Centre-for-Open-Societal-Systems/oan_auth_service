"""The correlation id, and one `http.request` log line per request, for every OAN app on the site.

Two Frappe hooks (see hooks.py):

`begin` is a `before_request` hook. Frappe runs those before the auth hooks, so a request the auth
layer refuses still has a correlation id and a start time. The id is Frappe's monitor trace id when
`monitor: 1` is set, otherwise a plain inbound `X-Request-Id`, otherwise a new UUID (see
`operational_log.ensure_correlation_id`). The envelope helpers in `utils.py` read the same
`frappe.local.request_id`, so it is the `request_id` in the response body and the `X-Request-Id`
response header.

`end` is an `after_request` hook. Frappe runs those in a `finally`, so it sees every outcome:
handled envelopes, auth refusals and the framework's own error pages. It sets the header, and
writes one `http.request` line with the level from the status.

It records only what the request and response themselves say. Events that need a reason are
emitted where they are decided: `security.auth_failure` by `middleware._reject` and
`handle_api_errors`, and the error `code` by `error_response` (on `frappe.local.oan_error_code`).

Frappe starts the session (`HTTPRequest()`) before it runs `before_request` hooks, and maintenance
mode stops a request before them too. A CSRF or session failure, or a site in maintenance,
therefore never reaches `begin`. `end` still runs for it and gives it an id there, and logs it
without a duration (nothing started the clock).

Logged: method, scrubbed path, status, duration, sizes, the masked user and client address, a
trimmed user agent, the *names* of the parameters and body fields, and the error `code`. Never
logged: any request or response body, any header value other than the user agent, any query or
form value, the response `message` (an error message can echo what the caller sent), or a
credential.

`oan_slow_request_ms` in site config (default 2000) is the duration above which a request is
logged as slow, at WARNING.
"""

import logging
import time

import frappe
from frappe.utils import flt

from oan_auth_service.api import operational_log as oplog
from oan_auth_service.api.middleware import _match_namespace
from oan_auth_service.api.router import NAMESPACE

CORRELATION_HEADER = "X-Request-Id"
DEFAULT_SLOW_REQUEST_MS = 2000


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
		# `begin` has not run for a request that failed before before_request hooks (see above).
		cid = oplog.ensure_correlation_id(request.headers.get(CORRELATION_HEADER))
		if CORRELATION_HEADER not in response.headers:
			response.headers[CORRELATION_HEADER] = cid

		started = getattr(frappe.local, "oan_request_started", None)
		duration_ms = None if started is None else round((time.perf_counter() - started) * 1000, 1)
		# A missing, non-numeric, zero or negative setting means the default.
		threshold = max(flt(frappe.conf.get("oan_slow_request_ms")), 0) or DEFAULT_SLOW_REQUEST_MS
		slow = duration_ms is not None and duration_ms >= threshold
		status = response.status_code
		level = logging.ERROR if status >= 500 else logging.WARNING if status >= 400 or slow else logging.INFO

		# Nothing is built unless a line will be written: at ERROR a busy site pays only for the
		# clock and the id.
		if not oplog.get_logger().isEnabledFor(level):
			return
		form = getattr(frappe.local, "form_dict", None) or {}
		oplog.emit(
			"http.request",
			level,
			method=request.method,
			path=oplog.scrub_text(request.path, 300),
			status=status,
			duration_ms=duration_ms,
			slow=True if slow else None,
			error_code=getattr(frappe.local, "oan_error_code", None),
			user=getattr(getattr(frappe.local, "session", None), "user", None),
			client_ip=oplog.mask_ip(getattr(frappe.local, "request_ip", None)),
			user_agent=oplog.scrub_text(request.headers.get("User-Agent"), 120) or None,
			request_bytes=request.content_length,
			response_bytes=response.content_length,
			# The names, never the values, of everything the caller sent (query string and body).
			param_names=sorted(str(name)[:40] for name in form if name != "cmd")[:30] or None,
		)
	except Exception:
		pass
