"""`Idempotency-Key` for endpoints a client retries on a flaky network.

    @rest("/applications", methods=("POST",))
    @validate_request(CreateApplication)
    @handle_api_errors
    @idempotent
    def create_application(**kwargs): ...

The key is stored in the database, in the same transaction as the endpoint's own
writes. Redis cannot do that: a key written before the commit can answer "done" for a
record that was rolled back, and a key written after it is lost if the worker dies in
between, so the retry duplicates.

How a request is handled:

- No `Idempotency-Key` header: the endpoint runs as it always did, unless `required`.
- First time: a row named by `sha256(caller, method, path, key)` is inserted, the
  endpoint runs, and its response is stored on the row. `handle_api_errors` rolls the
  transaction back when the endpoint raises, which removes the row, so a failed first
  attempt is never replayed.
- A retry that arrives while the first request is still running waits up to
  `IN_FLIGHT_WAIT` seconds on the unique insert, then gets 409 and tries again. If the
  first request commits within that wait, the insert fails as a duplicate and the
  stored response is replayed with `Idempotency-Replayed: true`. If it rolls back, the
  retry runs as the first.
- Same key and a different body: 422, `IdempotencyKeyReused`.
- The key is scoped to the caller, the method and the path, so another user or another
  route using the same key is a separate request. A guest is scoped by IP address.

Keep `@idempotent` innermost, under `@handle_api_errors`, so an exception reaches the
handler that rolls back. A response with status 400 or above that is returned and not
raised is not kept, so the client may retry it. Rows are deleted in batches by an
hourly job (`purge_expired`) once older than `oan_idempotency_retention_hours` in
site_config.json (default 24).

The stored response is encrypted with the site's encryption key, because it can hold
personal data. Nothing identifies the caller on the row: the caller is only part of the
hash the row is named by.

Every decision is logged once as a dict to `logs/oan_idempotency.log` and, when the
site has `monitor` on, added to Frappe's per-request monitor record (which carries the
request duration). `outcome` is one of: first, replay, in_progress, mismatch, released,
invalid_key, key_required.
"""

import hashlib
import json
import re
import time
from collections.abc import Callable
from functools import wraps

import frappe
from frappe import _
from frappe.utils.password import decrypt, encrypt

from oan_auth_service.oan_auth.doctype.oan_idempotency_key.oan_idempotency_key import set_lock_wait

HEADER = "Idempotency-Key"
DOCTYPE = "OAN Idempotency Key"
_KEY = re.compile(r"[A-Za-z0-9._:\-]{8,128}")
_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# How long a retry waits for a request still running before it gets 409.
IN_FLIGHT_WAIT = 1


class IdempotencyKeyInvalid(frappe.ValidationError):
	http_status_code = 400


class IdempotencyKeyReused(frappe.ValidationError):
	http_status_code = 422


class IdempotencyConflict(frappe.ValidationError):
	http_status_code = 409


def idempotent(fn: Callable | None = None, *, required: bool = False) -> Callable:
	"""Make `fn` run at most once per `Idempotency-Key`. `required=True` refuses a request without one."""

	def decorator(fn: Callable) -> Callable:
		@wraps(fn)
		def wrapper(*args, **kwargs):
			request = frappe.request
			if request is None or request.method not in _METHODS:
				return fn(*args, **kwargs)

			key = request.headers.get(HEADER)
			if not key:
				if required:
					_observe("key_required")
					raise IdempotencyKeyInvalid(_("The Idempotency-Key header is required."))
				return fn(*args, **kwargs)
			if not _KEY.fullmatch(key):
				_observe("invalid_key")
				raise IdempotencyKeyInvalid(_("Idempotency-Key must be 8 to 128 letters, digits or . _ : -"))

			name = _key_hash(key)
			fingerprint = hashlib.sha256(request.get_data(cache=True) or b"").hexdigest()

			if not _reserve(name, request.method, request.path, fingerprint):
				return _replay(name, fingerprint)

			started = time.monotonic()
			result = fn(*args, **kwargs)
			status = _status_code()
			duration_ms = int((time.monotonic() - started) * 1000)
			if status >= 400:
				# Returned and not raised, so nothing rolls the reservation back.
				frappe.db.delete(DOCTYPE, {"name": name})
				_observe("released", name, status=status, duration_ms=duration_ms)
				return result
			_store(name, status, result)
			_observe("first", name, status=status, duration_ms=duration_ms)
			return result

		return wrapper

	return decorator(fn) if fn else decorator


def _caller() -> str:
	user = frappe.session.user
	return user if user != "Guest" else f"Guest@{getattr(frappe.local, 'request_ip', '')}"


def _key_hash(key: str) -> str:
	request = frappe.request
	return hashlib.sha256(f"{_caller()}|{request.method}|{request.path}|{key}".encode()).hexdigest()


def _status_code() -> int:
	return int(frappe.response.get("http_status_code") or 200)


def _reserve(name: str, method: str, path: str, fingerprint: str) -> bool:
	"""Insert the reservation. False when the key is already taken and its request has finished.

	Raises `IdempotencyConflict` when the request that holds the key is still running
	after `IN_FLIGHT_WAIT` seconds.
	"""
	doc = frappe.get_doc(
		{
			"doctype": DOCTYPE,
			"key_hash": name,
			"method": method,
			"path": path,
			"fingerprint": fingerprint,
		}
	)
	# The unique insert waits for the lock of a running request. Keep that wait short
	# for this statement, then put the session's own value back.
	previous = set_lock_wait(IN_FLIGHT_WAIT)
	try:
		doc.insert(ignore_permissions=True)
	except (frappe.DuplicateEntryError, frappe.UniqueValidationError):
		return False
	except frappe.QueryTimeoutError:
		_observe("in_progress", name)
		raise IdempotencyConflict(
			_("A request with this Idempotency-Key is still running. Retry in a moment.")
		) from None
	finally:
		set_lock_wait(previous)
	return True


def _store(name: str, status: int, result) -> None:
	frappe.db.set_value(
		DOCTYPE,
		name,
		{"status_code": status, "response": encrypt(frappe.as_json(result, indent=None))},
		update_modified=False,
	)


def _replay(name: str, fingerprint: str):
	# A locking read sees the latest committed row, which a plain read in this
	# transaction's snapshot may not.
	row = frappe.db.get_value(
		DOCTYPE, name, ["fingerprint", "status_code", "response"], as_dict=True, for_update=True
	)
	if row is None:
		# Released between the failed insert and this read: the caller retries.
		raise IdempotencyConflict(_("A request with this Idempotency-Key was just released. Retry."))
	if row.fingerprint != fingerprint:
		_observe("mismatch", name)
		raise IdempotencyKeyReused(_("This Idempotency-Key was used with a different request."))
	if row.response is None:
		# Committed before the endpoint finished, by an explicit commit in its code.
		_observe("in_progress", name)
		raise IdempotencyConflict(_("A request with this Idempotency-Key is in progress."))

	frappe.response["http_status_code"] = row.status_code or 200
	frappe.local.response_headers.set("Idempotency-Replayed", "true")
	_observe("replay", name, status=row.status_code)
	return json.loads(decrypt(row.response))


def _observe(outcome: str, name: str | None = None, **fields) -> None:
	"""Log one decision and add it to the request's monitor record.

	Never the raw key or the path: the key is the client's secret and the path can hold a
	ticket or application ID. `key` is the first 8 characters of the row's hash, enough
	to find the row; `route` is the URL template.
	"""
	rule = getattr(frappe.request, "url_rule", None)
	entry = {
		"outcome": outcome,
		"route": getattr(rule, "rule", None) or "unknown",
		"method": getattr(frappe.request, "method", None),
		**({"key": name[:8]} if name else {}),
		**fields,
	}
	frappe.logger("oan_idempotency", allow_site=True).info(entry)
	try:
		from frappe.monitor import add_data_to_monitor

		add_data_to_monitor(idempotency=outcome)
	except Exception:
		pass
