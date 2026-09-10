"""General API utility functions, request validators, rate limiters, and error handlers."""

import ast
import inspect
import json
import re
import uuid
from functools import wraps
from typing import Annotated

import frappe
from frappe import _
from pydantic import BaseModel, BeforeValidator
from pydantic import ValidationError as PydanticValidationError

from oan_auth_service.api.jwt_keys import JWTKeyConfigurationError


class _DummyException(Exception):
	pass


# ---------------------------------------------------------------------------
# Password & Input Validations
# ---------------------------------------------------------------------------


def validate_password_complexity(value: str) -> str:
	"""Validate that a password meets complexity rules: at least 1 letter, 1 digit, and 1 symbol."""
	if not any(c.isalpha() for c in value):
		raise ValueError("Password must contain at least one letter.")
	if not any(c.isdigit() for c in value):
		raise ValueError("Password must contain at least one number.")
	if not any(not c.isalnum() for c in value):
		raise ValueError("Password must contain at least one special character.")
	return value


def validate_date_string(v: str | None) -> str | None:
	"""Validate that a string represents a valid date or datetime."""
	if v:
		try:
			import datetime

			try:
				datetime.date.fromisoformat(v)
			except ValueError:
				datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Invalid date format. Expected YYYY-MM-DD or ISO 8601 string.")
	return v


def validate_email_string(v: str | None) -> str | None:
	"""Validate that a string represents a valid email address format."""
	if v:
		from frappe.utils import validate_email_address

		if not validate_email_address(v):
			raise ValueError("Invalid email address format")
	return v


def validate_phone_string(v: str | None) -> str | None:
	"""Validate and normalize a phone number (10 to 15 digits)."""
	if v is None or v == "":
		return v

	raw = str(v).strip()
	has_plus = raw.startswith("+")
	digits = re.sub(r"\D", "", raw)

	if not (10 <= len(digits) <= 15):
		raise ValueError("Phone number must contain between 10 and 15 digits.")
	if has_plus and digits.startswith("0"):
		raise ValueError("An international (+) phone number cannot start with 0.")

	return f"+{digits}" if has_plus else digits


def validate_required_phone_string(v: str | None) -> str:
	"""Validate that a mandatory phone number is present and valid."""
	if v is None or str(v).strip() == "":
		raise ValueError("Phone number is required.")
	return validate_phone_string(v)  # type: ignore


SafeDate = Annotated[str | None, BeforeValidator(validate_date_string)]
SafeEmail = Annotated[str | None, BeforeValidator(validate_email_string)]
SafePhone = Annotated[str | None, BeforeValidator(validate_phone_string)]
RequiredPhone = Annotated[str, BeforeValidator(validate_required_phone_string)]


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------


def check_rate_limit(key: str, limit: int, window: int):
	"""Apply rate limits using Redis counter.

	:param key: unique identifier per caller and endpoint
	:param limit: max calls allowed in window
	:param window: seconds
	"""
	cache = frappe.cache
	count = cache.get_value(key) or 0

	if int(count) >= limit:
		frappe.response.status_code = 429
		frappe.throw(_("Rate limit exceeded. Try again later."), frappe.ValidationError)

	pipeline = cache.pipeline()
	pipeline.incr(key)
	pipeline.expire(key, window)
	pipeline.execute()


# ---------------------------------------------------------------------------
# Decorators: Schema Validation & Role Guard
# ---------------------------------------------------------------------------


def validate_request(schema: type[BaseModel]):
	"""Decorator to validate whitelisted API inputs using a Pydantic schema."""

	def decorator(func):
		@wraps(func)
		def wrapper(*args, **kwargs):
			sig = inspect.signature(func)
			bound = sig.bind_partial(*args, **kwargs)
			bound.apply_defaults()

			params = {}
			for k, v in bound.arguments.items():
				if k == "kwargs" and isinstance(v, dict):
					params.update(v)
				else:
					params[k] = v

			try:
				validated = schema(**params)
			except PydanticValidationError as e:
				errors = {}
				for err in e.errors():
					loc = ".".join(str(loc_item) for loc_item in err["loc"])
					errors[loc] = err["msg"]

				frappe.response["http_status_code"] = 400
				frappe.local.message_log = []
				return error_response(message=_("Validation failed"), code="VALIDATION_ERROR", details=errors)

			validated_dict = validated.model_dump()
			return func(**validated_dict)

		wrapper._request_schema = schema
		wrapper.__pydantic_schema__ = schema
		return wrapper

	return decorator


def api_doc(
	summary: str | None = None,
	description: str | None = None,
	tags: list[str] | None = None,
	response_model: type[BaseModel] | None = None,
	deprecated: bool = False,
):
	"""Decorator to attach OpenAPI documentation metadata to an endpoint."""

	def decorator(func):
		@wraps(func)
		def wrapper(*args, **kwargs):
			return func(*args, **kwargs)

		wrapper._api_doc = {
			"summary": summary,
			"description": description,
			"tags": tags,
			"response_model": response_model,
			"deprecated": deprecated,
		}
		return wrapper

	return decorator


def require_role(roles: list[str]):
	"""Decorator that enforces the caller holds at least one of `roles`."""

	def decorator(fn):
		@wraps(fn)
		def wrapper(*args, **kwargs):
			user_doc = frappe.get_doc("User", frappe.session.user)
			if not any(d.role in roles for d in user_doc.roles):
				roles_str = ", ".join(roles)
				frappe.throw(_("Only {0} can perform this action.").format(roles_str), frappe.PermissionError)
			return fn(*args, **kwargs)

		return wrapper

	return decorator


# ---------------------------------------------------------------------------
# Multi-value Parsing & Datetime Helpers
# ---------------------------------------------------------------------------


def match_allowed_tokens(text: str, allowed: set | list | tuple, strict: bool = True) -> list[str] | None:
	"""Split comma-separated `text`, keeping `allowed` values that contain commas intact."""
	if not text:
		return []
	allowed_sorted = sorted({str(a).strip() for a in allowed if str(a).strip()}, key=len, reverse=True)
	tokens = []
	remaining = text.strip()
	while remaining:
		for item_str in allowed_sorted:
			if remaining == item_str:
				tokens.append(item_str)
				remaining = ""
				break
			if remaining.startswith(item_str):
				rest = remaining[len(item_str) :].lstrip()
				if rest.startswith(","):
					tokens.append(item_str)
					remaining = rest[1:].lstrip()
					break
		else:
			if strict:
				return None
			token, _sep, remaining = remaining.partition(",")
			token = token.strip()
			if token:
				tokens.append(token)
			remaining = remaining.lstrip()
	return tokens


def parse_multi_value(value, allowed=None) -> list[str]:
	"""Split a single value or comma-separated string into a de-duplicated list."""
	if value is None:
		return []
	if isinstance(value, (list, tuple, set)):
		requested = [str(v).strip() for v in value]
	else:
		v_str = str(value).strip()
		if not v_str:
			return []
		if v_str.startswith("[") and v_str.endswith("]"):
			try:
				parsed = frappe.parse_json(v_str)
				requested = [str(v).strip() for v in parsed] if isinstance(parsed, list) else [v_str]
			except Exception:
				requested = [v.strip() for v in v_str.split(",")]
		elif allowed is not None and v_str in allowed:
			requested = [v_str]
		elif allowed is not None:
			matched_tokens = match_allowed_tokens(v_str, allowed)
			if matched_tokens is not None:
				requested = matched_tokens
			else:
				requested = [v.strip() for v in v_str.split(",")]
		else:
			requested = [v.strip() for v in v_str.split(",")]
	seen = set()
	result = []
	for v in requested:
		if not v or v in seen:
			continue
		if allowed is not None and v not in allowed:
			allowed_list = ", ".join(str(a) for a in allowed)
			frappe.throw(
				_("Invalid value '{0}'. Allowed values: {1}").format(v, allowed_list), frappe.ValidationError
			)
		seen.add(v)
		result.append(v)
	return result


def to_tz_aware_iso(dt) -> str | None:
	"""Convert a naive Frappe datetime to a timezone-aware ISO 8601 string in the system timezone."""
	if not dt:
		return None
	import pytz
	from frappe.utils import get_datetime, get_system_timezone

	dt_obj = get_datetime(dt)
	system_tz = pytz.timezone(get_system_timezone())
	return system_tz.localize(dt_obj).isoformat()


def from_tz_aware_iso(value):
	"""Convert an ISO 8601 string (tz-aware or naive) into a naive datetime in system timezone."""
	if not value:
		return None
	import pytz
	from frappe.utils import get_datetime, get_system_timezone

	if isinstance(value, str):
		from datetime import datetime

		try:
			dt_obj = datetime.fromisoformat(value)
		except ValueError:
			return get_datetime(value)
	else:
		dt_obj = value

	if dt_obj.tzinfo is not None:
		system_tz = pytz.timezone(get_system_timezone())
		dt_obj = dt_obj.astimezone(system_tz).replace(tzinfo=None)
	return dt_obj


# ---------------------------------------------------------------------------
# Message Extraction & Error Envelopes
# ---------------------------------------------------------------------------


def extract_message_from_str(val: str | None) -> str | None:
	"""Extract plain message string from possible json, ast, or html formatted text."""
	if not val:
		return val

	if isinstance(val, str) and val.startswith("{") and val.endswith("}"):
		try:
			try:
				parsed = json.loads(val)
			except Exception:
				parsed = ast.literal_eval(val)
			if isinstance(parsed, dict) and "message" in parsed:
				val = str(parsed["message"])
		except Exception:
			frappe.logger().debug("Could not parse message payload; returning raw value")

	if isinstance(val, str) and "<" in val and ">" in val:
		val = re.sub(r"<[^>]+>", "", val).strip()

	return val


def get_error_message(e: Exception, default_msg: str = "Validation Error") -> str:
	"""Retrieve clean error message from exception or frappe.local.message_log."""
	error_msg = ""
	if hasattr(e, "args") and e.args:
		first_arg = e.args[0]
		if isinstance(first_arg, dict):
			error_msg = first_arg.get("message") or str(first_arg)
		elif isinstance(first_arg, str):
			error_msg = extract_message_from_str(first_arg)
		else:
			error_msg = str(first_arg)
	else:
		error_msg = str(e)

	error_msg = extract_message_from_str(error_msg)

	messages = getattr(frappe.local, "message_log", [])
	if messages:
		parsed_msgs = []
		for m in messages:
			if isinstance(m, dict):
				msg_str = m.get("message") or str(m)
			elif isinstance(m, str):
				msg_str = extract_message_from_str(m)
			else:
				msg_str = str(m)
			if msg_str:
				parsed_msgs.append(msg_str)
		if parsed_msgs:
			return " | ".join(parsed_msgs)

	return error_msg or default_msg


def success_response(data=None, message="Success", meta=None, pagination=None) -> dict:
	"""Developer-facing payload builder for standardized success responses."""
	return {
		"data": data,
		"message": message,
		"meta": meta,
		"pagination": pagination,
	}


def _envelope_success(data=None, message="Success", meta=None, pagination=None) -> dict:
	"""Format standardized JSON success envelope with request_id."""
	clean_message = extract_message_from_str(message) if isinstance(message, str) else str(message)
	res = {
		"status": "success",
		"message": clean_message,
		"data": data,
		"meta": meta or {},
	}
	req_id = getattr(frappe.local, "request_id", None)
	if req_id:
		res["request_id"] = req_id
	if pagination:
		res["pagination"] = pagination
	return res


def error_response(
	message: str,
	code: str = "GENERIC_ERROR",
	details: dict | None = None,
	meta: dict | None = None,
) -> dict:
	"""Format standardized JSON error envelope with request_id and metadata."""
	clean_message = extract_message_from_str(message) if isinstance(message, str) else str(message)
	res = {
		"status": "error",
		"message": clean_message,
		"code": code,
		"details": details or {},
		"meta": meta or {},
	}
	req_id = getattr(frappe.local, "request_id", None)
	if req_id:
		res["request_id"] = req_id
	return res


def _resolve_version_meta(func, explicit_meta: dict | None = None) -> dict:
	"""Dynamically resolve the API version_meta from the caller's package if not explicitly provided."""
	auto_meta = {}
	mod_name = getattr(func, "__module__", "")

	if ".api." in mod_name:
		try:
			parts = mod_name.split(".api.")
			base_pkg = parts[0] + ".api"
			ver_candidate = parts[1].split(".")[0]

			import importlib

			api_mod = importlib.import_module(base_pkg)
			version_meta_fn = getattr(api_mod, "version_meta", None)
			if callable(version_meta_fn):
				auto_meta = version_meta_fn(ver_candidate)
			else:
				auto_meta = {"api_version": ver_candidate}
		except Exception:
			auto_meta = {}

	if explicit_meta and isinstance(explicit_meta, dict):
		return {**auto_meta, **explicit_meta}
	return auto_meta


# Frappe already carries the exception -> status mapping we need: every class in
# frappe/exceptions.py declares `http_status_code`, and frappe/app.py's own
# handle_exception() reads it with getattr(e, "http_status_code", 500). Deriving
# the status the same way — instead of hand-listing exception types — keeps this
# decorator correct for exception types it was never written against.
_CONSTRAINT_ERRORS = tuple(
	exc
	for exc in (
		getattr(frappe, "MandatoryError", None),
		getattr(frappe, "UniqueValidationError", None),
		getattr(frappe, "DuplicateEntryError", None),
		getattr(frappe, "DataError", None),
	)
	if exc is not None
) or (_DummyException,)

# Stable, caller-facing vocabulary. Consumers branch on these strings, so they are
# part of the API contract — add cases here rather than inventing codes at throw sites.
_ERROR_CODES = {
	400: "VALIDATION_ERROR",
	401: "AUTHENTICATION_ERROR",
	403: "PERMISSION_DENIED",
	404: "NOT_FOUND",
	409: "DUPLICATE_ENTRY",
	429: "RATE_LIMIT_EXCEEDED",
	500: "INTERNAL_ERROR",
	503: "SERVICE_UNAVAILABLE",
}

_DEFAULT_MESSAGES = {
	400: "Validation Error",
	401: "Authentication failed",
	403: "Permission denied",
	404: "Resource not found",
	409: "Duplicate entry",
	429: "Rate limit exceeded",
}


def _http_status_for(e: Exception) -> int:
	"""Resolve the HTTP status for an exception the way Frappe itself does."""
	status = getattr(e, "http_status_code", None)

	if status is None:
		# The `validate_*_string` helpers raise plain ValueError so they can double as
		# pydantic BeforeValidators; those are caller input errors, not server faults.
		return 400 if isinstance(e, ValueError) else 500

	# Frappe maps ValidationError to 417 Expectation Failed, which is not what the
	# status means and not what consumers of this envelope have ever received.
	return 400 if status == 417 else status


def _rollback():
	"""Discard partial writes made before an error.

	`handle_api_errors` returns an envelope instead of letting the exception
	escape, so Frappe never sees a failure and commits the request transaction
	as usual. Without this, a throw partway through a multi-write endpoint
	leaves the earlier writes behind. Call it *before* `frappe.log_error`, whose
	own insert would otherwise be rolled back along with everything else.
	"""
	try:
		frappe.db.rollback()
	except Exception:
		frappe.logger().debug("Rollback failed or no active transaction")


def handle_api_errors(func):
	"""Decorator to wrap whitelisted API methods with standardized error handling and JSON envelopes."""

	@wraps(func)
	def wrapper(*args, **kwargs):
		if not getattr(frappe.local, "request_id", None):
			req_id = None
			if frappe.request:
				headers = getattr(frappe.request, "headers", None)
				environ = getattr(frappe.request, "environ", None)
				req_id = (headers.get("X-Request-Id") if headers else None) or (
					environ.get("REQUEST_ID") if environ else None
				)
			if not req_id:
				req_id = str(uuid.uuid4())
			frappe.local.request_id = req_id

		try:
			res = func(*args, **kwargs)

			if getattr(frappe.local, "response", None) and frappe.local.response.get("type") == "download":
				return res

			message = "Success"
			pagination = None
			meta = None
			data = res

			if isinstance(res, dict) and ("data" in res or "message" in res):
				data = res.get("data", res if "data" not in res else None)
				message = res.get("message", "Success")
				pagination = res.get("pagination")
				meta = res.get("meta")

			resolved_meta = _resolve_version_meta(func, meta)
			return _envelope_success(data=data, message=message, pagination=pagination, meta=resolved_meta)

		except PydanticValidationError as e:
			# Handled ahead of the generic path only because it carries a per-field
			# `details` map no other exception has. (It subclasses ValueError, so it
			# would otherwise resolve to 400 anyway.)
			errors = {}
			for err in e.errors():
				loc = ".".join(str(loc_item) for loc_item in err["loc"])
				errors[loc] = err["msg"]
			_rollback()
			frappe.local.message_log = []
			frappe.response["http_status_code"] = 400
			resolved_meta = _resolve_version_meta(func)
			return error_response(
				message=_("Validation failed"),
				code="VALIDATION_ERROR",
				details=errors,
				meta=resolved_meta,
			)

		except JWTKeyConfigurationError as e:
			# The one 5xx whose message is safe — and necessary — to show the caller:
			# it means the deployment has no usable signing key, and masking it as a
			# generic 500 sends operators hunting through logs for a config typo.
			_rollback()
			frappe.local.message_log = []
			frappe.response["http_status_code"] = 500
			frappe.log_error(title="JWT Key Configuration Error", message=str(e))
			resolved_meta = _resolve_version_meta(func)
			return error_response(str(e), "CONFIGURATION_ERROR", meta=resolved_meta)

		except Exception as e:
			_rollback()
			status = _http_status_for(e)
			code = _ERROR_CODES.get(status, "INTERNAL_ERROR" if status >= 500 else "GENERIC_ERROR")

			# Log server faults, plus constraint errors: those are 4xx to the caller
			# but usually signal a schema or race problem worth investigating.
			if status >= 500 or isinstance(e, _CONSTRAINT_ERRORS):
				log_title = ("API Error" if status >= 500 else "DB/Constraint Error") + f" | {func.__name__}"
				frappe.log_error(
					title=log_title,
					message=json.dumps(
						{
							"request_id": getattr(frappe.local, "request_id", None),
							"endpoint": func.__name__,
							"user": frappe.session.user if frappe.session else None,
							"traceback": frappe.get_traceback(),
							"exception": str(e),
						},
						indent=2,
					),
				)

			# A 5xx message can carry internals (SQL, paths), so it is never echoed.
			message = (
				_("An unexpected error occurred")
				if status >= 500
				else get_error_message(e, _(_DEFAULT_MESSAGES.get(status, "Request could not be processed")))
			)

			frappe.local.message_log = []
			frappe.response["http_status_code"] = status
			resolved_meta = _resolve_version_meta(func)
			return error_response(message, code, meta=resolved_meta)

	return wrapper
