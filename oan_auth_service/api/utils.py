"""General API utility functions, request validators, rate limiters, and error handlers."""

import ast
import inspect
import json
import re
import uuid
from dataclasses import dataclass
from functools import wraps
from typing import Annotated

import frappe
from frappe import _
from pydantic import BaseModel, BeforeValidator, TypeAdapter
from pydantic import ValidationError as PydanticValidationError

from oan_auth_service.api.jwt_keys import JWTKeyConfigurationError


class _DummyException(Exception):
	pass


class ResponseValidationError(Exception):
	"""An endpoint returned data that does not match its declared `response_model`.

	This is always a fault in this service, never caller error: the endpoint
	promised a shape and did not produce it. It is therefore a 500, and the
	offending field errors are logged rather than echoed to the caller.
	"""

	http_status_code = 500

	def __init__(self, endpoint: str, errors: list[dict]):
		self.endpoint = endpoint
		self.errors = errors
		super().__init__(f"Response validation failed for {endpoint}: {errors}")


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
	"""Validate and normalize a phone number (7 to 15 digits)."""
	if v is None or v == "":
		return v

	raw = str(v).strip()
	has_plus = raw.startswith("+")
	digits = re.sub(r"\D", "", raw)

	if not (7 <= len(digits) <= 15):
		raise ValueError("Phone number must contain between 7 and 15 digits.")
	if has_plus and digits.startswith("0"):
		raise ValueError("An international (+) phone number cannot start with 0.")

	return f"+{digits}" if has_plus else digits


def validate_required_phone_string(v: str | None) -> str:
	"""Validate that a mandatory phone number is present and valid."""
	if v is None or str(v).strip() == "":
		raise ValueError("Phone number is required.")
	return validate_phone_string(v)  # type: ignore


def validate_mobile(v: str | None, fieldname: str = "contact_mobile") -> str:
	"""Strict Frappe phone validation with country code (E.164 via libphonenumber)."""
	from frappe.utils import validate_phone_number_with_country_code

	raw = str(v or "").strip()
	if not raw:
		frappe.throw(_("A contact mobile number is required."), title=_("Missing Mobile"))
	validate_phone_number_with_country_code(raw, fieldname)
	return raw


def split_phone_number(phone_str: str | None) -> tuple[str | None, str | None]:
	"""Decompose an E.164 or national phone string into (country_code, national_number)."""
	if not phone_str:
		return None, None
	raw = str(phone_str).strip()
	if not raw:
		return None, None
	try:
		import phonenumbers

		parsed = phonenumbers.parse(raw, "ET" if not raw.startswith("+") else None)
		if phonenumbers.is_valid_number(parsed):
			return f"+{parsed.country_code}", str(parsed.national_number)
	except Exception:
		pass
	if raw.startswith("+251"):
		return "+251", raw[4:].lstrip("0")
	elif raw.startswith("0") and len(raw) == 10:
		return "+251", raw[1:]
	return None, raw


def assemble_phone_number(phone: str | None, country_code: str | None = None) -> str | None:
	"""Assemble split country code and phone number into normalized string."""
	if not phone:
		return None
	raw_phone = str(phone).strip()
	if not raw_phone:
		return None
	if country_code and not raw_phone.startswith("+"):
		clean_cc = "+" + str(country_code).lstrip("+").strip()
		clean_phone = raw_phone.lstrip("0").strip()
		return f"{clean_cc}{clean_phone}"
	return raw_phone


SafeDate = Annotated[str | None, BeforeValidator(validate_date_string)]
SafeEmail = Annotated[str | None, BeforeValidator(validate_email_string)]
SafePhone = Annotated[str | None, BeforeValidator(validate_phone_string)]
RequiredPhone = Annotated[str, BeforeValidator(validate_required_phone_string)]


# ---------------------------------------------------------------------------
# Multipart Upload Extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UploadedFile:
	"""A normalized parsed file from a multipart/form-data request."""

	file_name: str
	content: bytes

	@property
	def size_bytes(self) -> int:
		return len(self.content)


def get_uploaded_files(
	key: str | None = None,
	allow_empty: bool = False,
	max_count: int | None = None,
	max_size_bytes: int | None = None,
) -> list[UploadedFile]:
	"""Extract multipart files from frappe.request.files.

	Supports single or multiple files under a specific key or any keys.
	Validates presence and non-empty content.

	:param key: Optional specific multipart field key to extract (e.g. 'file' or 'files').
	:param allow_empty: Whether 0-byte files are permitted without raising an error.
	:param max_count: Maximum number of files permitted in this request.
	:param max_size_bytes: Maximum allowed size per file in bytes.
	"""
	req = getattr(frappe, "request", None)
	files = getattr(req, "files", None) if req else None
	if not files:
		frappe.throw(
			_("No file was uploaded. Send it as multipart form data under the key 'file' or 'files'."),
			title=_("No File"),
		)

	file_objects = []
	if key:
		if hasattr(files, "getlist"):
			file_objects = [item for item in files.getlist(key) if item]
		elif isinstance(files, dict) and key in files:
			val = files[key]
			file_objects = list(val) if isinstance(val, (list, tuple)) else ([val] if val else [])
	else:
		if hasattr(files, "getlist"):
			for k in files.keys():
				for item in files.getlist(k):
					if item:
						file_objects.append(item)
		elif isinstance(files, dict):
			for val in files.values():
				if isinstance(val, (list, tuple)):
					file_objects.extend(item for item in val if item)
				elif val:
					file_objects.append(val)
		elif isinstance(files, (list, tuple)):
			file_objects.extend(item for item in files if item)

	if not file_objects:
		frappe.throw(
			_("No file was uploaded. Send it as multipart form data under the key 'file' or 'files'."),
			title=_("No File"),
		)

	if max_count and len(file_objects) > max_count:
		frappe.throw(
			_("Too many files. Maximum {0} files allowed.").format(max_count),
			title=_("Too Many Files"),
		)

	uploads: list[UploadedFile] = []
	for upload in file_objects:
		filename = getattr(upload, "filename", None) or getattr(upload, "file_name", None) or "unnamed"
		stream = getattr(upload, "stream", None)
		if stream:
			try:
				stream.seek(0)
			except Exception:
				pass
			content = stream.read()
		elif hasattr(upload, "read"):
			content = upload.read()
		elif hasattr(upload, "content"):
			content = upload.content
		elif isinstance(upload, bytes):
			content = upload
		else:
			content = b""

		if not content and not allow_empty:
			if len(file_objects) == 1:
				frappe.throw(_("The uploaded file is empty."), title=_("Empty File"))
			else:
				frappe.throw(
					_("The uploaded file {0} is empty.").format(frappe.bold(filename)),
					title=_("Empty File"),
				)

		if max_size_bytes and len(content) > max_size_bytes:
			frappe.throw(
				_("File {0} exceeds maximum allowed size of {1} bytes.").format(
					frappe.bold(filename), max_size_bytes
				),
				title=_("File Too Large"),
			)

		uploads.append(UploadedFile(file_name=filename, content=content))

	return uploads


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
	"""Decorator to validate whitelisted API inputs using a Pydantic schema.

	Schema failures are reported as **400 with code VALIDATION_ERROR**, not 422.
	Both are defensible and much of the ecosystem (FastAPI among them) picks 422;
	400 is chosen here and held deliberately, because it is what this service has
	always returned and `_ERROR_CODES` already keys VALIDATION_ERROR off it, so a
	change would break every client branching on the pair. The rule is: one code
	for "your input was rejected", set in exactly two places — here and the
	`PydanticValidationError` branch of `handle_api_errors`. Change both or
	neither.
	"""

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


def _apply_response_model(endpoint: str, adapter: TypeAdapter, res):
	"""Validate and filter an endpoint's payload against its declared response model.

	Returns the payload re-serialised through the model, so fields the model does
	not declare are dropped. On this service that filtering is the point as much
	as the validation is: a password hash, a reset key or an internal user id
	added to a return dict cannot leak through an endpoint that declares its
	shape.
	"""
	envelope_key = None
	payload = res

	if isinstance(res, dict):
		if res.get("status") == "error":
			# Error envelopes are shaped by `error_response`, not by the model.
			return res
		if "data" in res:
			envelope_key = "data"
			payload = res["data"]

	if payload is None:
		return res

	try:
		validated = adapter.validate_python(payload)
	except PydanticValidationError as e:
		raise ResponseValidationError(endpoint, e.errors()) from e

	dumped = adapter.dump_python(validated, mode="json")

	if envelope_key is None:
		return dumped

	out = dict(res)
	out[envelope_key] = dumped
	return out


def api_doc(
	summary: str | None = None,
	description: str | None = None,
	tags: list[str] | None = None,
	response_model: type[BaseModel] | None = None,
	deprecated: bool = False,
):
	"""Attach OpenAPI metadata to an endpoint, and enforce `response_model` if given.

	`response_model` is not documentation-only. If the endpoint returns data that
	does not match it, the call fails with a 500 rather than serving a payload of
	the wrong shape — the caller is better served by a clear server error than by
	data it cannot rely on. Any pydantic-compatible type works, including
	`list[Model]` and `Model | None`.

	Place this decorator *below* `@handle_api_errors` in the stack so the raised
	`ResponseValidationError` is caught, logged and enveloped:

	    @frappe.whitelist()
	    @validate_request(MySchema)
	    @handle_api_errors
	    @api_doc(summary="...", response_model=MyResponse)
	    def my_endpoint(...): ...
	"""
	adapter = TypeAdapter(response_model) if response_model is not None else None

	def decorator(func):
		@wraps(func)
		def wrapper(*args, **kwargs):
			res = func(*args, **kwargs)
			if adapter is None:
				return res
			return _apply_response_model(func.__name__, adapter, res)

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

			if isinstance(res, dict) and res.get("status") == "error":
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
			# 400 here must stay in step with `validate_request` — see its docstring
			# for why this service uses 400 rather than 422.
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

		except ResponseValidationError as e:
			# Handled ahead of the generic path so the per-field errors reach the
			# log. They are deliberately not echoed: the caller cannot act on them
			# and they describe this service's internals.
			_rollback()
			frappe.local.message_log = []
			frappe.response["http_status_code"] = 500
			frappe.log_error(
				title=f"Response Validation Error | {func.__name__}",
				message=json.dumps(
					{
						"request_id": getattr(frappe.local, "request_id", None),
						"endpoint": e.endpoint,
						"errors": e.errors,
					},
					indent=2,
					default=str,
				),
			)
			resolved_meta = _resolve_version_meta(func)
			return error_response(_("An unexpected error occurred"), "INTERNAL_ERROR", meta=resolved_meta)

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
