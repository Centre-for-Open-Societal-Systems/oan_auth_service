"""Structured operational logging, shared by every OAN app.

One JSON object per line in `logs/oan.log` (or on stderr when `FRAPPE_STREAM_LOGGING` is
set, as in a container). Every line has a UTC timestamp, a level, an `event` name and, inside
a request or a scheduled job, the `correlation_id` that ties it to the rest of that work.

It is Frappe's own logger (`frappe.logger`), so rotation and stream mode are the framework's.
This module adds a JSON line format, an INFO level (Frappe leaves `frappe.log_level` unset,
which makes every logger ERROR on a production bench), and masking.

Nothing here logs a request or response body, a header value or a query value. Values that are
logged go through `redact`, so a caller that passes a personal field by mistake still gets it
masked. Free text (exception messages, tracebacks, paths) goes through `scrub_text`.

Use `emit("area.what", level, **fields)` for an event and `log_error(title)` in an `except`
block (instead of `frappe.log_error`). The request hooks that set the correlation id and log
each request are in `request_log.py`.
"""

import json
import logging
import re
import sys
import threading
import uuid
from datetime import UTC, datetime

import frappe
from frappe.monitor import get_trace_id

LOGGER_NAME = "oan"
# `frappe.logger(..., allow_site=False)` names its logger "<module>-all".
_LOGGER_KEY = f"{LOGGER_NAME}-all"

REDACTED = "[REDACTED]"
MASKED = "[MASKED]"

MAX_TEXT = 2000
MAX_FIELD_TEXT = 500
MAX_DEPTH = 5
# An Error Log row keeps the end of a traceback (where the exception message is), and the
# structured line keeps its last line separately plus a shorter tail.
ERROR_LOG_LIMIT = 30_000
ERROR_DETAIL_LIMIT = 4000
ERROR_MESSAGE_LIMIT = 500
# `Error Log.method`, the title column, holds 140 characters; more raises.
ERROR_TITLE_LIMIT = 140

TRUNCATED_END = "...[truncated]"
TRUNCATED_START = "[truncated]..."


class Scrubbed(str):
	"""Text that has already been through `scrub_text`, so `redact` leaves it as it is.

	Without this a long, already-cleaned field would be scrubbed a second time and cut to
	`MAX_FIELD_TEXT`, which for a traceback throws away the exception message at the end.
	"""

	__slots__ = ()


# --- Masking ----------------------------------------------------------------------------


def mask_email(value) -> str:
	"""`jane.doe@example.com` -> `j***@example.com`."""
	text = str(value or "")
	local, sep, domain = text.rpartition("@")
	if not sep or not local:
		return MASKED
	return f"{local[0]}***@{domain}"


def mask_phone(value) -> str:
	"""Keep the last two digits: enough to tell two numbers apart in a trace, not to call one."""
	digits = re.sub(r"\D", "", str(value or ""))
	return f"***{digits[-2:]}" if len(digits) > 6 else MASKED


def mask_name(value) -> str:
	"""`Abebe Kebede` -> `A*** K***`."""
	parts = str(value or "").split()
	return " ".join(f"{part[0]}***" for part in parts) or MASKED


def mask_identifier(value) -> str:
	"""A national ID, registration number or similar: last two characters at most."""
	text = str(value or "")
	return f"***{text[-2:]}" if len(text) > 8 else MASKED


def mask_ip(value) -> str | None:
	"""IPv4 to its /24, IPv6 to its /48. The gateway's own log holds the full address."""
	text = str(value or "")
	if not text:
		return None
	if ":" in text:
		groups = text.split(":")
		return ":".join(groups[:3]) + "::" if len(groups) > 3 else MASKED
	octets = text.split(".")
	return ".".join([*octets[:3], "0"]) if len(octets) == 4 else MASKED


def mask_user(user) -> str | None:
	"""A User id is an email or a phone-derived name, so it is masked like either."""
	if not user:
		return None
	text = str(user)
	if text in ("Administrator", "Guest"):
		return text
	if "@" in text:
		return mask_email(text)
	if re.fullmatch(r"\+?[\d\s\-]{7,}", text):
		return mask_phone(text)
	return f"{text[0]}***"


# A key is sensitive when any of these is part of its name; a few short ones must match whole.
_SECRET_PARTS = (
	"password",
	"passwd",
	"secret",
	"token",
	"authorization",
	"cookie",
	"api_key",
	"apikey",
	"credential",
	"signature",
	"private_key",
	"csrf",
)
_SECRET_EXACT = {"pwd", "sid", "otp", "pin", "key", "auth", "session"}

# Personal data, with the way each is masked. Order matters: first match wins.
_PII_RULES = (
	(("email",), mask_email),
	(("mobile", "phone", "msisdn", "telephone"), mask_phone),
	(("submitter_name", "full_name", "first_name", "last_name", "middle_name", "surname"), mask_name),
	(("fayda", "national_id", "registration_number", "account_number", "iban", "tin"), mask_identifier),
)
_PII_PARTS = (
	"address",
	"birth",
	"dob",
	"latitude",
	"longitude",
	"gps",
	"location",
	"description",
	"complaint",
	"message",
	"body",
	"content",
	"remarks",
	"comment",
)
_USER_KEYS = {
	"user",
	"owner",
	"assigned_to",
	"officer",
	"usr",
	"username",
	"attempted_user",
	"from_user",
	"to_user",
	"recipient",
	"approver",
	"requested_by",
	"target_user",
}


def _split(key: str) -> list[str]:
	return [p for p in re.split(r"[^a-z0-9]+", key.lower()) if p]


def is_secret_key(key) -> bool:
	name = str(key).lower()
	return name in _SECRET_EXACT or any(part in name for part in _SECRET_PARTS)


def _mask_for_key(key: str):
	name = str(key).lower()
	if name in _USER_KEYS:
		return mask_user
	for parts, fn in _PII_RULES:
		if any(p in name if len(p) > 3 else p in _split(name) for p in parts):
			return fn
	if any(p in name for p in _PII_PARTS):
		return lambda _v: MASKED
	return None


_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*")
# A credential has a shape: an `Authorization` header (or the same key in a dict or JSON dump)
# followed by its value, or a long opaque `Bearer` token. The bare words "token", "basic" and
# "bearer" in a sentence ("Invalid token provided") are not credentials and are left alone.
_AUTH_HEADER = re.compile(
	r"""(?ix)
	(\bauthorization["']?\s*[:=]\s*["']?)
	(?:(?:bearer|basic|token)\s+)?
	[^\s"',;]+
	"""
)
_BEARER_OPAQUE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=\-]{20,}")
_SECRET_PAIR = re.compile(
	# The key must start where a name starts (the lookbehind) and its affixes are bounded. An
	# unanchored `[a-z_]*` before the keyword is tried from every position in a long run of
	# letters, which takes seconds on a 30,000-character local variable.
	r"""(?ix)
	(["']?(?<![A-Za-z0-9_])
	(?:[a-z_]{0,40}(?:password|passwd|secret|token|api_key|apikey|authorization|credential)[a-z_]{0,40}
		|pwd|sid|otp|csrf_token)(?![A-Za-z0-9_])["']?\s*[:=]\s*)
	("[^"]*"|'[^']*'|[^\s,;&})\]]+)
	"""
)
# Personal fields in a dict or keyword dump, as a local variable's repr shows them. Used on
# tracebacks only: in prose, "description: too short" is not data worth hiding.
_PII_PAIR = re.compile(
	r"""(?ix)
	(["']?(?<![A-Za-z0-9_])
	[a-z_]{0,40}(?:email|mobile|phone|msisdn|submitter_name|full_name|first_name|last_name
		|middle_name|surname|fayda|national_id|address|description|complaint)[a-z_]{0,40}
	(?![A-Za-z0-9_])["']?\s*[:=]\s*)
	("[^"]*"|'[^']*'|[^\s,;&})\]]+)
	"""
)
# Starts only at the beginning of a run of address characters, and the local part is at most
# 64 characters (the standard limit). Without the lookbehind the match is retried from every
# position of a long run of letters or digits, which is quadratic.
_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,}")
# Phone numbers have a shape too, so a timestamp or an id is not mistaken for one:
#   Ethiopian mobiles, 0911223344 or +251911223344 (a 10-digit 09/07 or 251 + 9 prefix);
#   Fayda ids, exactly 16 digits;
#   an international number with a +, with or without spaces and dashes;
#   a national number starting 0 that is written in groups, "0911 223 344".
# Not matched: epoch times, order ids, a nine-character ticket number such as 012345678.
_PHONE = re.compile(
	r"""(?x)
	(?<![\w.])
	(?:
		(?:\+?251|0)[79]\d{8}
		| \d{16}
		| \+\d{1,3}(?:[\s\-]?\d{2,4}){3,4}
		| 0\d{2,3}(?:[\s\-]\d{2,4}){2,3}
	)
	(?![\w])
	"""
)
# One local variable in a `get_traceback(with_context=True)` listing: `      name = value`.
_LOCAL_VAR = re.compile(r"^(\s{4,})([A-Za-z_][A-Za-z0-9_]*) = ")

# Only this many times the limit is ever scanned (a slice, at the two places that scrub). The
# patterns are linear, but a traceback listing every local variable of a request can be
# megabytes, and what is cut away afterwards need not be read at all.
SCAN_FACTOR = 4


def _cut(value: str, limit: int, keep: str) -> str:
	"""`value` within `limit` characters in all, marker included, from its head or its tail."""
	if len(value) <= limit:
		return value
	marker = TRUNCATED_START if keep == "tail" else TRUNCATED_END
	if limit <= len(marker):
		# No room for a marker as well: a hard cut still honours the limit.
		return (value[-limit:] if keep == "tail" else value[:limit]) if limit > 0 else ""
	room = limit - len(marker)
	return marker + value[-room:] if keep == "tail" else value[:room] + marker


def scrub_text(text, limit: int = MAX_TEXT, keep: str = "head") -> str:
	"""Remove credentials and personal data from free text, then cap its length.

	For anything a person or a library wrote: exception messages, tracebacks, paths.
	Order matters: a credential is removed before the email pass could half-mask it.
	The result is never longer than `limit`, marker included. `keep="tail"` keeps the end,
	which is where a traceback's exception message is.
	"""
	if text is None:
		return ""
	value = str(text)
	scan = max(limit, 1) * SCAN_FACTOR
	value = value[-scan:] if keep == "tail" else value[:scan]
	value = _JWT.sub(REDACTED, value)
	value = _AUTH_HEADER.sub(lambda m: f"{m.group(1)}{REDACTED}", value)
	value = _BEARER_OPAQUE.sub(f"Bearer {REDACTED}", value)
	value = _SECRET_PAIR.sub(lambda m: f"{m.group(1)}{REDACTED}", value)
	value = _EMAIL.sub(lambda m: mask_email(m.group(0)), value)
	value = _PHONE.sub(lambda m: mask_phone(m.group(0)), value)
	return _cut(value, limit, keep)


def scrub_traceback(text, limit: int = ERROR_LOG_LIMIT) -> str:
	"""`scrub_text` for a traceback, which may list each frame's local variables.

	Frappe blanks variables named `password` or `token` there (and, from 16.55, includes
	variables only in developer mode); this also blanks one named for a credential or personal
	field (`submitter_name = ...`), and personal keys inside a dict or document dump. The end is
	kept when it is cut: that is the exception message.
	"""
	lines = []
	for line in str(text or "")[-limit * SCAN_FACTOR :].split("\n"):
		match = _LOCAL_VAR.match(line)
		if match:
			prefix, name = match.group(0), match.group(2)
			if is_secret_key(name):
				line = f"{prefix}{REDACTED}"
			elif _mask_for_key(name) is not None:
				line = f"{prefix}{MASKED}"
			else:
				line = _PII_PAIR.sub(lambda m: f"{m.group(1)}{MASKED}", line)
		lines.append(line)
	return scrub_text("\n".join(lines), limit, keep="tail")


def redact(value, key=None, _depth: int = 0):
	"""A copy of `value` that is safe to log.

	Keys that name a credential become `[REDACTED]`; keys that name personal data are masked
	(an email keeps its first letter and domain, a phone its last two digits, and free
	text fields are dropped). Remaining strings are scrubbed for anything that looks like
	either. Containers are walked to a fixed depth, so a deep structure cannot cost much.
	"""
	if key is not None:
		if is_secret_key(key):
			return REDACTED
		mask = _mask_for_key(key)
		if mask is not None and value not in (None, "", [], {}):
			if isinstance(value, dict | list | tuple | set):
				return MASKED
			return mask(value)

	if isinstance(value, dict):
		if _depth >= MAX_DEPTH:
			return MASKED
		return {str(k): redact(v, key=k, _depth=_depth + 1) for k, v in value.items()}
	if isinstance(value, list | tuple | set):
		if _depth >= MAX_DEPTH:
			return MASKED
		return [redact(v, _depth=_depth + 1) for v in list(value)[:50]]
	if isinstance(value, Scrubbed):
		return value
	if isinstance(value, str):
		return scrub_text(value, MAX_FIELD_TEXT)
	if isinstance(value, bytes | bytearray):
		return f"<{len(value)} bytes>"
	if value is None or isinstance(value, bool | int | float):
		return value
	return scrub_text(str(value), MAX_FIELD_TEXT)


# --- Correlation ------------------------------------------------------------------------

# A caller-supplied correlation id is honoured only when it is plain. Anything else
# (spaces, newlines, quotes) is how a client forges log lines, so it is replaced.
_CORRELATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:\-]{7,63}")


def ensure_correlation_id(candidate=None) -> str:
	"""Set the id for this request or job unless one is already set, and return it.

	With Frappe's monitor on (`monitor: 1`) the id is the monitor's trace id, so these lines, the
	monitor log, background jobs and Sentry share one. Otherwise it is `candidate`, a caller's
	`X-Request-Id`, if it is a plain token of 8 to 64 characters; anything else (a space, a quote, a
	line break, too long) is how a client forges log lines, so it is replaced by a UUID.

	The envelope helpers read `frappe.local.request_id`, so this is the id in `request_id` and the
	`X-Request-Id` header.
	"""
	current = getattr(frappe.local, "request_id", None)
	if current:
		return current
	if trace_id := get_trace_id():
		new = trace_id
	# fullmatch, not `$`: `$` also matches before a trailing newline.
	elif isinstance(candidate, str) and _CORRELATION_ID.fullmatch(candidate):
		new = candidate
	else:
		new = str(uuid.uuid4())
	frappe.local.request_id = new
	return new


# --- Logger -----------------------------------------------------------------------------


class JsonFormatter(logging.Formatter):
	"""`{"ts": ..., "level": ..., "logger": ..., "event": ..., **fields}` on one line."""

	def format(self, record: logging.LogRecord) -> str:
		payload = {
			"ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
			"level": record.levelname,
			"logger": LOGGER_NAME,
			"event": record.getMessage(),
		}
		payload.update(getattr(record, "oan_fields", None) or {})
		return json.dumps(payload, default=str, ensure_ascii=False, separators=(",", ":"))


# Workers are threaded; two first requests must not each add a set of handlers.
_CONFIGURE_LOCK = threading.Lock()


def get_logger() -> logging.Logger:
	"""The operational logger, configured once per process."""
	existing = logging.getLogger(_LOGGER_KEY)
	if getattr(existing, "_oan_configured", False):
		return existing

	with _CONFIGURE_LOCK:
		if getattr(existing, "_oan_configured", False):
			return existing

		# Frappe sets a logger's level from `frappe.log_level` and, with it unset, falls back to
		# ERROR on a production bench, which would drop every INFO event. This is
		# `set_log_level("INFO")` without its reset of the logger cache, which would let a logger
		# that already exists gain a second set of handlers. An operator's own setting is kept.
		if frappe.log_level is None:
			frappe.log_level = logging.INFO
		# One file for the bench rather than one per site as well: records carry `site`.
		logger = frappe.logger(LOGGER_NAME, allow_site=False)
		for handler in logger.handlers:
			handler.setFormatter(JsonFormatter())
		logger._oan_configured = True
		return logger


def emit(event: str, level: int = logging.INFO, **fields) -> None:
	"""Write one event. Never raises: logging must not break the work it describes."""
	try:
		logger = get_logger()
		if not logger.isEnabledFor(level):
			return
		record = {
			"correlation_id": getattr(frappe.local, "request_id", None),
			"site": getattr(frappe.local, "site", None),
		}
		record.update(redact(fields))
		logger.log(level, event, extra={"oan_fields": {k: v for k, v in record.items() if v is not None}})
	except Exception:
		pass


# --- Errors -----------------------------------------------------------------------------


def log_error(title: str, message: str | None = None, **kwargs) -> None:
	"""`frappe.log_error` plus a structured line, both free of credentials and personal data.

	Called from `except` blocks, so it never raises: a failure to store the row is noted on the
	structured line (`error_log_failed`) rather than replacing the error being handled.

	The Error Log row has the correlation id on its first line, then what `frappe.log_error`
	would have stored (with no message, the traceback), scrubbed: variables named for a
	credential or a personal field are blanked, and an email, phone number or token anywhere in
	the text is masked. When the text is too long the *end* is kept, because a traceback's
	exception message is its last line.

	The structured line carries the title, the exception type, that last line as `summary`, and
	the tail of the plain traceback as `detail`. `kwargs` go to `frappe.log_error` (for example
	`defer_insert`).
	"""
	exc = sys.exc_info()[0]
	exc_type = exc.__name__ if exc else None

	if message is None:
		body = frappe.get_traceback(with_context=True)
		plain = frappe.get_traceback()
	else:
		body = plain = message

	cid = getattr(frappe.local, "request_id", None)
	stored = scrub_traceback(body)
	if cid:
		stored = f"correlation_id: {cid}\n{stored}"
	# One line: `frappe.log_error` takes a title with a line break to be a swapped traceback.
	title = scrub_text(" ".join(str(title or "Error").split()), ERROR_TITLE_LIMIT)

	# The last non-blank line: a traceback's exception type and message.
	summary = next((line.strip() for line in reversed(plain.splitlines()) if line.strip()), "")

	stored_ok = True
	try:
		frappe.log_error(title=title, message=stored, **kwargs)
	except Exception:
		stored_ok = False

	emit(
		"error",
		logging.ERROR,
		title=Scrubbed(title),
		exception=exc_type,
		summary=Scrubbed(scrub_text(summary, ERROR_MESSAGE_LIMIT)),
		detail=Scrubbed(scrub_text(plain, ERROR_DETAIL_LIMIT, keep="tail")),
		error_log_failed=None if stored_ok else True,
	)


def auth_failure(reason: str, level: int = logging.WARNING) -> None:
	"""`security.auth_failure`, with the reason the caller was refused.

	Emitted where the refusal is decided, which is two places: the auth middleware (`_reject`: a
	missing, expired or forged token) and `handle_api_errors` for an endpoint that answers 401 (a
	wrong password, a bad refresh token). The caller is told one undifferentiated 401; the reason
	is for this line. It records what the request looked like: which kind of credential was offered
	(never the credential), from where, and for which account.
	"""
	request = getattr(frappe.local, "request", None)
	if request is None:
		return
	form = getattr(frappe.local, "form_dict", None) or {}
	scheme = request.headers.get("Authorization", "").split(" ", 1)[0].lower()
	if scheme not in ("bearer", "basic", "token"):
		# A header with no scheme word is the credential itself, so it is never logged.
		scheme = "other" if scheme else ("cookie" if request.cookies else "none")
	emit(
		"security.auth_failure",
		level,
		reason=reason,
		method=request.method,
		path=scrub_text(request.path, 300),
		auth_scheme=scheme,
		client_ip=mask_ip(getattr(frappe.local, "request_ip", None)),
		user_agent=scrub_text(request.headers.get("User-Agent"), 120) or None,
		# Where a sign-in names the account it was for (`usr` on login, password reset).
		attempted_user=next(
			(
				form[n]
				for n in ("usr", "username", "email")
				if isinstance(form.get(n), str) and 0 < len(form[n]) <= 254
			),
			None,
		),
	)
