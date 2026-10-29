"""Field-specific wording for request-schema errors.

Pydantic's own messages ("Field required", "String should have at most 140 characters")
do not say which field they are about, and the API hands them to clients as the value of
`details[<field>]`. `validation_details` rewrites each so it names its field and the rule
it broke, with the limit when there is one: "Full name must not exceed 140 characters."

Pydantic v2 has no per-field message override, so this catches the `ValidationError` and
rewrites each error by its `type` and `ctx`, never by the English `msg`. The templates in
`_MESSAGES` are keyed by pydantic's error type and use its `ctx` names as placeholders, so
a new rule is one line.

Only pydantic's built-in messages are rewritten, and only when the numbers they quote are
still on the error. A message a validator wrote in plain words is shown as written, minus
pydantic's "Value error, " prefix. An error that was already rewritten (the apps that
build on this one do the same for their own schemas) carries a `label` and passes through
unchanged, so applying this twice is harmless.

Clients that translate on their own side read `validation_codes` instead: the same
fields, each as `{"code": <pydantic error type>, **limits}`, e.g.
`{"code": "string_too_long", "max_length": 140}`. The text stays as the fallback.

Translation: the templates and labels are marked with `N_` so Frappe's extractor finds
them, and translated with `_()` when a message is built. A label is translated as a whole
phrase, never word by word, so a translator supplies "Full name" once. Labels built from
a field name are not in the catalogue until someone adds them; they fall back to English.
Frappe has no plural forms, so the one-character wording is a separate string.

Which fields fail and the 400 code are not decided here; only the text is.
"""

from typing import Any

from frappe import N_, _
from pydantic import ValidationError

_VALUE_ERROR_PREFIX = "Value error, "
_ACRONYMS = {"sla": "SLA", "id": "ID", "url": "URL", "otp": "OTP", "iam": "IAM"}
# Names the forms call something else.
_LABELS = {"usr": N_("Email or username"), "pwd": N_("Password")}

_MISSING = N_("{label} is required.")
_WHOLE_NUMBER = N_("{label} must be a whole number.")
_NUMBER = N_("{label} must be a number.")
_TRUE_OR_FALSE = N_("{label} must be true or false.")

# pydantic error type -> template. Placeholders are `label` and the error's own `ctx` names.
_MESSAGES = {
	"missing": _MISSING,
	"string_too_short": N_("{label} must contain at least {min_length} characters."),
	"string_too_long": N_("{label} must not exceed {max_length} characters."),
	"string_pattern_mismatch": N_("{label} must match the required format."),
	"greater_than_equal": N_("{label} must be at least {ge}."),
	"greater_than": N_("{label} must be greater than {gt}."),
	"less_than_equal": N_("{label} must not exceed {le}."),
	"less_than": N_("{label} must be less than {lt}."),
	"int_parsing": _WHOLE_NUMBER,
	"int_from_float": _WHOLE_NUMBER,
	"int_type": _WHOLE_NUMBER,
	"float_parsing": _NUMBER,
	"float_type": _NUMBER,
	"bool_parsing": _TRUE_OR_FALSE,
	"bool_type": _TRUE_OR_FALSE,
	"string_type": N_("{label} must be text."),
	"literal_error": N_("{label} must be one of: {expected}."),
	"extra_forbidden": N_("{label} is not an accepted field."),
}
# A limit of exactly one reads differently in English ("1 character").
_SINGULAR = {
	"string_too_short": ("min_length", N_("{label} must contain at least {min_length} character.")),
	"string_too_long": ("max_length", N_("{label} must not exceed {max_length} character.")),
}
_ACCEPTED = N_("{label} must be accepted.")

# The `ctx` entries worth telling a client about. The rest (the regex a pattern uses, the
# exception object behind a value error) are internals, or not JSON.
_PARAMS = ("min_length", "max_length", "ge", "gt", "le", "lt", "expected")


def field_label(loc: tuple) -> str:
	"""`phone_number` -> "Phone number". Uses the last name in the location."""
	names = [part for part in loc if isinstance(part, str)]
	if not names:
		return _(N_("This value"))
	if names[-1] in _LABELS:
		return _(_LABELS[names[-1]])
	words = [_ACRONYMS.get(word.lower(), word) for word in names[-1].replace("_", " ").split()]
	text = " ".join(words)
	return _(text[:1].upper() + text[1:])


def _kind(error: dict) -> str:
	"""The stable code for an error. An empty-string failure is "missing" to the client."""
	kind = error["type"]
	if kind == "string_too_short" and (error.get("ctx") or {}).get("min_length") == 1:
		return "missing"
	return kind


def _number(value: Any) -> str:
	return f"{value:g}" if isinstance(value, float) else str(value)


def friendly_message(error: dict) -> str:
	"""The field-specific message for one pydantic error dict."""
	ctx = error.get("ctx") or {}
	if "label" in ctx:
		# A validator that names its own field in its message, e.g. "Justification ...".
		return error["msg"]

	kind = _kind(error)
	template = _MESSAGES.get(kind)
	if kind == "literal_error" and ctx.get("expected") == "True":
		template = _ACCEPTED
	elif kind in _SINGULAR and ctx.get(_SINGULAR[kind][0]) == 1:
		template = _SINGULAR[kind][1]

	if template:
		params = {key: _number(ctx[key]) for key in _PARAMS if key in ctx}
		try:
			return _(template).format(label=field_label(tuple(error["loc"])), **params)
		except KeyError:
			# The number the template quotes is not on the error; show pydantic's own text.
			pass
	if error["type"] == "value_error" and error["msg"].startswith(_VALUE_ERROR_PREFIX):
		return error["msg"][len(_VALUE_ERROR_PREFIX) :]
	return error["msg"]


def friendly_code(error: dict) -> dict:
	"""`{"code": "string_too_long", "max_length": 140}` for one pydantic error dict."""
	ctx = error.get("ctx") or {}
	return {"code": _kind(error)} | {key: ctx[key] for key in _PARAMS if key in ctx}


def _field(error: dict) -> str:
	return ".".join(str(part) for part in error["loc"])


def validation_details(error: ValidationError) -> dict[str, str]:
	"""{field: message} for a failed schema, every failing field together."""
	return {_field(line): friendly_message(line) for line in error.errors()}


def validation_codes(error: ValidationError) -> dict[str, dict]:
	"""{field: {"code": ..., <limits>}} for a failed schema, for clients that translate."""
	return {_field(line): friendly_code(line) for line in error.errors()}
