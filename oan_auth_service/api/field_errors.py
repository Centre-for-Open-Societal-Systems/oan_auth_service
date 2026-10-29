"""Field-specific wording for request-schema errors.

Pydantic's own messages ("Field required", "String should have at most 140 characters")
do not say which field they are about, and the API hands them to clients as the value of
`details[<field>]`. `validation_details` rewrites each so it names its field and the rule
it broke, with the limit when there is one: "Full name must not exceed 140 characters."

Only pydantic's built-in messages are rewritten, and only when the numbers they quote are
still on the error. A message a validator wrote in plain words is shown as written, minus
pydantic's "Value error, " prefix. An error that was already rewritten (the apps that
build on this one do the same for their own schemas) carries no numbers and passes
through unchanged, so applying this twice is harmless.

Which fields fail and the 400 code are not decided here; only the text is.
"""

from typing import Any

from pydantic import ValidationError

_VALUE_ERROR_PREFIX = "Value error, "
_ACRONYMS = {"sla": "SLA", "id": "ID", "url": "URL", "otp": "OTP", "iam": "IAM"}
# Names the forms call something else.
_LABELS = {"usr": "Email or username", "pwd": "Password"}


def field_label(loc: tuple) -> str:
	"""`phone_number` -> "Phone number". Uses the last name in the location."""
	names = [part for part in loc if isinstance(part, str)]
	if not names:
		return "This value"
	if names[-1] in _LABELS:
		return _LABELS[names[-1]]
	words = [_ACRONYMS.get(word.lower(), word) for word in names[-1].replace("_", " ").split()]
	text = " ".join(words)
	return text[:1].upper() + text[1:]


def _number(value: Any) -> str:
	return f"{value:g}" if isinstance(value, float) else str(value)


def _characters(count: int) -> str:
	return "1 character" if count == 1 else f"{count} characters"


def friendly_message(error: dict) -> str:
	"""The field-specific message for one pydantic error dict."""
	kind = error["type"]
	ctx = error.get("ctx") or {}
	label = field_label(tuple(error["loc"]))

	if "label" in ctx:
		# A validator that names its own field in its message, e.g. "Justification ...".
		return error["msg"]
	if kind == "missing":
		return f"{label} is required."
	if kind == "string_too_short" and "min_length" in ctx:
		if ctx["min_length"] == 1:
			return f"{label} is required."
		return f"{label} must contain at least {_characters(ctx['min_length'])}."
	if kind == "string_too_long" and "max_length" in ctx:
		return f"{label} must not exceed {_characters(ctx['max_length'])}."
	if kind == "string_pattern_mismatch":
		return f"{label} must match the required format."
	if kind == "greater_than_equal" and "ge" in ctx:
		return f"{label} must be at least {_number(ctx['ge'])}."
	if kind == "greater_than" and "gt" in ctx:
		return f"{label} must be greater than {_number(ctx['gt'])}."
	if kind == "less_than_equal" and "le" in ctx:
		return f"{label} must not exceed {_number(ctx['le'])}."
	if kind == "less_than" and "lt" in ctx:
		return f"{label} must be less than {_number(ctx['lt'])}."
	if kind in ("int_parsing", "int_from_float", "int_type"):
		return f"{label} must be a whole number."
	if kind in ("float_parsing", "float_type"):
		return f"{label} must be a number."
	if kind in ("bool_parsing", "bool_type"):
		return f"{label} must be true or false."
	if kind == "string_type":
		return f"{label} must be text."
	if kind == "literal_error" and "expected" in ctx:
		if ctx["expected"] == "True":
			return f"{label} must be accepted."
		return f"{label} must be one of: {ctx['expected']}."
	if kind == "extra_forbidden":
		return f"{label} is not an accepted field."
	if kind == "value_error" and error["msg"].startswith(_VALUE_ERROR_PREFIX):
		return error["msg"][len(_VALUE_ERROR_PREFIX) :]
	return error["msg"]


def validation_details(error: ValidationError) -> dict[str, str]:
	"""{field: message} for a failed schema, every failing field together."""
	details = {}
	for line in error.errors():
		details[".".join(str(part) for part in line["loc"])] = friendly_message(line)
	return details
