"""Field-specific wording for request-schema errors.

Pydantic's own messages ("Field required", "String should have at most 140 characters")
do not say which field they are about, and the API hands them to clients as the value of
`details[<field>]`. `validation_details` rewrites each so it names its field and the rule
it broke, with the limit when there is one: "Full name must not exceed 140 characters."

Pydantic v2 has no per-field message override, so this catches the `ValidationError` and
rewrites each error by its `type` and `ctx`, never by the English `msg`. The templates in
`_MESSAGES` are keyed by pydantic's error type and use its `ctx` names as placeholders, so
a new rule is one line.

The name of a field in a message comes from the schema: put a `title` on the field,
`usr: str = Field(min_length=1, title=N_("Email or username"))`, and that is its label.
Without a `title`, the field name is spelled out ("phone_number" -> "Phone number"). The
label lives next to the field it describes, and a title on one schema's `name` does not
rename another's. `N_` marks the title for Frappe's translation extractor.

Only pydantic's built-in messages are rewritten, and only when the numbers they quote are
still on the error. A message a validator wrote in plain words is shown as written, minus
pydantic's "Value error, " prefix. An error that was already rewritten (the apps that
build on this one do the same for their own schemas) carries a `label` and passes through
unchanged, so applying this twice is harmless.

Clients that translate on their own side read `validation_codes` instead: the same
fields, each as `{"code": <pydantic error type>, **limits}`, e.g.
`{"code": "string_too_long", "max_length": 140}`. The text stays as the fallback.

Translation: the templates and titles are marked with `N_` so Frappe's extractor finds
them, and translated with `_()` when a message is built. A label is translated as a whole
phrase, never word by word, so a translator supplies "Full name" once. A label spelled out
from a field name is not in the catalogue until someone adds it; give the field a `title`
to have it extracted. Frappe has no plural forms, so the one-character wording is a
separate string.

Which fields fail and the 400 code are not decided here; only the text is.
"""

from typing import Any, get_args

from frappe import N_, _
from pydantic import BaseModel, ValidationError

_VALUE_ERROR_PREFIX = "Value error, "

_MISSING = N_("{label} is required.")
_WHOLE_NUMBER = N_("{label} must be a whole number.")
_NUMBER = N_("{label} must be a number.")
_TRUE_OR_FALSE = N_("{label} must be true or false.")
_OBJECT = N_("{label} must be an object.")
_LIST = N_("{label} must be a list.")
_DATE = N_("{label} must be a valid date.")
_DATE_TIME = N_("{label} must be a valid date and time.")
_TIME = N_("{label} must be a valid time.")
_UUID = N_("{label} must be a valid UUID.")

# pydantic error type -> template. Placeholders are `label` and the error's own `ctx` names.
_MESSAGES = {
	"missing": _MISSING,
	"string_too_short": N_("{label} must contain at least {min_length} characters."),
	"string_too_long": N_("{label} must not exceed {max_length} characters."),
	"string_pattern_mismatch": N_("{label} must match the required format."),
	"too_short": N_("{label} must contain at least {min_length} items."),
	"too_long": N_("{label} must contain at most {max_length} items."),
	"greater_than_equal": N_("{label} must be at least {ge}."),
	"greater_than": N_("{label} must be greater than {gt}."),
	"less_than_equal": N_("{label} must not exceed {le}."),
	"less_than": N_("{label} must be less than {lt}."),
	"multiple_of": N_("{label} must be a multiple of {multiple_of}."),
	"int_parsing": _WHOLE_NUMBER,
	"int_from_float": _WHOLE_NUMBER,
	"int_type": _WHOLE_NUMBER,
	"float_parsing": _NUMBER,
	"float_type": _NUMBER,
	"decimal_parsing": _NUMBER,
	"decimal_type": _NUMBER,
	"bool_parsing": _TRUE_OR_FALSE,
	"bool_type": _TRUE_OR_FALSE,
	"string_type": N_("{label} must be text."),
	"bytes_type": N_("{label} must be text."),
	"dict_type": _OBJECT,
	"model_type": _OBJECT,
	"model_attributes_type": _OBJECT,
	"list_type": _LIST,
	"tuple_type": _LIST,
	"set_type": _LIST,
	"frozen_set_type": _LIST,
	"date_parsing": _DATE,
	"date_type": _DATE,
	"date_from_datetime_parsing": _DATE,
	"date_from_datetime_inexact": _DATE,
	"datetime_parsing": _DATE_TIME,
	"datetime_type": _DATE_TIME,
	"datetime_from_date_parsing": _DATE_TIME,
	"datetime_object_invalid": _DATE_TIME,
	"time_parsing": _TIME,
	"time_type": _TIME,
	"uuid_parsing": _UUID,
	"uuid_type": _UUID,
	"json_invalid": N_("{label} must be valid JSON."),
	"json_type": N_("{label} must be valid JSON."),
	"literal_error": N_("{label} must be one of: {expected}."),
	"enum": N_("{label} must be one of: {expected}."),
	"extra_forbidden": N_("{label} is not an accepted field."),
}
# A limit of exactly one reads differently in English ("1 character").
_SINGULAR = {
	"string_too_short": ("min_length", N_("{label} must contain at least {min_length} character.")),
	"string_too_long": ("max_length", N_("{label} must not exceed {max_length} character.")),
}
_ACCEPTED = N_("{label} must be accepted.")

# Pydantic types whose text is the validator's own, not a rule this table words: a
# `ValueError` or `assert` a schema raised.
_OWN_TEXT = frozenset({"value_error", "assertion_error"})

# The `ctx` entries worth telling a client about. The rest (the regex a pattern uses, the
# exception object behind a value error) are internals, or not JSON.
_PARAMS = ("min_length", "max_length", "ge", "gt", "le", "lt", "multiple_of", "expected")


def _nested_model(annotation: Any) -> type[BaseModel] | None:
	"""The model a field holds, looking inside `X | None`, `list[X]` and the like."""
	if isinstance(annotation, type) and issubclass(annotation, BaseModel):
		return annotation
	for arg in get_args(annotation):
		found = _nested_model(arg)
		if found:
			return found
	return None


def _field_info(model: type[BaseModel], name: str):
	"""A model's field by the name it appears under in an error location."""
	fields = model.model_fields
	if name in fields:
		return fields[name]
	for info in fields.values():
		if name in (info.alias, info.validation_alias):
			return info
	return None


def declared_title(schema: type[BaseModel] | None, loc: tuple) -> str | None:
	"""The `title` set on the field `loc` points at, following nested models; else None."""
	model, title = schema, None
	for part in loc:
		if not isinstance(part, str):
			continue  # a list index
		info = _field_info(model, part) if model else None
		title = info.title if info else None
		model = _nested_model(info.annotation) if info else None
	return title


def field_label(loc: tuple, schema: type[BaseModel] | None = None) -> str:
	"""The field's `title` in `schema`, else `phone_number` -> "Phone number"."""
	title = declared_title(schema, loc)
	if title:
		return _(title)
	names = [part for part in loc if isinstance(part, str)]
	if not names:
		return _(N_("This value"))
	text = " ".join(names[-1].replace("_", " ").split())
	return _(text[:1].upper() + text[1:])


def _kind(error: dict) -> str:
	"""The stable code for an error. An empty-string failure is "missing" to the client."""
	kind = error["type"]
	if kind == "string_too_short" and (error.get("ctx") or {}).get("min_length") == 1:
		return "missing"
	return kind


def _number(value: Any) -> str:
	return f"{value:g}" if isinstance(value, float) else str(value)


def friendly_message(error: dict, schema: type[BaseModel] | None = None) -> str:
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
			return _(template).format(label=field_label(tuple(error["loc"]), schema), **params)
		except KeyError:
			# The number the template quotes is not on the error; show pydantic's own text.
			pass
	if error["type"] == "value_error" and error["msg"].startswith(_VALUE_ERROR_PREFIX):
		return error["msg"][len(_VALUE_ERROR_PREFIX) :]
	return error["msg"]


def has_wording(error_type: str) -> bool:
	"""Whether a pydantic error type is worded here, or is a validator's own text."""
	return error_type in _MESSAGES or error_type in _OWN_TEXT


def friendly_code(error: dict) -> dict:
	"""`{"code": "string_too_long", "max_length": 140}` for one pydantic error dict."""
	ctx = error.get("ctx") or {}
	return {"code": _kind(error)} | {key: ctx[key] for key in _PARAMS if key in ctx}


def _field(error: dict) -> str:
	return ".".join(str(part) for part in error["loc"])


def validation_details(error: ValidationError, schema: type[BaseModel] | None = None) -> dict[str, str]:
	"""{field: message} for a failed schema, every failing field together.

	`schema` is the model the request was validated against; its field titles become the
	labels. Without it, every label is the field name spelled out.
	"""
	return {_field(line): friendly_message(line, schema) for line in error.errors()}


def validation_codes(error: ValidationError) -> dict[str, dict]:
	"""{field: {"code": ..., <limits>}} for a failed schema, for clients that translate."""
	return {_field(line): friendly_code(line) for line in error.errors()}
