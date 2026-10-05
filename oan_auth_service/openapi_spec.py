# Copyright (c) 2026, COSS - Centre for Open Societal Systems and contributors
# For license information, please see license.txt

"""Building blocks for the OpenAPI generators of every app on the shared router.

Build-time tooling, not request handling: nothing under `api/` imports this, and it
runs only from an app's `openapi/generate_openapi_spec.py`.

What can come from the code does. `@route` registers the path, method and summary;
`@validate_request` names the Pydantic model that validates the request, and that
model is turned into the request body (or, on a GET, the query parameters), so the
documented contract is the validation that actually runs. Responses are still
described by hand in each app, because handlers return plain dicts.
"""

import inspect
from typing import Any

import yaml
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------


def S(**kw: Any) -> dict[str, Any]:
	return {"type": "string", **kw}


def I(**kw: Any) -> dict[str, Any]:  # noqa: E743
	return {"type": "integer", **kw}


def N(**kw: Any) -> dict[str, Any]:
	return {"type": "number", **kw}


def B(**kw: Any) -> dict[str, Any]:
	return {"type": "boolean", **kw}


def ARR(items: Any, **kw: Any) -> dict[str, Any]:
	return {"type": "array", "items": items, **kw}


def OBJ(
	props: dict[str, Any],
	required: list[str] | None = None,
	description: str | None = None,
	confidence: str | None = None,
	**kw: Any,
) -> dict[str, Any]:
	d: dict[str, Any] = {"type": "object", "properties": props, **kw}
	if required:
		d["required"] = required
	if description:
		d["description"] = description
	if confidence:
		d["x-schema-confidence"] = confidence
	return d


def REF(name: str) -> dict[str, str]:
	return {"$ref": f"#/components/schemas/{name}"}


# The body of a route that streams a file rather than a JSON envelope, and one
# file in a multipart request.
BINARY = {"type": "string", "format": "binary"}


def make_envelope(
	data_ref: str,
	is_list: bool = False,
	nullable_data: bool = False,
	description: str = "Successful response",
) -> dict[str, Any]:
	"""The success envelope `success_response` wraps every payload in."""
	if is_list:
		data_prop: Any = ARR(REF(data_ref))
	elif nullable_data:
		data_prop = {**REF(data_ref), "nullable": True}
	else:
		data_prop = REF(data_ref)
	return OBJ(
		{
			"status": S(example="success", enum=["success"]),
			"message": S(nullable=True, description="Optional response message"),
			"data": data_prop,
			"meta": REF("ApiMeta"),
			"request_id": S(format="uuid", nullable=True, description="Tracing correlation ID"),
		},
		required=["status", "data"],
		description=description,
	)


# ---------------------------------------------------------------------------
# Request schemas from Pydantic models
# ---------------------------------------------------------------------------

# JSON Schema keywords OpenAPI 3.0 has no use for.
_DROP_KEYWORDS = {"title"}


def oas30(node: Any) -> Any:
	"""Pydantic emits JSON Schema 2020-12. OpenAPI 3.0 has no null type (it has
	`nullable`), no `const`, and ignores the siblings of a `$ref`."""
	if isinstance(node, list):
		return [oas30(n) for n in node]
	if not isinstance(node, dict):
		return node
	out: dict[str, Any] = {}
	for key, value in node.items():
		if key in _DROP_KEYWORDS:
			continue
		if key == "properties":
			# Keys here are field names, not keywords: a field may be called "title".
			out[key] = {name: oas30(prop) for name, prop in value.items()}
		else:
			out[key] = oas30(value)
	for key in ("anyOf", "oneOf"):
		options = out.get(key)
		if options and any(o.get("type") == "null" for o in options):
			rest = [o for o in options if o.get("type") != "null"]
			del out[key]
			out = {**rest[0], **out} if len(rest) == 1 else {key: rest, **out}
			out["nullable"] = True
	if "const" in out:
		out["enum"] = [out.pop("const")]
	# `field: NonBlank = None` means "may be omitted", not "may be null".
	if "default" in out and out["default"] is None and not out.get("nullable"):
		del out["default"]
	if "$ref" in out and len(out) > 1:
		out = {"allOf": [{"$ref": out.pop("$ref")}], **out}
	return out


def request_schema(
	cls: type[BaseModel], path_params: list[str], components: dict[str, Any]
) -> dict[str, Any] | None:
	"""The OpenAPI schema for a request model, minus the fields the path carries.

	None when nothing is left, as with a model that only names the record in the
	path. Nested models are added to `components` under their own names.
	"""
	schema = cls.model_json_schema(ref_template="#/components/schemas/{model}")
	for name, sub in schema.pop("$defs", {}).items():
		components.setdefault(name, oas30(sub))
	schema = oas30(schema)
	props = {k: v for k, v in schema.get("properties", {}).items() if k not in path_params}
	if not props:
		return None
	schema["properties"] = props
	required = [k for k in schema.get("required", []) if k in props]
	if required:
		schema["required"] = required
	else:
		schema.pop("required", None)
	if cls.__doc__ and "description" not in schema:
		schema["description"] = inspect.cleandoc(cls.__doc__)
	return schema


def query_parameters(schema: dict[str, Any]) -> list[dict[str, Any]]:
	"""A GET route's request model is its query string: one parameter per field."""
	required = set(schema.get("required", []))
	params = []
	for name, prop in schema["properties"].items():
		param: dict[str, Any] = {
			"name": name,
			"in": "query",
			"required": name in required,
			"schema": {k: v for k, v in prop.items() if k != "description"},
		}
		if prop.get("description"):
			param["description"] = prop["description"]
		params.append(param)
	return params


def request_model(endpoint_fn: Any) -> type[BaseModel] | None:
	"""The model `@validate_request` attached to an endpoint, if any."""
	return getattr(endpoint_fn, "_request_schema", None) or getattr(
		inspect.unwrap(endpoint_fn), "_request_schema", None
	)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def strip_extensions(o: Any) -> Any:
	"""The public contract: the same document without `x-` vendor extensions."""
	if isinstance(o, dict):
		return {k: strip_extensions(v) for k, v in o.items() if not k.startswith("x-")}
	if isinstance(o, list):
		return [strip_extensions(v) for v in o]
	return o


def dump_spec(doc: dict[str, Any], path, header: list[str]) -> None:
	"""Write `doc` as YAML under a comment header, in the layout every app commits."""
	with open(path, "w", encoding="utf-8") as f:  # nosemgrep: frappe-security-file-traversal
		for line in header:
			f.write(f"# {line}\n")
		yaml.safe_dump(doc, f, sort_keys=False, default_flow_style=False, width=100, allow_unicode=True)
