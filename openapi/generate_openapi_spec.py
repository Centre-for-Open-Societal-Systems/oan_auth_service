#!/usr/bin/env python3
"""generate_openapi_spec.py.

Dynamically discovers all declared REST routes across oan_auth_service,
introspects request/response models, query/path parameters, security requirements,
and builds openapi_v1.yaml and openapi_v1.public.yaml.

Outputs:
  - openapi_v1.yaml: Engineering/Internal specification with vendor extensions
    (x-legacy-rpc-method, x-schema-confidence).
  - openapi_v1.public.yaml: Public/Gateway contract with vendor extensions stripped.

Usage:
  python3 openapi/generate_openapi_spec.py
"""

import importlib
import inspect
import re
import sys
from pathlib import Path
from typing import Any

from oan_auth_service.openapi_spec import (
	ARR,
	OBJ,
	REF,
	B,
	I,
	S,
	dump_spec,
	make_envelope,
	query_parameters,
	request_model,
	request_schema,
	strip_extensions,
)

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
INTERNAL_SPEC_OUTPUT = SCRIPT_DIR / "openapi_v1.yaml"
PUBLIC_SPEC_OUTPUT = SCRIPT_DIR / "openapi_v1.public.yaml"


# ---------------------------------------------------------------------------
# Components: Data Schemas
# ---------------------------------------------------------------------------
DATA_SCHEMAS: dict[str, Any] = {}


def data(name: str, schema: dict[str, Any]) -> str:
	DATA_SCHEMAS[name] = schema
	return name


# Standard Response Envelopes
data(
	"ApiMeta",
	OBJ(
		{
			"api_version": S(example="v1", description="Semantic API version"),
			"status": S(example="current", description="Lifecycle status"),
		},
		required=["api_version"],
	),
)

data(
	"StandardErrorResponse",
	OBJ(
		{
			"status": S(example="error", enum=["error"]),
			"message": S(description="Human-readable error description"),
			"exception": S(nullable=True, description="Exception class name"),
			"errors": ARR(
				OBJ(
					{
						"field": S(nullable=True, description="Field causing the validation error"),
						"message": S(description="Error message for the specific field"),
					}
				),
				nullable=True,
				description="Structured validation errors if applicable",
			),
			"meta": REF("ApiMeta"),
			"request_id": S(format="uuid", nullable=True, description="Tracing correlation ID"),
		},
		required=["status", "message"],
		description="Standard error envelope returned on 4xx/5xx responses",
	),
)

data(
	"TokenPairData",
	OBJ(
		{
			"access_token": S(description="Short-lived JWT access token"),
			"refresh_token": S(description="Single-use cryptographically secure refresh token"),
			"token_type": S(example="Bearer"),
			"expires_in": I(example=900, description="Access token expiration in seconds"),
			"user": S(example="USR-0001", description="Canonical user ID or synthetic email"),
			"roles": ARR(S(), description="Roles assigned to this user"),
			"scope": ARR(S(), nullable=True, description="Narrowed token scope if requested"),
		},
		required=["access_token", "refresh_token", "token_type", "expires_in", "user", "roles"],
		description="Access token and refresh token pair",
	),
)

data(
	"LogoutData",
	OBJ(
		{"revoked": B(description="Whether the refresh token was revoked")},
		required=["revoked"],
	),
)

data(
	"UserMeData",
	OBJ(
		{
			"user": S(description="Unique User ID / internal handle"),
			"first_name": S(nullable=True),
			"last_name": S(nullable=True),
			"full_name": S(description="Full display name"),
			"login_email": S(format="email", nullable=True, description="Authoritative login email"),
			"mobile_no": S(nullable=True, description="Primary contact mobile number in E.164 format"),
			"country_code": S(example="+251", nullable=True, description="E.164 country dialing code"),
			"phone_number": S(
				example="911223344", nullable=True, description="National subscriber phone number"
			),
			"roles": ARR(S(), description="List of assigned roles"),
			"profiles": OBJ(
				{},
				additionalProperties=True,
				description="App-specific profiles collected from on_user_profile hooks (e.g. grievance)",
			),
		},
		required=["user", "full_name", "roles"],
		description="Introspected user identity and profile claims",
	),
)

data(
	"PublicKeyItem",
	OBJ(
		{
			"kid": S(description="Key Identifier"),
			"kty": S(example="RSA", description="Key Type"),
			"alg": S(example="RS256", description="Algorithm"),
			"use": S(example="sig", description="Key usage"),
			"n": S(description="RSA modulus, base64url"),
			"e": S(example="AQAB", description="RSA public exponent, base64url"),
		},
		required=["kid", "kty", "alg", "use", "n", "e"],
	),
)

data(
	"PublicKeysData",
	OBJ(
		{
			"issuer": S(description="JWT issuer identifier"),
			"algorithm": S(example="RS256"),
			"active_kid": S(description="Currently active Key ID used for signing"),
			"keys": ARR(REF("PublicKeyItem")),
		},
		required=["issuer", "algorithm", "active_kid", "keys"],
		description="RS256 public keys (JWKS) that verify access tokens, and the active signing kid",
	),
)

data(
	"HealthData",
	OBJ(
		{
			"status": S(example="healthy"),
			"service": S(example="oan_auth_service"),
			"api_version": S(example="v1"),
		},
		required=["status", "service", "api_version"],
		description="Service health status",
	),
)

data(
	"MetadataData",
	OBJ(
		{
			"auth": OBJ(
				{
					"self_registerable_roles": ARR(
						S(), description="Roles allowed during public self-registration"
					),
				},
				required=["self_registerable_roles"],
			),
		},
		additionalProperties=True,
		required=["auth"],
		description="Aggregated reference metadata across installed apps",
	),
)

data(
	"MessageOnlyData",
	OBJ(
		{"message": S(description="Status confirmation message")},
		required=["message"],
	),
)


# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------
# Derived from each route's @validate_request model by build_openapi().
REQ: dict[str, Any] = {}


# Envelope Schemas
ENVELOPES: dict[str, Any] = {
	"TokenPairResponse": make_envelope("TokenPairData", description="Token pair response"),
	"LogoutResponse": make_envelope("LogoutData", description="Logout revocation response"),
	"UserMeResponse": make_envelope("UserMeData", description="Authenticated user introspection response"),
	"PublicKeysResponse": make_envelope("PublicKeysData", description="Public keys metadata response"),
	"HealthResponse": make_envelope("HealthData", description="Health check response"),
	"MetadataResponse": make_envelope("MetadataData", description="Reference metadata response"),
	"MessageOnlyResponse": OBJ(
		{
			"status": S(example="success", enum=["success"]),
			"message": S(description="Action confirmation message"),
			"meta": REF("ApiMeta"),
			"request_id": S(format="uuid", nullable=True),
		},
		required=["status", "message"],
		description="Message-only confirmation response",
	),
}


# ---------------------------------------------------------------------------
# Dynamic Discovery Helpers
# ---------------------------------------------------------------------------
def _import_all_api_modules() -> None:
	"""Dynamically imports all modules under oan_auth_service.api to populate route registry."""
	api_dir = REPO_ROOT / "oan_auth_service" / "api"
	sys.path.insert(0, str(REPO_ROOT))

	# Import router module
	importlib.import_module("oan_auth_service.api.router")

	# Import v1 endpoint modules
	v1_dir = api_dir / "v1"
	if v1_dir.exists():
		for py_file in sorted(v1_dir.glob("*.py")):
			if py_file.name.startswith("_"):
				continue
			mod_name = f"oan_auth_service.api.v1.{py_file.stem}"
			try:
				# nosemgrep: non-literal-import, python.lang.security.audit.non-literal-import.non-literal-import
				importlib.import_module(mod_name)
			except Exception as e:
				print(f"Warning: could not import {mod_name}: {e}", file=sys.stderr)


def _determine_tag(path: str, func_name: str, api_doc_tags: list[str] | None = None) -> str:
	if api_doc_tags and api_doc_tags[0]:
		return api_doc_tags[0]
	path_parts = set(path.strip("/").split("/"))
	if func_name in ("login", "register_user", "refresh", "logout") or any(
		x in path_parts for x in ("login", "register", "refresh", "logout")
	):
		return "Authentication & Session"
	if func_name in ("forgot_password", "reset_password") or any(
		x in path_parts for x in ("forgot-password", "reset-password", "password")
	):
		return "Password Recovery"
	if func_name in ("get_me", "me") or "me" in path_parts or "profile" in path_parts:
		return "Identity & Profile"
	if func_name in ("get_keys", "get_public_keys", "get_health", "get_metadata") or any(
		x in path_parts for x in ("keys", "health", "metadata")
	):
		return "System & Keys"

	clean = path.removeprefix("/api/v1/").removeprefix("/api/")
	parts = clean.split("/")
	if parts:
		return parts[0].replace("-", " ").replace("_", " ").title()
	return "Authentication & Session"


def _determine_response_schema(
	func_name: str, path: str, method: str, api_doc_resp: Any = None
) -> str | None:
	if api_doc_resp:
		if isinstance(api_doc_resp, str):
			return api_doc_resp
		if hasattr(api_doc_resp, "__name__"):
			return api_doc_resp.__name__

	mapping = {
		"login": "TokenPairResponse",
		"register_user": "TokenPairResponse",
		"refresh": "TokenPairResponse",
		"logout": "LogoutResponse",
		"get_me": "UserMeResponse",
		"get_public_keys": "PublicKeysResponse",
		"get_health": "HealthResponse",
		"get_metadata": "MetadataResponse",
		"forgot_password": "MessageOnlyResponse",
		"reset_password": "MessageOnlyResponse",
	}
	if func_name in mapping:
		return mapping[func_name]

	resp_candidate = f"{func_name.title().replace('_', '')}Response"
	if resp_candidate in ENVELOPES:
		return resp_candidate
	return None


# ---------------------------------------------------------------------------
# Build Document
# ---------------------------------------------------------------------------
def build_openapi() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
	_import_all_api_modules()

	from oan_auth_service.api.router import _exempt_paths, _rules

	paths: dict[str, Any] = {}
	seen_ops: set[tuple[str, str]] = set()

	for rule in _rules:
		# Convert Werkzeug pattern e.g. <path:area_id_or_path> or <token> to {param}
		openapi_path = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", rule.rule)
		path_param_names = re.findall(r"<(?:\w+:)?(\w+)>", rule.rule)

		methods = [m.upper() for m in rule.methods if m.upper() not in ("HEAD", "OPTIONS")]
		endpoint_fn = rule.endpoint
		inner_fn = inspect.unwrap(endpoint_fn)

		func_name = inner_fn.__name__
		legacy_target = f"{inner_fn.__module__}.{func_name}"

		route_info = getattr(endpoint_fn, "_route", {})
		api_doc_info = getattr(endpoint_fn, "_api_doc", None) or getattr(inner_fn, "_api_doc", None) or {}

		allow_guest = route_info.get("allow_guest", False) or rule.rule in _exempt_paths
		status_code = route_info.get("status", 200)

		summary = (
			route_info.get("summary")
			or api_doc_info.get("summary")
			or (inner_fn.__doc__ or "").strip().split("\n")[0]
		)
		description = (
			route_info.get("description")
			or api_doc_info.get("description")
			or route_info.get("summary")
			or summary
		)

		tag = _determine_tag(openapi_path, func_name, api_doc_info.get("tags"))
		req_model = request_model(endpoint_fn)
		req_schema_name = req_model.__name__ if req_model else None
		req_schema = request_schema(req_model, path_param_names, REQ) if req_model else None
		response_schema_name = _determine_response_schema(
			func_name, openapi_path, methods[0] if methods else "GET", api_doc_info.get("response_model")
		)

		for method in sorted(methods):
			op_key = (method, openapi_path)
			if op_key in seen_ops:
				continue
			seen_ops.add(op_key)

			if openapi_path not in paths:
				paths[openapi_path] = {}

			# Path parameters
			parameters: list[dict[str, Any]] = []
			for p in path_param_names:
				parameters.append(
					{
						"name": p,
						"in": "path",
						"required": True,
						"schema": S(),
						"description": f"{p.replace('_', ' ').title()} parameter",
					}
				)

			if method == "GET" and req_schema:
				parameters.extend(query_parameters(req_schema))

			op: dict[str, Any] = {
				"tags": [tag],
				"summary": summary,
				"description": description,
				"operationId": f"{method.lower()}_{openapi_path.strip('/').replace('/', '_').replace('-', '_').replace('{', '').replace('}', '')}",
				"responses": {
					str(status_code): {
						"description": "Success",
						"content": {
							"application/json": {
								"schema": (
									REF(response_schema_name)
									if response_schema_name
									else REF("StandardErrorResponse")
								)
							}
						},
					},
					"400": {
						"description": "Validation or Client Error",
						"content": {"application/json": {"schema": REF("StandardErrorResponse")}},
					},
					"500": {
						"description": "Internal Server Error",
						"content": {"application/json": {"schema": REF("StandardErrorResponse")}},
					},
				},
			}

			if not allow_guest:
				op["responses"]["401"] = {
					"description": "Unauthorized / Authentication Required",
					"content": {"application/json": {"schema": REF("StandardErrorResponse")}},
				}

			if parameters:
				op["parameters"] = parameters

			op["x-legacy-rpc-method"] = legacy_target
			op["security"] = [] if allow_guest else [{"BearerAuth": []}]

			# A model left empty once the path parameters are taken out means no body.
			if method in ("POST", "PUT", "PATCH", "DELETE") and req_schema:
				REQ[req_schema_name] = req_schema
				op["requestBody"] = {
					"required": bool(req_schema.get("required")),
					"content": {"application/json": {"schema": REF(req_schema_name)}},
				}

			paths[openapi_path][method.lower()] = op

	components_schemas: dict[str, Any] = {}
	components_schemas.update(DATA_SCHEMAS)
	components_schemas.update(REQ)
	components_schemas.update(ENVELOPES)

	doc: dict[str, Any] = {
		"openapi": "3.0.3",
		"info": {
			"title": "OAN Authentication Service API",
			"version": "1.0.0",
			"description": (
				"JWT authentication and user lifecycle service for OpenAgriNet (OAN). "
				"Provides RESTful endpoints for user registration, login, token refresh, "
				"logout, password recovery, identity introspection, and metadata aggregation."
			),
			"contact": {"name": "COSS - Centre for Open Societal Systems"},
		},
		"servers": [
			{"url": "http://localhost:8000", "description": "Local Frappe Bench"},
			{"url": "https://auth.openagrinet.org", "description": "Production Auth Gateway"},
		],
		"tags": [
			{
				"name": "Authentication & Session",
				"description": "User login, registration, and token lifecycle",
			},
			{
				"name": "Password Recovery",
				"description": "Forgot password and reset flows via email or SMS OTP",
			},
			{"name": "Identity & Profile", "description": "User profile introspection and claims"},
			{"name": "System & Keys", "description": "Health check, public key discovery, and metadata"},
		],
		"paths": paths,
		"components": {
			"securitySchemes": {
				"BearerAuth": {
					"type": "http",
					"scheme": "bearer",
					"bearerFormat": "JWT",
					"description": "Provide access token as `Bearer <token>` in the Authorization header.",
				}
			},
			"schemas": components_schemas,
		},
	}

	# Ensure any dynamically discovered tags are present in root tag list
	defined_tag_names = {t["name"] for t in doc["tags"]}
	for p_ops in paths.values():
		for op_item in p_ops.values():
			for t_name in op_item.get("tags", []):
				if t_name not in defined_tag_names:
					doc["tags"].append({"name": t_name, "description": f"Operations for {t_name}"})
					defined_tag_names.add(t_name)

	return doc, paths, components_schemas


def main() -> None:
	doc, paths, components_schemas = build_openapi()
	n_paths = len(paths)
	n_ops = sum(len(v) for v in paths.values())

	dump_spec(
		doc,
		INTERNAL_SPEC_OUTPUT,
		[
			"OAN Authentication Service API -- OpenAPI 3.0.3 (INTERNAL)",
			"Carries internal vendor extensions (x-legacy-rpc-method).",
			"Generated from generate_openapi_spec.py -- do not edit manually.",
		],
	)
	print(
		f"Wrote {INTERNAL_SPEC_OUTPUT.name}: {n_paths} paths, {n_ops} operations, {len(components_schemas)} schemas",
		file=sys.stderr,
	)

	dump_spec(
		strip_extensions(doc),
		PUBLIC_SPEC_OUTPUT,
		[
			"OAN Authentication Service API -- OpenAPI 3.0.3 (PUBLIC)",
			"Contract with vendor extensions removed. Generated from generate_openapi_spec.py.",
		],
	)
	print(
		f"Wrote {PUBLIC_SPEC_OUTPUT.name}: {n_paths} paths, {n_ops} operations, {len(components_schemas)} schemas",
		file=sys.stderr,
	)


if __name__ == "__main__":
	main()
