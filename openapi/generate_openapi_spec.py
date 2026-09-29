#!/usr/bin/env python3
"""
generate_openapi_spec.py

Builds openapi_v1.yaml and openapi_v1.public.yaml for the OAN Authentication Service.
Generates an OpenAPI 3.0.3 specification covering JWT authentication, registration,
refresh token rotation, logout, password recovery, current user introspection,
public keys, health, and system metadata.

Outputs:
  - openapi_v1.yaml: Engineering/Internal specification with vendor extensions
    (x-legacy-rpc-method, x-schema-confidence).
  - openapi_v1.public.yaml: Public/Gateway contract with vendor extensions stripped.

Usage:
  python3 generate_openapi_spec.py
"""

import sys
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
INTERNAL_SPEC_OUTPUT = SCRIPT_DIR / "openapi_v1.yaml"
PUBLIC_SPEC_OUTPUT = SCRIPT_DIR / "openapi_v1.public.yaml"


# ---------------------------------------------------------------------------
# Schema building helper functions
# ---------------------------------------------------------------------------
def S(**kw):
	return {"type": "string", **kw}


def I(**kw):  # noqa: E743
	return {"type": "integer", **kw}


def N(**kw):
	return {"type": "number", **kw}


def B(**kw):
	return {"type": "boolean", **kw}


def ARR(items, **kw):
	return {"type": "array", "items": items, **kw}


def OBJ(props, required=None, description=None, confidence=None, **kw):
	d = {"type": "object", "properties": props, **kw}
	if required:
		d["required"] = required
	if description:
		d["description"] = description
	if confidence:
		d["x-schema-confidence"] = confidence
	return d


def REF(name):
	return {"$ref": f"#/components/schemas/{name}"}


# ---------------------------------------------------------------------------
# Components: Data Schemas
# ---------------------------------------------------------------------------
DATA_SCHEMAS = {}


def data(name, schema):
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
			"mobile_no": S(nullable=True, description="Primary contact mobile number"),
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
			"kty": S(example="oct", description="Key Type"),
			"alg": S(example="HS256", description="Algorithm"),
			"use": S(example="sig", description="Public key usage"),
		},
		required=["kid", "kty", "alg", "use"],
	),
)

data(
	"PublicKeysData",
	OBJ(
		{
			"issuer": S(description="JWT issuer string"),
			"algorithm": S(example="HS256"),
			"active_kid": S(description="Currently active Key ID used for signing"),
			"keys": ARR(REF("PublicKeyItem")),
		},
		required=["issuer", "algorithm", "active_kid", "keys"],
		description="Public verification key information",
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
# Request Body Schemas
# ---------------------------------------------------------------------------
REQ = {}

REQ["RegisterRequest"] = OBJ(
	{
		"password": S(
			format="password",
			minLength=8,
			maxLength=128,
			description="Password meeting complexity requirements (at least 8 characters)",
		),
		"full_name": S(minLength=1, maxLength=140, description="Full name of user or organization"),
		"email": S(format="email", nullable=True, description="Login email address"),
		"phone_number": S(nullable=True, description="E.164 formatted phone number e.g. +251911223344"),
		"role": S(nullable=True, description="Singular role to request"),
		"roles": ARR(S(), nullable=True, description="Multiple roles to request"),
	},
	required=["password", "full_name"],
	additionalProperties=True,
	description="Payload for registering a new user account. Additional fields are forwarded to domain hooks.",
)

REQ["LoginRequest"] = OBJ(
	{
		"usr": S(minLength=1, description="Login identifier: email, mobile number, or User ID"),
		"pwd": S(format="password", minLength=1, description="Account password"),
		"remember_me": B(default=False, description="Extend refresh token lifetime to 30 days"),
		"scope": S(nullable=True, description="Optional scope narrowing: comma-separated list of roles"),
	},
	required=["usr", "pwd"],
	description="Credentials to authenticate and obtain token pair",
)

REQ["RefreshTokenRequest"] = OBJ(
	{
		"refresh_token": S(minLength=1, description="Active single-use refresh token"),
	},
	required=["refresh_token"],
	description="Refresh token exchange payload",
)

REQ["LogoutRequest"] = OBJ(
	{
		"refresh_token": S(minLength=1, description="Active refresh token to revoke"),
	},
	required=["refresh_token"],
	description="Revoke refresh token session",
)

REQ["ForgotPasswordRequest"] = OBJ(
	{
		"usr": S(minLength=1, description="Login handle (email or phone number) to initiate recovery"),
	},
	required=["usr"],
	description="Password recovery initiation request",
)

REQ["ResetPasswordRequest"] = OBJ(
	{
		"new_password": S(format="password", minLength=8, maxLength=128, description="New account password"),
		"key": S(nullable=True, description="Reset token key received via email link"),
		"usr": S(nullable=True, description="Login identifier (used alongside SMS OTP)"),
		"otp": S(nullable=True, description="Numeric one-time verification code received via SMS"),
	},
	required=["new_password"],
	description="Password reset completion payload. Provide either `key` OR (`usr` and `otp`).",
)


# ---------------------------------------------------------------------------
# Envelope Builder Helper
# ---------------------------------------------------------------------------
def make_envelope(data_ref, is_list=False, description="Successful response"):
	data_prop = ARR(REF(data_ref)) if is_list else REF(data_ref)
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


# Envelope Schemas
ENVELOPES = {
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
# Routes Specification
# ---------------------------------------------------------------------------
def R(
	method,
	path,
	summary,
	tag,
	security,
	request=None,
	query=None,
	response=None,
	legacy="",
	status=200,
	description="",
):
	return dict(
		method=method.lower(),
		path=path,
		summary=summary,
		tag=tag,
		security=security,
		request=request,
		query=query or [],
		response=response,
		legacy=legacy,
		status=status,
		description=description,
	)


ROUTES = [
	# Domain 1: Authentication & Session
	R(
		"post",
		"/api/v1/auth/register",
		summary="Register a new user account",
		tag="Authentication & Session",
		security=[],
		request="RegisterRequest",
		response="TokenPairResponse",
		legacy="oan_auth_service.api.v1.auth.register_user",
		description=(
			"Creates a User record, assigns permissible self-registration roles, fires registered "
			"`on_user_registered` hooks across installed apps to link domain records, and issues an "
			"initial JWT access and refresh token pair."
		),
	),
	R(
		"post",
		"/api/v1/auth/login",
		summary="Login and obtain token pair",
		tag="Authentication & Session",
		security=[],
		request="LoginRequest",
		response="TokenPairResponse",
		legacy="oan_auth_service.api.v1.auth.login",
		description=(
			"Authenticates credentials against the User repository, resolves login identifier "
			"(email, mobile_no, or user ID), mitigates timing oracles, and returns a short-lived access "
			"token along with a single-use refresh token."
		),
	),
	R(
		"post",
		"/api/v1/auth/refresh",
		summary="Exchange single-use refresh token",
		tag="Authentication & Session",
		security=[],
		request="RefreshTokenRequest",
		response="TokenPairResponse",
		legacy="oan_auth_service.api.v1.auth.refresh",
		description=(
			"Exchanges an active refresh token for a brand new token pair. The submitted refresh token "
			"is single-use and immediately deleted to prevent replay attacks."
		),
	),
	R(
		"post",
		"/api/v1/auth/logout",
		summary="Revoke refresh token",
		tag="Authentication & Session",
		security=[],
		request="LogoutRequest",
		response="LogoutResponse",
		legacy="oan_auth_service.api.v1.auth.logout",
		description="Revokes an active refresh token in the database.",
	),
	# Domain 2: Password Recovery
	R(
		"post",
		"/api/v1/auth/forgot-password",
		summary="Initiate password recovery",
		tag="Password Recovery",
		security=[],
		request="ForgotPasswordRequest",
		response="MessageOnlyResponse",
		legacy="oan_auth_service.api.v1.auth.forgot_password",
		description=(
			"Initiates password recovery. Dispatches an email reset link if the user has an email address, "
			"or an SMS OTP code if the account is mobile-only. Returns a generic message to prevent account enumeration."
		),
	),
	R(
		"post",
		"/api/v1/auth/reset-password",
		summary="Complete password reset",
		tag="Password Recovery",
		security=[],
		request="ResetPasswordRequest",
		response="MessageOnlyResponse",
		legacy="oan_auth_service.api.v1.auth.reset_password",
		description=(
			"Completes password reset using either an emailed `key` or (`usr` + `otp`) texted to mobile. "
			"Revokes all existing refresh tokens for the user upon successful reset."
		),
	),
	# Domain 3: Identity & Profile
	R(
		"get",
		"/api/v1/auth/me",
		summary="Introspect current authenticated user",
		tag="Identity & Profile",
		security=[{"BearerAuth": []}],
		response="UserMeResponse",
		legacy="oan_auth_service.api.v1.auth.get_me",
		description=(
			"Returns canonical details, assigned roles, and namespaced profiles for the authenticated user "
			"collected from `on_user_profile` hooks."
		),
	),
	# Domain 4: System & Keys
	R(
		"get",
		"/api/v1/auth/keys",
		summary="Public key information",
		tag="System & Keys",
		security=[],
		response="PublicKeysResponse",
		legacy="oan_auth_service.api.v1.auth.get_public_keys",
		description="Returns active key ID (kid), algorithm (HS256), and public key metadata.",
	),
	R(
		"get",
		"/api/v1/auth/health",
		summary="Service health status",
		tag="System & Keys",
		security=[],
		response="HealthResponse",
		legacy="oan_auth_service.api.v1.auth.get_health",
		description="Lightweight health check endpoint for container probes and load balancers.",
	),
	R(
		"get",
		"/api/v1/auth/metadata",
		summary="Aggregated form and reference metadata",
		tag="System & Keys",
		security=[],
		response="MetadataResponse",
		legacy="oan_auth_service.api.v1.auth.get_metadata",
		description="Aggregates public reference metadata and registration settings across installed apps.",
	),
]


# ---------------------------------------------------------------------------
# Build Document
# ---------------------------------------------------------------------------
def build_openapi():
	paths = {}

	for r in ROUTES:
		p = r["path"]
		m = r["method"]

		if p not in paths:
			paths[p] = {}

		op = {
			"tags": [r["tag"]],
			"summary": r["summary"],
			"description": r["description"],
			"operationId": f"{m}_{p.strip('/').replace('/', '_').replace('-', '_')}",
			"responses": {
				str(r["status"]): {
					"description": "Success",
					"content": {"application/json": {"schema": REF(r["response"])}},
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

		if r["legacy"]:
			op["x-legacy-rpc-method"] = r["legacy"]

		if r["security"] is not None:
			op["security"] = r["security"]

		if r["request"]:
			op["requestBody"] = {
				"required": True,
				"content": {"application/json": {"schema": REF(r["request"])}},
			}

		paths[p][m] = op

	components_schemas = {}
	components_schemas.update(DATA_SCHEMAS)
	components_schemas.update(REQ)
	components_schemas.update(ENVELOPES)

	doc = {
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
	return doc, paths, components_schemas


def strip_extensions(o):
	if isinstance(o, dict):
		return {k: strip_extensions(v) for k, v in o.items() if not k.startswith("x-")}
	if isinstance(o, list):
		return [strip_extensions(v) for v in o]
	return o


def main():
	doc, paths, components_schemas = build_openapi()

	# 1. Write internal spec
	with open(INTERNAL_SPEC_OUTPUT, "w") as f:
		f.write("# OAN Authentication Service API -- OpenAPI 3.0.3 (INTERNAL)\n")
		f.write("# Carries internal vendor extensions (x-legacy-rpc-method).\n")
		f.write("# Generated from generate_openapi_spec.py -- do not edit manually.\n")
		yaml.safe_dump(doc, f, sort_keys=False, default_flow_style=False, width=100, allow_unicode=True)

	n_paths = len(paths)
	n_ops = sum(len(v) for v in paths.values())
	print(
		f"Wrote {INTERNAL_SPEC_OUTPUT.name}: {n_paths} paths, {n_ops} operations, {len(components_schemas)} schemas",
		file=sys.stderr,
	)

	# 2. Write public spec (vendor extensions stripped)
	public_doc = strip_extensions(doc)
	with open(PUBLIC_SPEC_OUTPUT, "w") as f:
		f.write("# OAN Authentication Service API -- OpenAPI 3.0.3 (PUBLIC)\n")
		f.write("# Contract with vendor extensions removed. Generated from generate_openapi_spec.py.\n")
		yaml.safe_dump(
			public_doc, f, sort_keys=False, default_flow_style=False, width=100, allow_unicode=True
		)

	print(
		f"Wrote {PUBLIC_SPEC_OUTPUT.name}: {n_paths} paths, {n_ops} operations, {len(components_schemas)} schemas",
		file=sys.stderr,
	)


if __name__ == "__main__":
	main()
