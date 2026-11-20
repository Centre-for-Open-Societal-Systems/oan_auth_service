# Copyright (c) 2026, COSS - Centre for Open Societal Systems and contributors
# For license information, please see license.txt

"""One OpenAPI + APISIX generator for every app on the shared router.

Build-time tooling, run from an app's `openapi/generate_openapi_spec.py`. Everything
the spec needs about an endpoint is already declared on it:

- `@rest(...)` gives the path, methods, auth scheme, success status and gateway tier;
- `@validate_request(Model)` gives the request body (or, on a GET, the query string);
- `@api_doc(...)` gives the summary, description, tags and `response_model`.

so an app's script is a call, not a copy of this file:

	from oan_auth_service.openapi_generator import generate_spec_and_gateway

	generate_spec_and_gateway(
		app_name="oan-da-services",
		module="da_services",
		title="OAN DA Services API",
		upstream_host_env="DA_SERVICES_UPSTREAM_HOST",
		tiers=TIERS,
		openapi_dir=Path(__file__).parent,
		gateway_dir=Path(__file__).parent.parent / "apisix",
	)

Anything an app cannot declare on the endpoint (a tag taxonomy, a response catalog
for handlers that predate `response_model`, bespoke security) is passed as an
argument. The hooks are the only app-specific code left.
"""

import copy
import importlib
import inspect
import pkgutil
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, get_args, get_origin

from pydantic import BaseModel

from oan_auth_service import gateway_apisix as gw
from oan_auth_service.api.router import declared_endpoints
from oan_auth_service.openapi_spec import (
	ARR,
	BINARY,
	OBJ,
	REF,
	S,
	dump_spec,
	make_envelope,
	oas30,
	query_parameters,
	request_model,
	request_schema,
	strip_extensions,
)

ERROR_RESPONSES = {
	"400": "Validation or Bad Input Error",
	"401": "Unauthorized / Authentication Required",
	"403": "Forbidden / Insufficient Role Scope",
	"404": "Resource Not Found",
	"500": "Internal Server Error",
}

BEARER_SECURITY_SCHEME = {
	"type": "http",
	"scheme": "bearer",
	"bearerFormat": "JWT",
	"description": "Provide JWT access token as `Bearer <token>` in the Authorization header.",
}


def standard_schemas() -> dict[str, Any]:
	"""The envelope pieces every `make_envelope` response and error response refers to."""
	return {
		"ApiMeta": OBJ(
			{
				"api_version": S(example="v1", description="Semantic API version"),
				"status": S(example="current", description="Lifecycle status"),
			},
			required=["api_version"],
		),
		"StandardErrorResponse": OBJ(
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
	}


# ---------------------------------------------------------------------------
# Route discovery
# ---------------------------------------------------------------------------


def import_route_modules(package: str, modules: list[str] | None = None) -> None:
	"""Import `modules`, else `package` and every module under it: importing declares a route.

	Paths appear in the spec in the order routes were declared, so an app that wants a
	stable, hand-chosen order lists its modules.
	"""
	if modules is None:
		root = importlib.import_module(package)
		modules = [info.name for info in pkgutil.walk_packages(root.__path__, prefix=f"{package}.")]
	for name in modules:
		try:
			importlib.import_module(name)
		except Exception as e:
			print(f"Warning: Failed to import {name}: {e}", file=sys.stderr)


def api_doc_of(endpoint_fn: Any) -> dict[str, Any] | None:
	"""The `@api_doc` metadata, wherever it sits in the decorator stack."""
	curr = endpoint_fn
	while curr is not None:
		if hasattr(curr, "_api_doc"):
			return curr._api_doc
		curr = getattr(curr, "__wrapped__", None)
	return None


def _register_model(model: type[BaseModel], components: dict[str, Any]) -> None:
	schema = model.model_json_schema(ref_template="#/components/schemas/{model}")
	for name, sub in schema.pop("$defs", {}).items():
		components.setdefault(name, oas30(sub))
	components.setdefault(model.__name__, oas30(schema))


def response_from_model(
	response_model: Any, components: dict[str, Any], envelopes: dict[str, Any]
) -> str | None:
	"""Register `@api_doc(response_model=...)` as components and return its envelope's name."""
	# dict[Literal[key], RecordModel]: one record under `key`.
	if get_origin(response_model) is dict:
		args = get_args(response_model)
		if len(args) == 2 and get_origin(args[0]) is Literal:
			key, record = get_args(args[0])[0], args[1]
			if inspect.isclass(record) and issubclass(record, BaseModel):
				_register_model(record, components)
				base = record.__name__.removesuffix("Record")
				components.setdefault(f"{base}Data", OBJ({key: REF(record.__name__)}, required=[key]))
				name = f"{base}Response"
				envelopes.setdefault(name, make_envelope(f"{base}Data", description=f"{base} response"))
				return name

	if inspect.isclass(response_model) and issubclass(response_model, BaseModel):
		_register_model(response_model, components)
		model_name = response_model.__name__
		if model_name.endswith("ListData"):
			name = f"{model_name.removesuffix('ListData')}ListResponse"
		elif model_name.endswith("Data"):
			name = f"{model_name.removesuffix('Data')}Response"
		else:
			name = f"{model_name}Response"
		envelopes.setdefault(name, make_envelope(model_name, description=f"{model_name} response"))
		return name
	return None


# ---------------------------------------------------------------------------
# Spec
# ---------------------------------------------------------------------------

_PATH_PARAM = re.compile(r"<(?:\w+:)?(\w+)>")


def build_openapi(
	*,
	app: str,
	title: str,
	description: str,
	servers: list[dict[str, str]],
	version: str = "1.0.0",
	tags: list[dict[str, str]] | None = None,
	security_schemes: dict[str, Any] | None = None,
	schemas: dict[str, Any] | None = None,
	envelopes: dict[str, Any] | None = None,
	contact: dict[str, str] | None = None,
	multipart_requests: dict[str, tuple[str, ...]] | None = None,
	path_param_docs: dict[str, str] | None = None,
	tag_for: Callable[[str, str], str] | None = None,
	response_for: Callable[[str, str, str], str | None] | None = None,
	query_parameters_for: Callable[[str, str, str], list[dict[str, Any]]] | None = None,
	security_for: Callable[[str, bool], list[dict[str, list]]] | None = None,
	customize_operation: Callable[[dict[str, Any], str, str], None] | None = None,
) -> dict[str, Any]:
	"""The OpenAPI 3.0.3 document for every route `app` declared through `rest`.

	`schemas` and `envelopes` are the app's hand-written response catalog, for handlers
	with no `response_model`; they are copied, so a second build starts clean.
	Hooks, all optional, and called with the handler's function name where they get one:

	- `tag_for(path, func_name)`: tag when `@api_doc` has no `tags`;
	- `response_for(func_name, path, method)`: envelope name when there is no `response_model`;
	- `query_parameters_for(func_name, path, method)`: query string of a GET with no request model;
	- `security_for(func_name, is_public)`: the operation's `security`, default bearer/none;
	- `customize_operation(op, func_name, method)`: last word on a finished operation.
	"""
	components = {**standard_schemas(), **copy.deepcopy(schemas or {})}
	envelopes = copy.deepcopy(envelopes or {})
	requests: dict[str, Any] = {}
	multipart_requests = multipart_requests or {}
	path_param_docs = path_param_docs or {}

	paths: dict[str, Any] = {}
	seen: set[tuple[str, str]] = set()

	for endpoint in declared_endpoints(app):
		route = endpoint._route
		rule_path = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", route["path"])
		path_params = _PATH_PARAM.findall(route["path"])
		unwrapped = inspect.unwrap(endpoint)
		func_name = unwrapped.__name__
		doc = api_doc_of(endpoint) or {}

		summary = (
			doc.get("summary") or route.get("summary") or (unwrapped.__doc__ or "").strip().split("\n")[0]
		)
		op_description = doc.get("description") or (unwrapped.__doc__ or "").strip() or summary
		tag = (doc.get("tags") or [None])[0] or (tag_for(rule_path, func_name) if tag_for else None)

		model = request_model(endpoint)
		model_name = model.__name__ if model else None
		req_schema = request_schema(model, path_params, requests) if model else None

		is_public = route["auth"] == "public"
		response_name = response_from_model(doc.get("response_model"), components, envelopes) if doc else None
		for method in sorted(route["methods"]):
			if method == "HEAD" or (method, rule_path) in seen:
				continue
			seen.add((method, rule_path))

			parameters = [
				{
					"name": p,
					"in": "path",
					"required": True,
					"schema": S(),
					"description": path_param_docs.get(p, f"{p.replace('_', ' ').title()} identifier"),
				}
				for p in path_params
			]
			if method == "GET":
				if req_schema:
					parameters.extend(query_parameters(req_schema))
				elif query_parameters_for:
					parameters.extend(copy.deepcopy(query_parameters_for(func_name, rule_path, method)))

			name = response_name or (response_for(func_name, rule_path, method) if response_for else None)
			op: dict[str, Any] = {
				"tags": [tag] if tag else [],
				"summary": summary,
				"description": op_description,
				"operationId": f"{method.lower()}_{re.sub(r'[/-]', '_', rule_path.strip('/')).replace('{', '').replace('}', '')}",
				"responses": {
					str(route.get("status") or 200): {
						"description": "Success",
						"content": {"application/json": {"schema": REF(name) if name else BINARY}},
					},
					**{
						code: {
							"description": text,
							"content": {"application/json": {"schema": REF("StandardErrorResponse")}},
						}
						for code, text in ERROR_RESPONSES.items()
					},
				},
			}
			if doc.get("deprecated"):
				op["deprecated"] = True
			if parameters:
				op["parameters"] = parameters
			op["x-legacy-rpc-method"] = f"{unwrapped.__module__}.{func_name}"
			if route.get("tier"):
				op["x-gateway-tier"] = route["tier"]
			op["security"] = (
				security_for(func_name, is_public)
				if security_for
				else ([] if is_public else [{"BearerAuth": []}])
			)

			# A model left empty once the path parameters are taken out means no body.
			if method in ("POST", "PUT", "PATCH", "DELETE") and req_schema:
				body = copy.deepcopy(req_schema)
				if model_name in multipart_requests:
					body["properties"]["files"] = ARR(
						BINARY, description="Files, sent as multipart/form-data"
					)
				component = model_name
				if requests.get(component, body) != body:
					# The same model on routes with different path parameters.
					component = f"{model_name}_{'_'.join(path_params) or 'body'}"
				requests[component] = body
				op["requestBody"] = {
					"required": bool(body.get("required")),
					"content": {
						ct: {"schema": REF(component)}
						for ct in multipart_requests.get(model_name, ("application/json",))
					},
				}

			if customize_operation:
				customize_operation(op, func_name, method)
			paths.setdefault(rule_path, {})[method.lower()] = op

	return {
		"openapi": "3.0.3",
		"info": {
			"title": title,
			"version": version,
			"description": description,
			"contact": contact or {"name": "COSS - Centre for Open Societal Systems"},
		},
		"servers": servers,
		"tags": tags or [],
		"paths": paths,
		"components": {
			"securitySchemes": {"BearerAuth": BEARER_SECURITY_SCHEME, **(security_schemes or {})},
			"schemas": {**components, **requests, **envelopes},
		},
	}


def write_specs(
	doc: dict[str, Any],
	openapi_dir: Path,
	public_servers: list[dict[str, str]],
	*,
	title: str,
	filename: str = "openapi_v1",
) -> None:
	"""The internal spec (vendor extensions, Frappe paths) and the public contract."""
	n_paths = len(doc["paths"])
	n_ops = sum(len(v) for v in doc["paths"].values())
	n_schemas = len(doc["components"]["schemas"])
	for suffix, spec, lines in (
		(
			"",
			doc,
			[
				f"{title} -- OpenAPI 3.0.3 (INTERNAL)",
				"Carries internal vendor extensions (x-legacy-rpc-method, x-gateway-tier).",
				"Generated by oan_auth_service.openapi_generator -- do not edit manually.",
			],
		),
		(
			".public",
			gw.publicize_spec(strip_extensions(doc), public_servers),
			[
				f"{title} -- OpenAPI 3.0.3 (PUBLIC)",
				"Contract with vendor extensions removed. Generated by oan_auth_service.openapi_generator.",
			],
		),
	):
		out = openapi_dir / f"{filename}{suffix}.yaml"
		dump_spec(spec, out, lines)
		print(f"Wrote {out.name}: {n_paths} paths, {n_ops} operations, {n_schemas} schemas", file=sys.stderr)


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------


def api_upstream(host_env: str, port_env: str, site_name: str) -> dict[str, Any]:
	"""Frappe upstream. The host stays a `${VAR}` placeholder that ADC or Helm fills in."""
	try:
		upstream = gw.upstream(
			host_env=host_env,
			port_env=port_env,
			# Frappe picks the site from the Host header, so send the site name, not the gateway's.
			pass_host="rewrite",
			upstream_host=site_name,
			timeout={"connect": 5, "send": 20, "read": 20},
			retries=2,
		)
		upstream["nodes"][0]["host"] = f"${{{host_env}}}"
		return upstream
	except gw.GatewayConfigError:
		return {
			"scheme": "http",
			"nodes": [{"host": f"${{{host_env}}}", "port": 8000, "weight": 1}],
			"pass_host": "rewrite",
			"upstream_host": site_name,
			"timeout": {"connect": 5, "send": 20, "read": 20},
			"retries": 2,
		}


def tier_overrides(internal_spec: dict[str, Any]) -> dict[tuple[str, str], str]:
	"""(method, public path) -> tier, from the `tier=` on each `@rest`.

	Read from the internal spec: the public one strips `x-gateway-tier` so the
	throttling decision stays out of the client contract.
	"""
	return {
		(method.upper(), gw.public_path(path)): op["x-gateway-tier"]
		for path, methods in internal_spec["paths"].items()
		for method, op in methods.items()
		if "x-gateway-tier" in op
	}


def write_gateway(
	*,
	app_name: str,
	internal_spec: dict[str, Any],
	public_spec: dict[str, Any],
	tiers: dict[str, dict[str, Any]],
	upstream_host_env: str,
	upstream_port_env: str,
	gateway_dir: Path,
	title: str,
	service_plugins: dict[str, Any] | None = None,
	extra_services: list[dict[str, Any]] | None = None,
	helm_values: dict[str, str] | None = None,
	helm_required: set[str] | None = None,
	helm_backends: dict[str, tuple[str, ...]] | None = None,
	helm_ints: set[str] | None = None,
	customize_document: Callable[[dict[str, Any]], None] | None = None,
	gateway_jwt: bool = False,
	with_auth_routes: bool = True,
	site_name: str = "${FRAPPE_SITE_NAME}",
) -> None:
	"""`adc.yaml` and the Helm templates of `app_name`, from the specs written above."""
	routes = gw.reconcile(gw.spec_routes(public_spec), tier_overrides(internal_spec))
	if with_auth_routes:
		# oan_auth_service's endpoints are served by the same bench.
		routes = gw.with_auth_routes(routes)

	doc = gw.build_document(
		routes,
		app=app_name,
		tiers={**tiers, **gw.AUTH_TIERS},
		api_upstream=api_upstream(upstream_host_env, upstream_port_env, site_name),
		service_plugins=service_plugins
		or gw.service_plugins(
			methods="GET,POST,PATCH,DELETE,OPTIONS",
			credentials=False,
			max_body_mb=15,
			cors_origins=gw.env("CORS_ORIGINS_REGEX", r"https?://localhost(:[0-9]+)?"),
		),
		extra_services=extra_services,
		consumers=[gw.jwt_issuer_consumer()] if gateway_jwt else None,
		gateway_jwt=gateway_jwt,
	)
	if customize_document:
		customize_document(doc)

	prefix = upstream_host_env.removesuffix("_HOST")
	provenance = [
		f"Source Spec: {public_spec['info']['title']} v{public_spec['info']['version']}",
		"Generated by oan_auth_service.openapi_generator -- do not hand-edit;",
		"change an endpoint's `@rest(tier=...)` or the app's TIERS and re-run.",
	]
	adc_path = gateway_dir / "adc.yaml"
	gw.write_document(doc, adc_path, [f"{title} ADC config (adc lint|validate|diff|sync)", *provenance])
	gw.write_helm_templates(
		doc,
		gateway_dir / "k8s" / "templates",
		[f"{title} APISIX Ingress Controller resources", *provenance],
		app=app_name,
		backends={
			f"{app_name}-service-v1": (
				f"${{{upstream_host_env}}}",
				"${WEB_PORT}",
				f"${{{prefix}_EXTERNAL_HOST}}",
			),
			**(helm_backends or {}),
		},
		values={
			upstream_host_env: ".Values.web.serviceName",
			f"{prefix}_EXTERNAL_HOST": ".Values.web.externalHosts",
			"FRAPPE_SITE_NAME": ".Values.siteName",
			"WEB_PORT": ".Values.web.port",
			**(helm_values or {}),
		},
		required={upstream_host_env, "FRAPPE_SITE_NAME", *(helm_required or ())},
		ints={"WEB_PORT", *(helm_ints or ())},
	)
	gw.report(adc_path, routes, doc, public_spec)


def generate_spec_and_gateway(
	*,
	app_name: str,
	module: str,
	title: str,
	description: str,
	upstream_host_env: str,
	tiers: dict[str, dict[str, Any]],
	openapi_dir: Path,
	gateway_dir: Path,
	servers: list[dict[str, str]],
	public_servers: list[dict[str, str]],
	upstream_port_env: str | None = None,
	modules: list[str] | None = None,
	gateway: bool = True,
	gateway_options: dict[str, Any] | None = None,
	**spec_options: Any,
) -> dict[str, Any]:
	"""Write the OpenAPI specs and the APISIX config of one app. Returns the internal spec.

	`module` is the app's Python package (`oan_grievance_service`): every module under
	it is imported, so every route it declares is found. `app_name` is the gateway name
	(`oan-grievance`). `spec_options` go to `build_openapi`, `gateway_options` to
	`write_gateway`; `modules` pins the import order; `gateway=False` writes the specs only. Run through `gw.cli` so a
	missing environment variable reads as a message, not a traceback.
	"""
	import_route_modules(module, modules)
	doc = build_openapi(
		app=module,
		title=title,
		description=description,
		servers=servers,
		**spec_options,
	)
	write_specs(doc, openapi_dir, public_servers, title=title)
	if gateway:
		public = gw.publicize_spec(strip_extensions(doc), public_servers)
		write_gateway(
			app_name=app_name,
			internal_spec=doc,
			public_spec=public,
			tiers=tiers,
			upstream_host_env=upstream_host_env,
			upstream_port_env=upstream_port_env or upstream_host_env.replace("_HOST", "_PORT"),
			gateway_dir=gateway_dir,
			title=title,
			**(gateway_options or {}),
		)
	return doc
