"""Shared helpers for the test suite."""

import contextlib
from typing import get_args

import frappe
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError
from pydantic_core.core_schema import ErrorType


def generate_rsa_pem(bits: int = 2048) -> str:
	"""Return a fresh unencrypted PEM private key, in the form site_config holds."""
	key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
	return key.private_bytes(
		serialization.Encoding.PEM,
		serialization.PrivateFormat.PKCS8,
		serialization.NoEncryption(),
	).decode()


# Generated once per test run: RSA keygen is slow enough to matter per test, and
# no test depends on the specific key, only on which kid holds it.
TEST_PRIVATE_KEYS = {
	"v1": generate_rsa_pem(),
	"v2": generate_rsa_pem(),
}


@contextlib.contextmanager
def override_conf(**values):
	"""Temporarily set site_config keys, restoring exactly what was there.

	Restores by key rather than by replacing the whole dict: `frappe.local.conf`
	carries the real site's database credentials, and swapping the object out
	would strip them from any code that reads it while the block is open.
	"""
	conf = frappe.local.conf
	sentinel = object()
	previous = {key: conf.get(key, sentinel) for key in values}

	conf.update(values)
	try:
		yield
	finally:
		for key, old in previous.items():
			if old is sentinel:
				conf.pop(key, None)
			else:
				conf[key] = old


@contextlib.contextmanager
def configured_keys(current_kid="v1"):
	"""A site with usable JWT key material."""
	with override_conf(
		jwt_private_keys=dict(TEST_PRIVATE_KEYS), jwt_current_kid=current_kid, jwt_issuer="test-issuer"
	):
		yield


def make_user(email: str, password: str, roles: list[str] | None = None) -> str:
	"""Create (or reset) an enabled test user, and return its name."""
	if frappe.db.exists("User", email):
		frappe.delete_doc("User", email, force=True, ignore_permissions=True)

	user = frappe.get_doc(
		{
			"doctype": "User",
			"email": email,
			"first_name": email.split("@")[0],
			"send_welcome_email": 0,
			"enabled": 1,
			"new_password": password,
			"roles": [{"role": role} for role in (roles or [])],
		}
	)
	user.insert(ignore_permissions=True)
	frappe.db.commit()  # nosemgrep: frappe-manual-commit

	return user.name


def _drop_pending_owner_sweeps(email: str):
	"""Cancel queued `rewrite_owner_fields` jobs that name `email`.

	Renaming a User queues that job. Newer Frappe refuses to delete a user a
	queued job still names, and no worker runs in tests, so the job would
	otherwise block the cleanup. Older Frappe has no such job: nothing to drop.
	"""
	try:
		from frappe.utils.background_jobs import get_queue

		for job in get_queue("long").jobs:
			if job.kwargs.get("method") != "frappe.core.doctype.user.user.rewrite_owner_fields":
				continue
			if email in (job.kwargs.get("kwargs") or {}).values():
				job.delete()
	except Exception:
		pass


def cleanup_user(email: str):
	_drop_pending_owner_sweeps(email)
	if frappe.db.exists("User", email):
		frappe.db.delete("OAN User Refresh Token", {"user": email})
		frappe.delete_doc("User", email, force=True, ignore_permissions=True)
		frappe.db.commit()  # nosemgrep: frappe-manual-commit


def ensure_role(role: str):
	if not frappe.db.exists("Role", role):
		frappe.get_doc({"doctype": "Role", "role_name": role}).insert(ignore_permissions=True)
		frappe.db.commit()  # nosemgrep: frappe-manual-commit


def ensure_gender(gender: str):
	if not frappe.db.exists("Gender", gender):
		frappe.get_doc({"doctype": "Gender", "gender": gender}).insert(ignore_permissions=True)
		frappe.db.commit()  # nosemgrep: frappe-manual-commit


IAM_SERVICE_DOCTYPE = "OAN IAM Service"


def make_iam_service(key: str, default_roles=(), **fields) -> str:
	"""Create (or replace) an enabled `OAN IAM Service` row, committed, and return its name."""
	delete_iam_service(key)
	fields.pop("return_origins", None)
	doc = frappe.get_doc(
		{
			"doctype": IAM_SERVICE_DOCTYPE,
			"key": key,
			"label": fields.pop("label", f"Sign in with {key}"),
			"enabled": fields.pop("enabled", 1),
			**fields,
			"default_roles": [{"role": r} for r in default_roles],
		}
	)
	doc.insert(ignore_permissions=True)
	frappe.db.commit()  # nosemgrep: frappe-manual-commit
	return doc.name


def delete_iam_service(key: str) -> None:
	from oan_auth_service.config import settings

	if frappe.db.exists(IAM_SERVICE_DOCTYPE, key):
		frappe.delete_doc(IAM_SERVICE_DOCTYPE, key, force=True, ignore_permissions=True)
		frappe.db.commit()  # nosemgrep: frappe-manual-commit
	settings.clear_iam_services_cache()


def clear_rate_limits():
	"""Forget every rate-limit counter. They live in Redis and outlive a test run, so a test
	that calls a limited endpoint clears them before and after, or a rerun inside the window
	would be refused."""
	frappe.cache.delete_keys("oan_auth:")


def request_schemas(*modules) -> list[type]:
	"""The request schemas of every `validate_request` endpoint in `modules`, once each."""
	found = {}
	for module in modules:
		for value in vars(module).values():
			schema = getattr(value, "__pydantic_schema__", None)
			if schema is not None:
				found[schema] = None
	return list(found)


# One value of each shape, to make every field of a schema fail in the ways its type can.
_PROBES = (None, True, 7, 1.5, "", "x" * 10_000, "not-a-date", [], ["a"], {}, {"a": 1})


def raw_message_leaks(schemas, has_wording) -> list[str]:
	"""Errors the schemas can raise whose text would reach a client as pydantic's own.

	Each field of each schema is given one value of every shape in turn. An error is a leak
	when it is one of pydantic's built-in types and `has_wording(type)` is false; a
	validator's own message (a custom error type) is not. Only each schema's top-level
	fields are probed, not the fields of the models nested inside them.
	"""
	builtin = set(get_args(ErrorType))
	leaks = set()
	for schema in schemas:
		payloads = [{}] + [{name: value} for name in schema.model_fields for value in _PROBES]
		for payload in payloads:
			try:
				schema(**payload)
			except ValidationError as error:
				for line in error.errors():
					if line["type"] in builtin and not has_wording(line["type"]):
						leaks.add(f"{schema.__name__}.{'.'.join(map(str, line['loc']))}: {line['type']}")
			except Exception:
				pass  # a schema validator that cannot take this probe is not a message leak
	return sorted(leaks)
