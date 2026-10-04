"""Shared helpers for the test suite."""

import contextlib

import frappe
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


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


def cleanup_user(email: str):
	if frappe.db.exists("User", email):
		frappe.db.delete("OAN User Refresh Token", {"user": email})
		frappe.delete_doc("User", email, force=True, ignore_permissions=True)
		frappe.db.commit()  # nosemgrep: frappe-manual-commit


def ensure_role(role: str):
	if not frappe.db.exists("Role", role):
		frappe.get_doc({"doctype": "Role", "role_name": role}).insert(ignore_permissions=True)
		frappe.db.commit()  # nosemgrep: frappe-manual-commit
