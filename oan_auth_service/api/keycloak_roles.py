"""Mirror a service role into Keycloak, so the role a user is granted there is the role Frappe knows.

A delegated login turns the token's client roles of a login option's `application` into Frappe roles of
the same name (see `iam_users.granted_roles`). The admin API creates and deletes the Frappe role; this
module creates and deletes the client role of that name in every Keycloak client a login option points at.

Configured in site_config.json, all required to turn the mirror on (without them it does nothing):

    "keycloak_admin_client_id": "oan-auth-admin",
    "keycloak_admin_client_secret": "...",
    "keycloak_admin_realm": "master"

The client is a Keycloak service account (client credentials) allowed to manage clients in the realms of
the login options. Realm and Keycloak URL come from each option's `issuer` (`https://<host>/realms/<realm>`).
"""

import frappe
import requests
from frappe import _

from oan_auth_service.api.iam_tokens import is_secure_url
from oan_auth_service.config import settings

TIMEOUT = 10


class KeycloakError(frappe.ValidationError):
	"""Keycloak could not be asked, or refused. A 502: the role was not created or deleted anywhere."""

	http_status_code = 502


def sync_role(role: str, delete: bool = False) -> list[str]:
	"""Create (or, with `delete`, remove) the client role `role` in each Keycloak client of the login options.

	Returns the `realm/client` pairs it touched. An existing role on create and a missing one on delete
	are fine, so a retry after a half-finished call is safe. Raises `KeycloakError` on any other answer.
	"""
	admin_id = frappe.conf.get("keycloak_admin_client_id")
	secret = frappe.conf.get("keycloak_admin_client_secret")
	if not (admin_id and secret):
		return []

	targets = {
		(s.issuer.rstrip("/"), s.application)
		for s in settings.iam_services()
		if s.application and s.issuer and "/realms/" in s.issuer
	}
	admin_realm = frappe.conf.get("keycloak_admin_realm") or "master"
	touched, tokens = [], {}
	for issuer, application in sorted(targets):
		base, realm = issuer.split("/realms/", 1)
		if not is_secure_url(base):
			raise KeycloakError(_("Keycloak URL {0} must be https.").format(base))
		try:
			if base not in tokens:
				r = requests.post(
					f"{base}/realms/{admin_realm}/protocol/openid-connect/token",
					data={"grant_type": "client_credentials", "client_id": admin_id, "client_secret": secret},
					timeout=TIMEOUT,
					allow_redirects=False,
				)
				if r.status_code != 200:
					raise KeycloakError(_("Keycloak refused the admin client ({0}).").format(r.status_code))
				tokens[base] = {"Authorization": f"Bearer {r.json()['access_token']}"}
			admin = f"{base}/admin/realms/{realm}/clients"
			found = requests.get(
				admin,
				params={"clientId": application},
				headers=tokens[base],
				timeout=TIMEOUT,
				allow_redirects=False,
			)
			if found.status_code != 200 or not found.json():
				raise KeycloakError(
					_("Keycloak client {0} not found in realm {1}.").format(application, realm)
				)
			roles = f"{admin}/{found.json()[0]['id']}/roles"
			if delete:
				r = requests.delete(
					f"{roles}/{role}", headers=tokens[base], timeout=TIMEOUT, allow_redirects=False
				)
				ok = (204, 404)
			else:
				r = requests.post(
					roles, json={"name": role}, headers=tokens[base], timeout=TIMEOUT, allow_redirects=False
				)
				ok = (201, 409)
		except (requests.RequestException, ValueError, KeyError) as exc:
			raise KeycloakError(_("Could not reach Keycloak: {0}").format(exc))
		if r.status_code not in ok:
			raise KeycloakError(_("Keycloak answered {0} for role {1}.").format(r.status_code, role))
		touched.append(f"{realm}/{application}")
	return touched
