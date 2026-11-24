"""Mirror a service role into Keycloak, so the role a user is granted there is the role Frappe knows.

A delegated login turns the token's client roles of a login option's `application` into Frappe roles of
the same name (see `iam_users.granted_roles`). The admin API creates and deletes the Frappe role; this
module creates and deletes the client role of that name in the Keycloak client of every login option.

Each login option (`OAN IAM Service`, one per realm) carries its own `admin_client_id` and
`admin_client_secret` (a Password field, encrypted at rest): a service-account client of the option's own
realm, allowed to manage clients there. An option without them is skipped. Realm and Keycloak URL come
from the option's `issuer` (`https://<host>/realms/<realm>`).
"""

import frappe
import requests
from frappe import _
from frappe.utils.password import get_decrypted_password

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
	touched = []
	for service in settings.iam_services():
		if not (service.application and service.admin_client_id and "/realms/" in (service.issuer or "")):
			continue
		secret = get_decrypted_password(
			"OAN IAM Service", service.key, "admin_client_secret", raise_exception=False
		)
		if not secret:
			continue
		issuer = service.issuer.rstrip("/")
		base, realm = issuer.split("/realms/", 1)
		if not is_secure_url(base):
			raise KeycloakError(_("Keycloak URL {0} must be https.").format(base))
		application = service.application
		try:
			r = requests.post(
				f"{issuer}/protocol/openid-connect/token",
				data={
					"grant_type": "client_credentials",
					"client_id": service.admin_client_id,
					"client_secret": secret,
				},
				timeout=TIMEOUT,
				allow_redirects=False,
			)
			if r.status_code != 200:
				raise KeycloakError(_("Keycloak refused the admin client ({0}).").format(r.status_code))
			headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
			clients = f"{base}/admin/realms/{realm}/clients"
			found = requests.get(
				clients,
				params={"clientId": application},
				headers=headers,
				timeout=TIMEOUT,
				allow_redirects=False,
			)
			if found.status_code != 200 or not found.json():
				raise KeycloakError(
					_("Keycloak client {0} not found in realm {1}.").format(application, realm)
				)
			roles = f"{clients}/{found.json()[0]['id']}/roles"
			if delete:
				r = requests.delete(
					f"{roles}/{role}", headers=headers, timeout=TIMEOUT, allow_redirects=False
				)
				ok = (204, 404)
			else:
				r = requests.post(
					roles, json={"name": role}, headers=headers, timeout=TIMEOUT, allow_redirects=False
				)
				ok = (201, 409)
		except (requests.RequestException, ValueError, KeyError) as exc:
			raise KeycloakError(_("Could not reach Keycloak: {0}").format(str(exc)))
		if r.status_code not in ok:
			raise KeycloakError(_("Keycloak answered {0} for role {1}.").format(r.status_code, role))
		touched.append(f"{realm}/{application}")
	return touched
