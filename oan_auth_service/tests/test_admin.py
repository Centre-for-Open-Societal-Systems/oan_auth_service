"""Tests for the admin user and role management endpoints under /api/v1/admin."""

import json
import unittest
from urllib.parse import quote

import frappe

from oan_auth_service.api.router import ensure_routes_registered
from oan_auth_service.api.v1.auth import LOGIN_EMAIL_FIELD, MUST_CHANGE_PASSWORD_FIELD, REFRESH_TOKEN_DOCTYPE
from oan_auth_service.tests.test_router import make_test_request
from oan_auth_service.tests.utils import cleanup_user, ensure_role, make_user, override_conf


def call(path: str, method: str = "GET", data: dict | None = None) -> tuple[int, dict]:
	import frappe.api

	res = frappe.api.handle(make_test_request(path, method=method, data=data))
	return res.status_code, json.loads(res.get_data(as_text=True))


class TestAdminEndpoints(unittest.TestCase):
	def setUp(self):
		ensure_routes_registered()
		ensure_role("System Manager")
		ensure_role("Customer")
		self.admin = make_user("oan_admin_api@example.com", "AdminPass123!", roles=["System Manager"])
		self.plain = make_user("oan_plain_api@example.com", "PlainPass123!", roles=["Customer"])
		self.created = []
		# A consuming app on the test site may hook the default registration role and
		# demand extra fields; these tests only exercise the auth service.
		self._conf = override_conf(jwt_default_registration_role=None)
		self._conf.__enter__()
		frappe.set_user(self.admin)

	def tearDown(self):
		self._conf.__exit__(None, None, None)
		frappe.set_user("Administrator")
		for user in self.created:
			if frappe.db.exists("User", user):
				frappe.db.delete(REFRESH_TOKEN_DOCTYPE, {"user": user})
				for c in frappe.get_all("Contact", filters={"user": user}, pluck="name"):
					frappe.delete_doc("Contact", c, force=True, ignore_permissions=True)
				frappe.delete_doc("User", user, force=True, ignore_permissions=True)
		cleanup_user(self.admin)
		cleanup_user(self.plain)

	def _create(self, **data) -> dict:
		status, body = call("/api/v1/admin/users", "POST", {"full_name": "Admin Made", **data})
		self.assertEqual(status, 201, body)
		self.created.append(body["data"]["user"])
		return body["data"]

	def test_non_admin_is_refused(self):
		frappe.set_user(self.plain)
		status, body = call("/api/v1/admin/users")
		self.assertEqual(status, 403)
		self.assertEqual(body["code"], "PERMISSION_DENIED")

	def test_create_issues_temporary_password_and_no_tokens(self):
		email = f"admin_made_{frappe.generate_hash(length=6)}@example.com"
		data = self._create(email=email, roles=["Customer"])

		self.assertTrue(data["user"].endswith("@id.openagrinet.internal"))
		self.assertEqual(data["login_email"], email)
		self.assertEqual(data["roles"], ["Customer"])
		self.assertTrue(data["must_change_password"])
		self.assertTrue(data["temporary_password"])
		self.assertNotIn("access_token", data)
		self.assertTrue(frappe.db.exists("Contact", {"user": data["user"]}))

	def test_create_with_chosen_password_does_not_echo_it(self):
		data = self._create(
			email=f"admin_made_{frappe.generate_hash(length=6)}@example.com", temporary_password="Temp12345"
		)
		self.assertNotIn("temporary_password", data)
		self.assertTrue(frappe.db.get_value("User", data["user"], MUST_CHANGE_PASSWORD_FIELD))

	def test_create_requires_email_or_phone(self):
		status, _body = call("/api/v1/admin/users", "POST", {"full_name": "Nobody"})
		self.assertEqual(status, 400)

	def test_system_manager_cannot_grant_administrator(self):
		status, _body = call(
			"/api/v1/admin/users",
			"POST",
			{"full_name": "Escalate", "email": "escalate@example.com", "roles": ["Administrator"]},
		)
		self.assertEqual(status, 403)
		self.assertFalse(frappe.db.exists("User", {LOGIN_EMAIL_FIELD: "escalate@example.com"}))

	def test_ambient_role_is_refused(self):
		status, _body = call(
			"/api/v1/admin/users", "POST", {"full_name": "X", "email": "x1@example.com", "roles": ["Guest"]}
		)
		self.assertEqual(status, 400)

	def test_list_filters_and_paginates(self):
		email = f"listme_{frappe.generate_hash(length=6)}@example.com"
		data = self._create(email=email, roles=["Customer"])

		status, body = call("/api/v1/admin/users", "GET", {"search": email})
		self.assertEqual(status, 200)
		self.assertEqual([u["user"] for u in body["data"]], [data["user"]])
		self.assertEqual(body["pagination"]["total_count"], 1)

		status, body = call("/api/v1/admin/users", "GET", {"search": email, "role": "System Manager"})
		self.assertEqual(body["data"], [])

	def test_get_by_id_and_lookup_by_email_filter(self):
		email = f"getme_{frappe.generate_hash(length=6)}@example.com"
		data = self._create(email=email)

		status, body = call(f"/api/v1/admin/users/{quote(data['user'])}")
		self.assertEqual(status, 200, body)
		self.assertEqual(body["data"]["user"], data["user"])

		# Handles are not accepted in the path, only as list filters.
		status, _body = call(f"/api/v1/admin/users/{quote(email)}")
		self.assertEqual(status, 404)

		status, body = call("/api/v1/admin/users", "GET", {"email": email.upper()})
		self.assertEqual([u["user"] for u in body["data"]], [data["user"]])

	def test_create_sets_location_header(self):
		data = self._create(email=f"loc_{frappe.generate_hash(length=6)}@example.com")
		self.assertEqual(frappe.local.response_headers.get("Location"), f"/api/v1/admin/users/{data['user']}")

	def test_patch_updates_profile_and_contact(self):
		data = self._create(email=f"patch_{frappe.generate_hash(length=6)}@example.com")
		new_email = f"patched_{frappe.generate_hash(length=6)}@example.com"

		status, body = call(
			f"/api/v1/admin/users/{data['user']}",
			"PATCH",
			{"first_name": "Renamed", "email": new_email, "phone_number": "+251911223399"},
		)
		self.assertEqual(status, 200, body)
		self.assertEqual(body["data"]["first_name"], "Renamed")
		self.assertEqual(body["data"]["last_name"], "Made")
		self.assertEqual(body["data"]["login_email"], new_email)
		self.assertEqual(body["data"]["mobile_no"], "+251911223399")

		contact = frappe.get_doc("Contact", {"user": data["user"]})
		self.assertEqual(contact.first_name, "Renamed")
		self.assertEqual([e.email_id for e in contact.email_ids], [new_email])
		self.assertEqual([p.phone for p in contact.phone_nos], ["+251911223399"])

	def test_patch_rejects_email_held_by_another_user(self):
		a = self._create(email=f"a_{frappe.generate_hash(length=6)}@example.com")
		b = self._create(email=f"b_{frappe.generate_hash(length=6)}@example.com")
		status, _body = call(f"/api/v1/admin/users/{b['user']}", "PATCH", {"email": a["login_email"]})
		self.assertEqual(status, 400)

	def _add_refresh_token(self, user: str):
		frappe.get_doc(
			{
				"doctype": REFRESH_TOKEN_DOCTYPE,
				"user": user,
				"token_hash": frappe.generate_hash(),
				"expires_at": frappe.utils.add_days(frappe.utils.now_datetime(), 1),
			}
		).insert(ignore_permissions=True)

	def test_disable_via_patch_revokes_tokens_and_guards_self(self):
		data = self._create(email=f"del_{frappe.generate_hash(length=6)}@example.com")
		self._add_refresh_token(data["user"])

		status, body = call(f"/api/v1/admin/users/{data['user']}", "PATCH", {"enabled": False})
		self.assertEqual(status, 200, body)
		self.assertFalse(body["data"]["enabled"])
		self.assertFalse(frappe.db.exists(REFRESH_TOKEN_DOCTYPE, {"user": data["user"]}))

		for protected in (self.admin, "Administrator"):
			status, _body = call(f"/api/v1/admin/users/{protected}", "PATCH", {"enabled": False})
			self.assertEqual(status, 403)

	def test_no_delete_on_user(self):
		from oan_auth_service.tests.test_router import registered_routes

		methods = {
			m
			for r in registered_routes()
			if r["path"] == "/api/v1/admin/users/<user_id>"
			for m in r["methods"]
		}
		self.assertEqual(methods, {"GET", "PATCH"})

	def test_delete_sessions(self):
		data = self._create(email=f"sess_{frappe.generate_hash(length=6)}@example.com")
		self._add_refresh_token(data["user"])

		status, body = call(f"/api/v1/admin/users/{data['user']}/sessions", "DELETE")
		self.assertEqual(status, 200, body)
		self.assertEqual(body["data"]["revoked_sessions"], 1)
		self.assertFalse(frappe.db.exists(REFRESH_TOKEN_DOCTYPE, {"user": data["user"]}))

	def test_grant_and_revoke_role(self):
		data = self._create(email=f"roles_{frappe.generate_hash(length=6)}@example.com")

		status, body = call(f"/api/v1/admin/users/{data['user']}/roles", "POST", {"roles": ["Customer"]})
		self.assertEqual(status, 200, body)
		self.assertIn("Customer", body["data"]["roles"])

		status, body = call(f"/api/v1/admin/users/{data['user']}/roles")
		self.assertEqual(body["data"]["roles"], ["Customer"])

		status, body = call(f"/api/v1/admin/users/{data['user']}/roles/Customer", "DELETE")
		self.assertEqual(status, 200, body)
		self.assertNotIn("Customer", body["data"]["roles"])

		status, _body = call(f"/api/v1/admin/users/{self.admin}/roles/System%20Manager", "DELETE")
		self.assertEqual(status, 403)

	def test_reissue_temporary_password(self):
		data = self._create(email=f"tmp_{frappe.generate_hash(length=6)}@example.com")
		frappe.db.set_value("User", data["user"], MUST_CHANGE_PASSWORD_FIELD, 0)

		status, body = call(f"/api/v1/admin/users/{data['user']}/temporary-password", "POST")
		self.assertEqual(status, 200, body)
		self.assertTrue(body["data"]["temporary_password"])
		self.assertTrue(frappe.db.get_value("User", data["user"], MUST_CHANGE_PASSWORD_FIELD))

	def test_list_roles_hides_ambient(self):
		status, body = call("/api/v1/admin/roles")
		self.assertEqual(status, 200)
		names = {r["name"] for r in body["data"]}
		self.assertIn("System Manager", names)
		self.assertFalse(names & {"All", "Guest", "Desk User"})
