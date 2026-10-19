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
		ensure_role("Svc Customer")
		ensure_role("Svc Staff")
		self.admin = make_user(
			"oan_admin_api@example.com", "AdminPass123!", roles=["System Manager", "Svc Customer"]
		)
		self.admin_only = make_user(
			"oan_adminonly_api@example.com", "AdminPass123!", roles=["System Manager"]
		)
		self.plain = make_user("oan_plain_api@example.com", "PlainPass123!", roles=["Svc Customer"])
		self.created = []
		# A consuming app on the test site may hook the default registration role and
		# demand extra fields; these tests only exercise the auth service.
		self._conf = override_conf(jwt_default_registration_role=None, service_prefix="Svc")
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
		cleanup_user(self.admin_only)

	def _create(self, **data) -> dict:
		data.setdefault("roles", ["Svc Customer"])
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
		data = self._create(email=email, roles=["Svc Customer"])

		self.assertTrue(data["user"].endswith("@id.openagrinet.internal"))
		self.assertEqual(data["login_email"], email)
		self.assertEqual(data["roles"], ["Svc Customer"])
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
		self.assertEqual(status, 400)
		self.assertFalse(frappe.db.exists("User", {LOGIN_EMAIL_FIELD: "escalate@example.com"}))

	def test_ambient_role_is_refused(self):
		status, _body = call(
			"/api/v1/admin/users", "POST", {"full_name": "X", "email": "x1@example.com", "roles": ["Guest"]}
		)
		self.assertEqual(status, 400)

	def test_list_filters_and_paginates(self):
		email = f"listme_{frappe.generate_hash(length=6)}@example.com"
		data = self._create(email=email, roles=["Svc Customer"])

		status, body = call("/api/v1/admin/users", "GET", {"search": email})
		self.assertEqual(status, 200)
		self.assertEqual([u["user"] for u in body["data"]], [data["user"]])
		self.assertEqual(body["pagination"]["total_count"], 1)

		status, body = call("/api/v1/admin/users", "GET", {"search": email, "role": "Svc Staff"})
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

	def test_patch_cannot_clear_both_email_and_phone(self):
		data = self._create(
			email=f"both_{frappe.generate_hash(length=6)}@example.com", phone_number="+251911223344"
		)
		url = f"/api/v1/admin/users/{data['user']}"
		status, _body = call(url, "PATCH", {"email": None, "phone_number": None})
		self.assertEqual(status, 400)
		status, body = call(url, "PATCH", {"email": None})
		self.assertEqual(status, 200, body)

	def test_search_treats_wildcards_literally(self):
		data = self._create(email=f"wild_{frappe.generate_hash(length=6)}@example.com")
		status, body = call("/api/v1/admin/users", "GET", {"search": "%"})
		self.assertEqual(status, 200, body)
		self.assertNotIn(data["user"], [u["user"] for u in body["data"]])

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

		status, _body = call(f"/api/v1/admin/users/{self.admin}", "PATCH", {"enabled": False})
		self.assertEqual(status, 403)
		# Administrator holds no service role, so is out of scope.
		status, _body = call("/api/v1/admin/users/Administrator", "PATCH", {"enabled": False})
		self.assertEqual(status, 404)

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

		status, body = call(f"/api/v1/admin/users/{data['user']}/roles", "POST", {"roles": ["Svc Customer"]})
		self.assertEqual(status, 200, body)
		self.assertIn("Svc Customer", body["data"]["roles"])

		status, body = call(f"/api/v1/admin/users/{data['user']}/roles")
		self.assertEqual(body["data"]["roles"], ["Svc Customer"])

		status, body = call(f"/api/v1/admin/users/{data['user']}/roles/Svc%20Customer", "DELETE")
		self.assertEqual(status, 200, body)
		self.assertNotIn("Svc Customer", body["data"]["roles"])

		status, _body = call(f"/api/v1/admin/users/{self.admin}/roles/System%20Manager", "DELETE")
		self.assertEqual(status, 403)

	def test_reissue_temporary_password(self):
		data = self._create(email=f"tmp_{frappe.generate_hash(length=6)}@example.com")
		frappe.db.set_value("User", data["user"], MUST_CHANGE_PASSWORD_FIELD, 0)

		status, body = call(f"/api/v1/admin/users/{data['user']}/temporary-password", "POST")
		self.assertEqual(status, 200, body)
		self.assertTrue(body["data"]["temporary_password"])
		self.assertTrue(frappe.db.get_value("User", data["user"], MUST_CHANGE_PASSWORD_FIELD))

	def _make_privileged(self, label: str, role: str) -> str:
		ensure_role(role)
		user = make_user(f"oan_{label}_api@example.com", "PrivPass123!", roles=[role, "Svc Customer"])
		self.addCleanup(cleanup_user, user)
		return user

	def test_out_of_scope_users_are_hidden(self):
		for target in ("Administrator", self.admin_only):
			status, _body = call(f"/api/v1/admin/users/{quote(target)}")
			self.assertEqual(status, 404, target)
		status, body = call("/api/v1/admin/users", "GET", {"search": "oan_adminonly"})
		self.assertEqual(body["data"], [])

	def test_role_outside_service_is_refused(self):
		data = self._create(email=f"scope_{frappe.generate_hash(length=6)}@example.com")
		status, _body = call(
			f"/api/v1/admin/users/{data['user']}/roles", "POST", {"roles": ["System Manager"]}
		)
		self.assertEqual(status, 400)
		status, _body = call(f"/api/v1/admin/users/{data['user']}/roles/System%20Manager", "DELETE")
		self.assertEqual(status, 403)

	def test_system_manager_cannot_modify_administrator_accounts(self):
		holder = self._make_privileged("holder_admin", "Administrator")
		for target in (holder,):
			base = f"/api/v1/admin/users/{quote(target)}"
			attempts = [
				(base, "PATCH", {"phone_number": "+251911000111"}),
				(base, "PATCH", {"email": "takeover@example.com"}),
				(f"{base}/temporary-password", "POST", None),
				(f"{base}/sessions", "DELETE", None),
				(f"{base}/roles", "POST", {"roles": ["Svc Customer"]}),
				(f"{base}/roles/System%20Manager", "DELETE", None),
			]
			for path, method, data in attempts:
				status, _body = call(path, method, data)
				self.assertEqual(status, 403, (target, method, path))
		self.assertFalse(frappe.db.exists("User", {LOGIN_EMAIL_FIELD: "takeover@example.com"}))

	def test_system_manager_can_modify_peer_system_manager(self):
		peer = self._make_privileged("peer_sm", "System Manager")
		status, body = call(f"/api/v1/admin/users/{quote(peer)}/temporary-password", "POST")
		self.assertEqual(status, 200, body)

	def test_administrator_can_modify_privileged_accounts(self):
		peer = self._make_privileged("peer_sm2", "System Manager")
		frappe.set_user("Administrator")
		status, body = call(f"/api/v1/admin/users/{quote(peer)}/temporary-password", "POST")
		self.assertEqual(status, 200, body)

	def _reset_note_permissions(self):
		"""Editing "Notification Log" copies its standard rules into Custom DocPerm; undo that."""
		frappe.db.delete("Custom DocPerm", {"parent": "Notification Log"})
		frappe.clear_cache(doctype="Notification Log")
		frappe.db.commit()  # nosemgrep: frappe-manual-commit

	def test_permissions_scoped_to_service_prefix(self):
		# "Notification Log" is a core doctype, so it stands in for a service doctype.
		ensure_role("Notification Perm Role")
		self.addCleanup(self._reset_note_permissions)
		with override_conf(service_prefix="Notification"):
			status, body = call(
				"/api/v1/admin/permissions",
				"PUT",
				{
					"role": "Notification Perm Role",
					"doctype": "Notification Log",
					"permissions": {"read": True, "write": True},
				},
			)
			self.assertEqual(status, 200, body)
			row = next(r for r in body["data"] if r["role"] == "Notification Perm Role")
			self.assertEqual((row["read"], row["write"], row["create"]), (1, 1, 0))

			status, body = call("/api/v1/admin/permissions", "GET", {"role": "Notification Perm Role"})
			self.assertEqual(status, 200, body)
			self.assertTrue(all(r["doctype"].startswith("Notification") for r in body["data"]))

			status, body = call(
				"/api/v1/admin/permissions",
				"DELETE",
				{"role": "Notification Perm Role", "doctype": "Notification Log"},
			)
			self.assertEqual(status, 200, body)
			self.assertFalse([r for r in body["data"] if r["role"] == "Notification Perm Role"])

			for data in (
				{"role": "System Manager", "doctype": "Notification Log", "permissions": {"read": True}},
				{"role": "Notification Perm Role", "doctype": "User", "permissions": {"read": True}},
			):
				status, _body = call("/api/v1/admin/permissions", "PUT", data)
				self.assertEqual(status, 403, data)

	def test_prefix_from_hook(self):
		from unittest.mock import patch

		real = frappe.get_hooks

		def fake(name=None, *a, **kw):
			return ["Svc"] if name == "oan_service_prefix" else real(name, *a, **kw)

		with override_conf(service_prefix=None), patch("frappe.get_hooks", fake):
			status, body = call("/api/v1/admin/roles")
		self.assertEqual(status, 200, body)
		self.assertTrue(all(r["name"].startswith("Svc") for r in body["data"]))

	def test_permissions_show_source_and_reset(self):
		ensure_role("Notification Reset Role")
		self._reset_note_permissions()
		self.addCleanup(self._reset_note_permissions)
		with override_conf(service_prefix="Notification"):
			url = "/api/v1/admin/permissions"
			status, body = call(url, "GET", {"doctype": "Notification Log"})
			self.assertEqual(status, 200, body)
			self.assertTrue(all(r["source"] == "standard" for r in body["data"]))
			self.assertFalse(any(r["differs_from_standard"] for r in body["data"]))

			status, body = call(
				url,
				"PUT",
				{
					"role": "Notification Reset Role",
					"doctype": "Notification Log",
					"permissions": {"read": True},
				},
			)
			self.assertEqual(status, 200, body)
			row = body["data"][0]
			self.assertEqual((row["source"], row["differs_from_standard"]), ("custom", True))

			from oan_auth_service.api.permission_rules import drifted_rules

			self.assertEqual(
				[r["role"] for r in drifted_rules("Notification Log")], ["Notification Reset Role"]
			)

			status, body = call(f"{url}/reset", "POST", {"doctype": "Notification Log"})
			self.assertEqual(status, 200, body)
			self.assertGreater(body["data"]["removed_rules"], 0)
			self.assertFalse(frappe.db.exists("Custom DocPerm", {"parent": "Notification Log"}))
			self.assertEqual(drifted_rules("Notification Log"), [])

			status, _body = call(f"{url}/reset", "POST", {"doctype": "User"})
			self.assertEqual(status, 403)

	def test_custom_docperm_tracking_is_enabled_once(self):
		# Frappe skips Version records under tests (`ignore_version = frappe.in_test`), so
		# this checks the setting that makes edits versioned, not a Version row.
		from oan_auth_service.setup.install import enable_custom_docperm_tracking

		enable_custom_docperm_tracking()
		enable_custom_docperm_tracking()
		self.assertEqual(frappe.get_meta("Custom DocPerm").track_changes, 1)
		self.assertEqual(
			frappe.db.count("Property Setter", {"doc_type": "Custom DocPerm", "property": "track_changes"}), 1
		)

	def test_permissions_refuse_if_owner(self):
		ensure_role("Notification Owner Role")
		self._reset_note_permissions()
		self.addCleanup(self._reset_note_permissions)
		with override_conf(service_prefix="Notification"):
			base = {"role": "Notification Owner Role", "doctype": "Notification Log"}
			for method, data in (
				("PUT", {**base, "permissions": {"write": True}, "if_owner": True}),
				("DELETE", {**base, "if_owner": True}),
			):
				status, _body = call("/api/v1/admin/permissions", method, data)
				self.assertEqual(status, 400, method)
			self.assertFalse(
				frappe.db.exists(
					"Custom DocPerm", {"parent": "Notification Log", "role": "Notification Owner Role"}
				)
			)

	def test_prefix_needs_a_word_boundary(self):
		ensure_role("Svcfoo Role")
		with override_conf(service_prefix="Svc"):
			status, body = call("/api/v1/admin/roles")
		self.assertEqual(status, 200, body)
		names = {r["name"] for r in body["data"]}
		self.assertIn("Svc Customer", names)
		self.assertNotIn("Svcfoo Role", names)

	def test_permissions_need_service_prefix(self):
		with override_conf(service_prefix=""):
			status, _body = call("/api/v1/admin/permissions")
		self.assertEqual(status, 400)

	def test_list_roles_only_service_roles(self):
		ensure_role("Notification Listed Role")
		with override_conf(service_prefix="Notification"):
			status, body = call("/api/v1/admin/roles")
		self.assertEqual(status, 200)
		names = {r["name"] for r in body["data"]}
		self.assertIn("Notification Listed Role", names)
		self.assertTrue(all(n.startswith("Notification") for n in names))
