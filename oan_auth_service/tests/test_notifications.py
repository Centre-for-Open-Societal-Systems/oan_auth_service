"""Tests for the notification endpoints under /api/v1/notifications."""

import json
import unittest

import frappe

from oan_auth_service.api.router import ensure_routes_registered
from oan_auth_service.api.v1.notifications import notify_users
from oan_auth_service.tests.test_router import make_test_request
from oan_auth_service.tests.utils import ensure_role, make_user

BASE = "/api/v1/notifications"


def call(path: str, method: str = "GET", data: dict | None = None) -> tuple[int, dict]:
	import frappe.api

	res = frappe.api.handle(make_test_request(path, method=method, data=data))
	return res.status_code, json.loads(res.get_data(as_text=True))


class TestNotificationEndpoints(unittest.TestCase):
	def setUp(self):
		ensure_routes_registered()
		ensure_role("System Manager")
		ensure_role("Customer")
		self.admin = make_user("oan_notif_admin@example.com", "AdminPass123!", roles=["System Manager"])
		self.alice = make_user("oan_notif_alice@example.com", "AlicePass123!", roles=["Customer"])
		self.bob = make_user("oan_notif_bob@example.com", "BobPass123!", roles=["Customer"])
		frappe.set_user(self.admin)
		self.ids = {}
		for user in (self.alice, self.bob):
			notify_users([user], f"Hello {user}")
			notify_users([user], f"Second {user}")
			self.ids[user] = frappe.get_all(
				"Notification Log", filters={"for_user": user}, pluck="name", order_by="creation asc"
			)
		# A 4xx rolls the transaction back, which would drop uncommitted fixtures.
		frappe.db.commit()  # nosemgrep: frappe-manual-commit

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.delete("Notification Log", {"for_user": ["in", [self.admin, self.alice, self.bob]]})
		for user in (self.admin, self.alice, self.bob):
			if frappe.db.exists("User", user):
				frappe.delete_doc("User", user, force=True, ignore_permissions=True)
		frappe.db.commit()  # nosemgrep: frappe-manual-commit

	def test_bulk_ids_are_capped(self):
		frappe.set_user(self.alice)
		ids = [f"n{i}" for i in range(501)]
		for method in ("PATCH", "DELETE"):
			status, _body = call(BASE, method, {"ids": ids})
			self.assertEqual(status, 400, method)

	def test_list_scoped_to_caller_with_unread_count(self):
		frappe.set_user(self.alice)
		status, body = call(BASE)
		self.assertEqual(status, 200)
		self.assertEqual(body["data"]["unread_count"], 2)
		self.assertEqual(len(body["data"]["notifications"]), 2)
		self.assertEqual(body["pagination"]["total_count"], 2)

	def test_list_filters_by_status(self):
		frappe.set_user(self.alice)
		call(f"{BASE}/{self.ids[self.alice][0]}", "PATCH", {"read": True})
		_, unread = call(BASE, "GET", {"status": "unread"})
		_, read = call(BASE, "GET", {"status": "read"})
		self.assertEqual(len(unread["data"]["notifications"]), 1)
		self.assertEqual(len(read["data"]["notifications"]), 1)
		self.assertEqual(unread["data"]["unread_count"], 1)

	def test_get_own_and_not_other(self):
		frappe.set_user(self.alice)
		status, body = call(f"{BASE}/{self.ids[self.alice][0]}")
		self.assertEqual(status, 200)
		self.assertFalse(body["data"]["read"])
		status, _ = call(f"{BASE}/{self.ids[self.bob][0]}")
		self.assertEqual(status, 404)

	def test_patch_one_marks_read_and_unread(self):
		frappe.set_user(self.alice)
		nid = self.ids[self.alice][0]
		_, body = call(f"{BASE}/{nid}", "PATCH", {"read": True})
		self.assertTrue(body["data"]["read"])
		_, body = call(f"{BASE}/{nid}", "PATCH", {"read": False})
		self.assertFalse(body["data"]["read"])

	def test_patch_other_users_notification_is_404(self):
		frappe.set_user(self.alice)
		status, _ = call(f"{BASE}/{self.ids[self.bob][0]}", "PATCH", {"read": True})
		self.assertEqual(status, 404)
		self.assertEqual(frappe.db.get_value("Notification Log", self.ids[self.bob][0], "read"), 0)

	def test_bulk_patch_all_touches_only_caller(self):
		frappe.set_user(self.alice)
		status, body = call(BASE, "PATCH", {"all": True})
		self.assertEqual(status, 200)
		self.assertEqual(body["data"]["updated"], 2)
		self.assertEqual(frappe.db.count("Notification Log", {"for_user": self.bob, "read": 0}), 2)

	def test_bulk_requires_ids_or_all(self):
		frappe.set_user(self.alice)
		self.assertEqual(call(BASE, "PATCH", {})[0], 400)
		self.assertEqual(call(BASE, "DELETE", {})[0], 400)
		self.assertEqual(call(BASE, "DELETE", {"ids": [self.ids[self.alice][0]], "all": True})[0], 400)

	def test_bulk_delete_ids_ignores_other_users(self):
		frappe.set_user(self.alice)
		ids = [self.ids[self.alice][0], self.ids[self.bob][0]]
		_, body = call(BASE, "DELETE", {"ids": ids})
		self.assertEqual(body["data"]["deleted"], 1)
		self.assertTrue(frappe.db.exists("Notification Log", self.ids[self.bob][0]))

	def test_delete_one(self):
		frappe.set_user(self.alice)
		nid = self.ids[self.alice][0]
		self.assertEqual(call(f"{BASE}/{nid}", "DELETE")[0], 200)
		self.assertEqual(call(f"{BASE}/{nid}")[0], 404)

	def test_notify_users_skips_actor(self):
		before = frappe.db.count("Notification Log", {"for_user": self.admin})
		notify_users([self.admin], "self")
		self.assertEqual(frappe.db.count("Notification Log", {"for_user": self.admin}), before)
