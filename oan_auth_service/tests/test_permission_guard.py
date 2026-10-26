# Copyright (c) 2026, COSS - Centre for Open Societal Systems and contributors
# For license information, please see license.txt

"""Tests for the require_permission endpoint guard decorator in oan_auth_service.api.utils."""

import json
import unittest
from unittest.mock import patch

import frappe
import frappe.api

from oan_auth_service.api.router import _rules, ensure_routes_registered, rest
from oan_auth_service.api.utils import handle_api_errors, require_permission
from oan_auth_service.tests.test_router import make_test_request
from oan_auth_service.tests.utils import cleanup_user, ensure_role, make_user


class TestRequirePermissionGuard(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		ensure_routes_registered()
		ensure_role("Customer")
		ensure_role("System Manager")

	def setUp(self):
		self.users = []
		frappe.set_user("Administrator")

	def tearDown(self):
		frappe.set_user("Administrator")
		for user in self.users:
			cleanup_user(user)

	def _make_test_user(self, roles=None) -> str:
		email = f"perm_test_{frappe.generate_hash(length=8)}@example.com"
		user = make_user(email, "TestPassword123!", roles=roles or [])
		self.users.append(user)
		return user

	def test_wraps_preserves_function_metadata(self):
		"""require_permission preserves function __name__, __doc__, and annotations."""

		@require_permission("User", "read")
		def sample_fn(x: int) -> int:
			"""Sample docstring."""
			return x * 2

		self.assertEqual(sample_fn.__name__, "sample_fn")
		self.assertEqual(sample_fn.__doc__, "Sample docstring.")

	def test_delegates_to_frappe_has_permission_with_throw_true(self):
		"""Decorator forwards doctype, ptype, and throw=True to frappe.has_permission."""
		for ptype in ("read", "write", "create", "delete", "submit", "cancel"):
			with self.subTest(ptype=ptype):

				@require_permission("CustomDoc", ptype)
				def dummy_action():
					return "ok"

				with patch("frappe.has_permission", return_value=True) as mock_has_perm:
					result = dummy_action()
					self.assertEqual(result, "ok")
					mock_has_perm.assert_called_once_with("CustomDoc", ptype, throw=True)

	def test_arguments_and_kwargs_forwarded_to_wrapped_function(self):
		"""Arguments and keyword arguments are passed through unchanged."""

		@require_permission("User", "read")
		def calculate(a, b, factor=1):
			return (a + b) * factor

		frappe.set_user("Administrator")
		self.assertEqual(calculate(2, 3, factor=4), 20)

	def test_direct_call_allowed_when_user_has_permission(self):
		"""When session user holds permission, wrapped function executes and returns value."""
		frappe.set_user("Administrator")

		executed = []

		@require_permission("User", "read")
		def read_action(msg: str):
			executed.append(msg)
			return f"read: {msg}"

		res = read_action("hello")
		self.assertEqual(res, "read: hello")
		self.assertEqual(executed, ["hello"])

	def test_direct_call_raises_permission_error_when_denied(self):
		"""When caller lacks permission, frappe.PermissionError is raised and function does not execute."""
		plain_user = self._make_test_user(roles=["Customer"])
		frappe.set_user(plain_user)

		executed = []

		@require_permission("User", "delete")
		def delete_action():
			executed.append(True)
			return "deleted"

		with self.assertRaises(frappe.PermissionError):
			delete_action()

		self.assertEqual(executed, [])

	def test_guest_caller_raises_permission_error(self):
		"""Guest caller lacking permission raises frappe.PermissionError."""
		frappe.set_user("Guest")

		@require_permission("User", "create")
		def create_action():
			return "created"

		with self.assertRaises(frappe.PermissionError):
			create_action()

	def test_handle_api_errors_catches_permission_error_and_returns_403(self):
		"""Combined with @handle_api_errors, PermissionError becomes HTTP 403 PERMISSION_DENIED."""
		plain_user = self._make_test_user(roles=["Customer"])
		frappe.set_user(plain_user)

		@handle_api_errors
		@require_permission("User", "delete")
		def guarded_handler():
			return {"deleted": True}

		res = guarded_handler()
		self.assertEqual(frappe.response.get("http_status_code"), 403)
		self.assertEqual(res["status"], "error")
		self.assertEqual(res["code"], "PERMISSION_DENIED")

	def test_handle_api_errors_allows_execution_when_permitted(self):
		"""Combined with @handle_api_errors, permitted caller receives 200 success envelope."""
		frappe.set_user("Administrator")

		@handle_api_errors
		@require_permission("User", "read")
		def guarded_handler():
			return {"allowed": True}

		res = guarded_handler()
		self.assertEqual(res["status"], "success")
		self.assertEqual(res["data"], {"allowed": True})

	def test_rest_route_enforces_permission_guard_end_to_end(self):
		"""A Werkzeug REST route guarded with @require_permission responds 403 for unauthorized caller and 200 for authorized."""
		endpoint_path = "/api/v1/test_permission_guard_sample"

		@rest(endpoint_path, methods=("GET",), allow_guest=True)
		@handle_api_errors
		@require_permission("User", "delete")
		def sample_route():
			return {"secret": "confidential"}

		for rule in _rules:
			if rule not in frappe.api.API_URL_MAP._rules:
				frappe.api.API_URL_MAP.add(rule.empty())

		# 1. Unauthorized caller (Guest) -> 403 PERMISSION_DENIED
		frappe.set_user("Guest")
		req_denied = make_test_request(endpoint_path, method="GET")
		res_denied = frappe.api.handle(req_denied)
		self.assertEqual(res_denied.status_code, 403)
		body_denied = json.loads(res_denied.get_data(as_text=True))
		self.assertEqual(body_denied["status"], "error")
		self.assertEqual(body_denied["code"], "PERMISSION_DENIED")

		# 2. Authorized caller (Administrator) -> 200 SUCCESS
		frappe.set_user("Administrator")
		req_allowed = make_test_request(endpoint_path, method="GET")
		res_allowed = frappe.api.handle(req_allowed)
		self.assertEqual(res_allowed.status_code, 200)
		body_allowed = json.loads(res_allowed.get_data(as_text=True))
		self.assertEqual(body_allowed["status"], "success")
		self.assertEqual(body_allowed["data"], {"secret": "confidential"})
