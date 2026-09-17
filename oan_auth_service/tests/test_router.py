"""Tests for the Werkzeug REST Router framework and REST Auth endpoints."""

import json
import unittest

import frappe
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from oan_auth_service.api import tokens
from oan_auth_service.api.router import (
	ensure_routes_registered,
	prefixed,
	registered_routes,
	rest,
)
from oan_auth_service.config import settings
from oan_auth_service.tests.utils import configured_keys, ensure_role, override_conf


def make_test_request(
	path: str,
	method: str = "GET",
	data: dict | None = None,
	headers: dict | None = None,
	scheme: str = "http",
	environ_base: dict | None = None,
) -> Request:
	"""Helper to construct a Werkzeug Request and set up frappe.local state."""
	builder_kwargs = {
		"path": path,
		"method": method.upper(),
		"base_url": f"{scheme}://testsite.localhost",
		"headers": headers or {},
	}
	if data is not None:
		builder_kwargs["json"] = data

	builder = EnvironBuilder(**builder_kwargs)
	env = builder.get_environ()
	if environ_base:
		env.update(environ_base)
	req = Request(env)

	frappe.local.request = req
	frappe.local.request_ip = "127.0.0.1"
	frappe.local.form_dict = frappe._dict(data or {})
	frappe.local.response = frappe._dict({})

	return req


class TestWerkzeugRESTRouter(unittest.TestCase):
	def test_rest_decorator_registration(self):
		@rest("/api/v1/test_dummy_route", methods=("GET", "POST"), allow_guest=True, summary="Test Route")
		def dummy_route():
			return {"message": "hello"}

		routes = registered_routes()
		matching = [r for r in routes if r["path"] == "/api/v1/test_dummy_route"]
		self.assertTrue(len(matching) >= 1)
		self.assertEqual(matching[0]["methods"], ("GET", "POST"))
		self.assertTrue(matching[0]["allow_guest"])
		self.assertEqual(matching[0]["summary"], "Test Route")

	def test_prefixed_helper(self):
		my_route = prefixed("/api/v1/sample")

		@my_route("/action", methods=("POST",))
		def sample_action():
			return {"action": "ok"}

		routes = registered_routes()
		matching = [r for r in routes if r["path"] == "/api/v1/sample/action"]
		self.assertTrue(len(matching) >= 1)
		self.assertEqual(matching[0]["methods"], ("POST",))


class TestHTTPSValidationAndEnforcement(unittest.TestCase):
	def test_enforce_https_setting(self):
		with override_conf(jwt_enforce_https=True):
			self.assertTrue(settings.enforce_https())

		with override_conf(jwt_enforce_https=False, enforce_https=False):
			self.assertFalse(settings.enforce_https())


class TestRESTAuthEndpoints(unittest.TestCase):
	def setUp(self):
		ensure_routes_registered()
		self.created_users = []
		self.created_contacts = []
		ensure_role("Customer")
		ensure_role("System Manager")

	def tearDown(self):
		for user in self.created_users:
			if frappe.db.exists("User", user):
				frappe.db.delete("OAN User Refresh Token", {"user": user})
				contacts = frappe.get_all(
					"Dynamic Link", filters={"link_doctype": "User", "link_name": user}, pluck="parent"
				)
				for c in contacts:
					if frappe.db.exists("Contact", c):
						frappe.delete_doc("Contact", c, force=True, ignore_permissions=True)
				frappe.delete_doc("User", user, force=True, ignore_permissions=True)

		for c in self.created_contacts:
			if frappe.db.exists("Contact", c):
				frappe.delete_doc("Contact", c, force=True, ignore_permissions=True)

		frappe.db.commit()
		frappe.set_user("Administrator")

	def test_rest_public_health_and_keys(self):
		import frappe.api

		# Health endpoint
		req_health = make_test_request("/api/v1/auth/health", method="GET")
		res_health = frappe.api.handle(req_health)
		self.assertEqual(res_health.status_code, 200)
		data_health = json.loads(res_health.get_data(as_text=True))
		self.assertEqual(data_health["data"]["status"], "healthy")

		# Public keys endpoint
		with configured_keys():
			req_keys = make_test_request("/api/v1/auth/keys", method="GET")
			res_keys = frappe.api.handle(req_keys)
			self.assertEqual(res_keys.status_code, 200)
			data_keys = json.loads(res_keys.get_data(as_text=True))
			self.assertEqual(data_keys["data"]["algorithm"], "HS256")
			self.assertEqual(data_keys["data"]["active_kid"], "v1")

		# Public metadata endpoint
		req_meta = make_test_request("/api/v1/auth/metadata", method="GET")
		res_meta = frappe.api.handle(req_meta)
		self.assertEqual(res_meta.status_code, 200)
		data_meta = json.loads(res_meta.get_data(as_text=True))
		self.assertEqual(data_meta["status"], "success")
		self.assertIn("auth", data_meta["data"])
		self.assertIn("self_registerable_roles", data_meta["data"]["auth"])

	def test_rest_register_login_refresh_logout_lifecycle(self):
		import frappe.api

		with configured_keys(), override_conf(jwt_self_registerable_roles=["Customer"]):
			email = f"rest_user_{frappe.generate_hash(length=6)}@example.com"
			pwd = "SuperSecretPassword123!"

			# 1. Register via REST POST /api/v1/auth/register
			reg_req = make_test_request(
				"/api/v1/auth/register",
				method="POST",
				data={
					"email": email,
					"password": pwd,
					"full_name": "REST Tester",
					"role": "Customer",
				},
			)
			reg_res = frappe.api.handle(reg_req)
			self.assertEqual(reg_res.status_code, 200)
			reg_data = json.loads(reg_res.get_data(as_text=True))
			self.assertEqual(reg_data["status"], "success")
			user_id = reg_data["data"]["user"]
			self.created_users.append(user_id)
			self.assertTrue(bool(reg_data["data"]["refresh_token"]))

			# 2. Login via REST POST /api/v1/auth/login
			login_req = make_test_request(
				"/api/v1/auth/login",
				method="POST",
				data={"usr": email, "pwd": pwd},
			)
			login_res = frappe.api.handle(login_req)
			self.assertEqual(login_res.status_code, 200)
			login_data = json.loads(login_res.get_data(as_text=True))
			self.assertEqual(login_data["status"], "success")
			self.assertTrue(bool(login_data["data"]["access_token"]))
			login_refresh = login_data["data"]["refresh_token"]

			# 3. Refresh via REST POST /api/v1/auth/refresh
			ref_req = make_test_request(
				"/api/v1/auth/refresh",
				method="POST",
				data={"refresh_token": login_refresh},
			)
			ref_res = frappe.api.handle(ref_req)
			self.assertEqual(ref_res.status_code, 200)
			ref_data = json.loads(ref_res.get_data(as_text=True))
			new_access = ref_data["data"]["access_token"]
			new_refresh = ref_data["data"]["refresh_token"]
			self.assertNotEqual(login_refresh, new_refresh)

			# 4. Introspect via REST GET /api/v1/auth/me (Protected)
			me_req = make_test_request(
				"/api/v1/auth/me",
				method="GET",
				headers={"Authorization": f"Bearer {new_access}"},
			)
			frappe.set_user("Guest")
			frappe.local.session = frappe._dict({"user": "Guest"})

			from oan_auth_service.api.middleware import validate_jwt_request

			validate_jwt_request(me_req)
			me_res = frappe.api.handle(me_req)
			self.assertEqual(me_res.status_code, 200)
			me_data = json.loads(me_res.get_data(as_text=True))
			self.assertEqual(me_data["data"]["user"], user_id)
			self.assertEqual(me_data["data"]["login_email"], email)

			# 5. Logout via REST POST /api/v1/auth/logout
			logout_req = make_test_request(
				"/api/v1/auth/logout",
				method="POST",
				data={"refresh_token": new_refresh},
			)
			logout_res = frappe.api.handle(logout_req)
			self.assertEqual(logout_res.status_code, 200)
			logout_data = json.loads(logout_res.get_data(as_text=True))
			self.assertTrue(logout_data["data"]["revoked"])

	def test_rest_protected_me_endpoint_unauthorized(self):
		import frappe.api

		# Anonymous / Guest caller without Bearer token must be rejected
		me_req = make_test_request("/api/v1/auth/me", method="GET")
		frappe.set_user("Guest")
		frappe.local.session = frappe._dict({"user": "Guest"})

		from oan_auth_service.api.middleware import validate_jwt_request

		with self.assertRaises(frappe.AuthenticationError):
			validate_jwt_request(me_req)

	def test_exempt_endpoint_with_bearer_token(self):
		"""Verify that an exempt route accepts Bearer token without raising AuthenticationError."""
		from oan_auth_service.api.middleware import validate_jwt_request

		with configured_keys():
			token, _ = tokens.issue_access_token("Administrator", ["System Manager"])
			req = make_test_request(
				"/api/v1/auth/health",
				method="GET",
				headers={"Authorization": f"Bearer {token}"},
			)
			frappe.set_user("Guest")
			frappe.local.session = frappe._dict({"user": "Guest"})

			validate_jwt_request(req)
			self.assertEqual(frappe.session.user, "Administrator")

	def test_exempt_endpoint_with_expired_token(self):
		"""Verify that an exempt route never 401s on expired token; caller falls through to Guest."""
		from datetime import UTC, datetime, timedelta

		import jwt as pyjwt

		from oan_auth_service.api.middleware import validate_jwt_request
		from oan_auth_service.tests.test_jwt_keys import TEST_SECRETS

		with configured_keys():
			past = datetime.now(UTC) - timedelta(hours=1)
			claims = {
				"iss": settings.issuer(),
				"sub": "Administrator",
				"iat": int(past.timestamp()),
				"exp": int((past + timedelta(minutes=1)).timestamp()),
				"typ": tokens.ACCESS_TOKEN_TYPE,
				"roles": ["System Manager"],
			}
			expired_token = pyjwt.encode(
				claims, TEST_SECRETS["v1"], algorithm=tokens.ALGORITHM, headers={"kid": "v1"}
			)
			req = make_test_request(
				"/api/v1/auth/health",
				method="GET",
				headers={"Authorization": f"Bearer {expired_token}"},
			)
			frappe.set_user("Guest")
			frappe.local.session = frappe._dict({"user": "Guest"})

			validate_jwt_request(req)
			self.assertEqual(frappe.session.user, "Guest")

	def test_exempt_endpoint_with_revoked_scope_token(self):
		"""Verify that an exempt route falls through to Guest if scope is no longer held."""
		from oan_auth_service.api.middleware import validate_jwt_request

		with configured_keys():
			token, _ = tokens.issue_access_token("Administrator", ["System Manager"], scope=["LostRole"])
			req = make_test_request(
				"/api/v1/auth/health",
				method="GET",
				headers={"Authorization": f"Bearer {token}"},
			)
			frappe.set_user("Guest")
			frappe.local.session = frappe._dict({"user": "Guest"})

			validate_jwt_request(req)
			self.assertEqual(frappe.session.user, "Guest")

	def test_exempt_endpoint_with_malformed_token(self):
		"""Verify that an exempt route falls through to Guest if token is completely malformed."""
		from oan_auth_service.api.middleware import validate_jwt_request

		req = make_test_request(
			"/api/v1/auth/health",
			method="GET",
			headers={"Authorization": "Bearer not-a-jwt-token"},
		)
		frappe.set_user("Guest")
		frappe.local.session = frappe._dict({"user": "Guest"})

		validate_jwt_request(req)
		self.assertEqual(frappe.session.user, "Guest")

	def test_rest_forgot_password_flow(self):
		import random

		import frappe.api

		with configured_keys(), override_conf(jwt_self_registerable_roles=["Customer"]):
			phone = "98" + "".join(random.choices("0123456789", k=8))
			pwd = "SuperSecretPassword123!"

			# Register with phone
			reg_req = make_test_request(
				"/api/v1/auth/register",
				method="POST",
				data={
					"phone_number": phone,
					"password": pwd,
					"full_name": "Password Tester",
					"role": "Customer",
				},
			)
			reg_res = frappe.api.handle(reg_req)
			self.assertEqual(reg_res.status_code, 200)
			user_id = json.loads(reg_res.get_data(as_text=True))["data"]["user"]
			self.created_users.append(user_id)

			# Forgot password via REST
			forgot_req = make_test_request(
				"/api/v1/auth/forgot-password",
				method="POST",
				data={"usr": phone},
			)
			forgot_res = frappe.api.handle(forgot_req)
			self.assertEqual(forgot_res.status_code, 200)
			forgot_data = json.loads(forgot_res.get_data(as_text=True))
			self.assertEqual(forgot_data["status"], "success")
