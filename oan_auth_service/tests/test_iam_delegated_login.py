"""Tests for login delegated to the OpenG2P IAM service.

IAM is faked at the HTTP boundary: `GET /auth/get_user_profile` answers with a
principal for tokens it knows and 401 for anything else, as the real service
does.
"""

import unittest
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import frappe
import jwt
import requests

from oan_auth_service.api import iam_users
from oan_auth_service.api.middleware import validate_jwt_request
from oan_auth_service.api.router import ensure_routes_registered
from oan_auth_service.api.v1.auth import _resolve_login_identifier, issue_temporary_password
from oan_auth_service.tests.test_router import make_test_request
from oan_auth_service.tests.utils import cleanup_user, configured_keys, ensure_role, override_conf

IAM_URL = "http://iam.test"
APP = "oan-grievance"
OFFICER = "IAM Test Officer"
VIEWER = "IAM Test Viewer"


class _Response:
	def __init__(self, status_code, payload):
		self.status_code = status_code
		self._payload = payload

	def json(self):
		return self._payload


class FakeIAM:
	"""IAM's profile endpoint: knows the principals registered with `issue`."""

	def __init__(self):
		self.principals = {}
		self.calls = 0
		self.down = False

	def issue(self, sub, client_roles=None, name="Test Officer"):
		# Any non-local issuer routes to IAM; the signature is IAM's concern, not ours.
		token = jwt.encode(
			{
				"iss": "https://idp.test/realms/staff",
				"sub": sub,
				"jti": str(uuid.uuid4()),
				"exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
			},
			"idp-secret",
			algorithm="HS256",
		)
		self.principals[token] = {
			"scheme": "bearer",
			"sub": sub,
			"name": name,
			"client_roles": client_roles or {},
		}
		return token

	def get(self, url, headers=None, **_kwargs):
		self.calls += 1
		if self.down:
			raise requests.ConnectionError("IAM down")
		assert url == f"{IAM_URL}/auth/get_user_profile"
		token = (headers or {}).get("Authorization", "").removeprefix("Bearer ")
		if token not in self.principals:
			return _Response(401, {"errors": [{"code": "G2P-AUT-401"}]})
		return _Response(200, self.principals[token])


class TestIAMDelegatedLogin(unittest.TestCase):
	def setUp(self):
		ensure_routes_registered()
		for role in (OFFICER, VIEWER):
			ensure_role(role)
		frappe.cache.delete_keys("oan_auth:iam_")
		self.iam = FakeIAM()
		self.subs = []

	def tearDown(self):
		for sub in self.subs:
			cleanup_user(iam_users.user_name_for_sub(sub))
		frappe.set_user("Administrator")

	def _sub(self):
		sub = str(uuid.uuid4())
		self.subs.append(sub)
		return sub

	def _authenticate(self, token, **conf):
		conf = {"iam_base_url": IAM_URL, "iam_application": APP, **conf}
		with (
			configured_keys(),
			override_conf(**conf),
			patch("oan_auth_service.api.iam_tokens.requests.get", side_effect=self.iam.get),
		):
			req = make_test_request(
				"/api/v1/auth/health", method="GET", headers={"Authorization": f"Bearer {token}"}
			)
			frappe.set_user("Guest")
			frappe.local.session = frappe._dict({"user": "Guest"})
			validate_jwt_request(req)
		return frappe.session.user

	def _roles(self, user):
		return set(frappe.get_all("Has Role", filters={"parent": user, "parenttype": "User"}, pluck="role"))

	def test_first_login_creates_user_with_application_roles(self):
		sub = self._sub()
		token = self.iam.issue(
			sub,
			{APP: [OFFICER, "Not A Frappe Role"], "other-app": [VIEWER]},
			name="Dev Submitter",
		)
		user = self._authenticate(token)

		self.assertEqual(user, iam_users.user_name_for_sub(sub))
		self.assertEqual(frappe.db.get_value("User", user, ["first_name", "last_name"]), ("Dev", "Submitter"))
		# Only this application's roles, and only those that exist in Frappe.
		self.assertEqual(self._roles(user), {OFFICER})
		self.assertEqual(frappe.local.oan_auth_issuer_kind, "iam")
		self.assertEqual(frappe.local.oan_auth_claims["sub"], sub)

	def test_returning_user_reuses_row(self):
		sub = self._sub()
		first = self._authenticate(self.iam.issue(sub))
		second = self._authenticate(self.iam.issue(sub))
		self.assertEqual(first, second)

	def test_roles_follow_iam_exactly(self):
		sub = self._sub()
		user = self._authenticate(self.iam.issue(sub, {APP: [OFFICER, VIEWER]}))
		self.assertEqual(self._roles(user), {OFFICER, VIEWER})

		self._authenticate(self.iam.issue(sub, {APP: [VIEWER]}))
		self.assertEqual(self._roles(user), {VIEWER})

	def test_principal_is_cached_per_token(self):
		token = self.iam.issue(self._sub())
		self._authenticate(token)
		self._authenticate(token)
		self.assertEqual(self.iam.calls, 1)

	def test_disabled_user_is_rejected(self):
		sub = self._sub()
		user = self._authenticate(self.iam.issue(sub))
		frappe.db.set_value("User", user, "enabled", 0)

		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(self.iam.issue(sub))

	def test_token_iam_rejects_is_rejected(self):
		unknown = jwt.encode({"iss": "https://idp.test/realms/staff", "sub": "x"}, "k", algorithm="HS256")
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(unknown)

	def test_iam_unreachable_is_rejected(self):
		token = self.iam.issue(self._sub())
		self.iam.down = True
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(token)

	def test_iam_not_configured_is_rejected(self):
		token = self.iam.issue(self._sub())
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(token, iam_base_url="")

	def test_delegated_user_cannot_use_password_flows(self):
		user = self._authenticate(self.iam.issue(self._sub()))

		self.assertIsNone(_resolve_login_identifier(user))
		with self.assertRaises(frappe.ValidationError):
			issue_temporary_password(user, "Temp1234")
