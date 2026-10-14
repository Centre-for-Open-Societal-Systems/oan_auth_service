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

from oan_auth_service.api import iam_tokens, iam_users, middleware
from oan_auth_service.api.iam_tokens import TokenError
from oan_auth_service.api.middleware import validate_jwt_request
from oan_auth_service.api.router import ensure_routes_registered
from oan_auth_service.api.v1.auth import _resolve_login_identifier, issue_temporary_password
from oan_auth_service.tests.test_router import make_test_request
from oan_auth_service.tests.utils import cleanup_user, configured_keys, ensure_role, override_conf

IAM_URL = "https://iam.test"
APP = "oan-grievance"
OFFICER = "IAM Test Officer"
VIEWER = "IAM Test Viewer"


class _Response:
	def __init__(self, status_code, payload):
		self.status_code = status_code
		self._payload = payload

	def json(self):
		if isinstance(self._payload, Exception):
			raise self._payload
		return self._payload


class FakeIAM:
	"""IAM's profile endpoint: knows the principals registered with `issue`."""

	def __init__(self):
		self.principals = {}
		self.calls = 0
		self.down = False
		self.override = None

	def issue(self, sub, client_roles=None, name="Test Officer"):
		# Default grants a role: principals with none are rejected.
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
			"client_roles": client_roles if client_roles is not None else {APP: [OFFICER]},
		}
		return token

	def get(self, url, headers=None, **_kwargs):
		self.calls += 1
		if self.down:
			raise requests.ConnectionError("IAM down")
		assert url == f"{IAM_URL}/auth/get_user_profile"
		if self.override is not None:
			return self.override
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

	def _authenticate_cookies(
		self, cookies, method="GET", headers=None, protected=False, form_dict=None, **conf
	):
		"""`protected` makes the test path non-exempt, as every real endpoint but login-style ones."""
		conf = {"iam_base_url": IAM_URL, "iam_application": APP, **conf}
		env = {"HTTP_COOKIE": "; ".join(f"{k}={v}" for k, v in cookies.items())}
		real_match = middleware._match_namespace

		def match(path):
			config = real_match(path)
			return {**config, "exempt_paths": []} if config and protected else config

		with (
			configured_keys(),
			override_conf(**conf),
			patch("oan_auth_service.api.iam_tokens.requests.get", side_effect=self.iam.get),
			patch.object(middleware, "_match_namespace", side_effect=match),
		):
			req = make_test_request(
				"/api/v1/auth/health", method=method, headers=headers or {}, environ_base=env
			)
			frappe.set_user("Guest")
			frappe.local.session = frappe._dict({"user": "Guest"})
			frappe.local.form_dict = frappe._dict(form_dict or {})
			validate_jwt_request(req)
		return frappe.session.user

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

	def test_case_and_odd_characters_in_sub_map_to_distinct_valid_users(self):
		base = uuid.uuid4().hex
		subs = [f"Ab{base}", f"aB{base}", f"ab{base}", f"a/b+c d={base}"]
		self.subs.extend(subs)
		users = [self._authenticate(self.iam.issue(sub)) for sub in subs]
		self.assertEqual(len(set(users)), len(subs))
		for user in users:
			self.assertTrue(frappe.db.exists("User", user))

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

	def test_principal_without_app_roles_is_rejected_and_not_created(self):
		for roles in ({}, {"other-app": [OFFICER]}, {APP: ["No Such Role"]}):
			sub = self._sub()
			with self.assertRaises(frappe.AuthenticationError):
				self._authenticate(self.iam.issue(sub, roles))
			self.assertFalse(frappe.db.exists("User", iam_users.user_name_for_sub(sub)))

	def test_unset_iam_application_is_rejected(self):
		sub = self._sub()
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(self.iam.issue(sub), iam_application="")
		self.assertFalse(frappe.db.exists("User", iam_users.user_name_for_sub(sub)))

	def test_user_losing_all_roles_is_stripped_and_rejected(self):
		# Safe method (GET): the strip is committed before the 401, so it persists.
		sub = self._sub()
		user = self._authenticate(self.iam.issue(sub))
		with patch("frappe.db.commit") as commit, self.assertRaises(frappe.AuthenticationError):
			self._authenticate(self.iam.issue(sub, {APP: []}))
		commit.assert_called_once()
		self.assertEqual(self._roles(user), set())

	def test_role_strip_is_not_committed_on_unsafe_method(self):
		# POST: nothing commits, so Frappe's rollback of the rejected request undoes
		# the strip. The request is still refused.
		sub = self._sub()
		self._authenticate(self.iam.issue(sub))
		token = self.iam.issue(sub, {APP: []})
		with patch("frappe.db.commit") as commit, self.assertRaises(frappe.AuthenticationError):
			self._authenticate_cookies(
				{"X-Access-Token": token, "X-CSRF-Token": "abc"},
				method="POST",
				headers={"X-CSRF-Token": "abc"},
				protected=True,
			)
		commit.assert_not_called()

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

	def test_malformed_iam_200_is_rejected_not_500(self):
		for payload in (ValueError("not json"), [], "ok", None):
			sub = self._sub()
			token = self.iam.issue(sub)
			self.iam.override = _Response(200, payload)
			with self.assertRaises(frappe.AuthenticationError):
				self._authenticate(token)
			self.assertFalse(frappe.db.exists("User", iam_users.user_name_for_sub(sub)))

	def test_iam_unreachable_is_503_not_401(self):
		token = self.iam.issue(self._sub())
		self.iam.down = True
		with self.assertRaises(frappe.ServiceUnavailableError):
			self._authenticate(token)

	def test_iam_5xx_is_503_not_401(self):
		token = self.iam.issue(self._sub())
		self.iam.override = _Response(502, {})
		with self.assertRaises(frappe.ServiceUnavailableError):
			self._authenticate(token)

	def test_iam_outage_logs_once_per_window(self):
		self.iam.down = True
		with patch("oan_auth_service.api.iam_tokens.frappe.log_error") as log_error:
			for _i in range(3):
				with self.assertRaises(frappe.ServiceUnavailableError):
					self._authenticate(self.iam.issue(self._sub()))
		self.assertEqual(log_error.call_count, 1)

	def test_iam_not_configured_is_rejected(self):
		token = self.iam.issue(self._sub())
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(token, iam_base_url="")

	def test_delegated_user_cannot_use_password_flows(self):
		user = self._authenticate(self.iam.issue(self._sub()))

		self.assertIsNone(_resolve_login_identifier(user))
		with self.assertRaises(frappe.ValidationError):
			issue_temporary_password(user, "Temp1234")

	def test_cookie_session_authenticates_get_without_bearer(self):
		sub = self._sub()
		token = self.iam.issue(sub, {APP: [OFFICER]})
		user = self._authenticate_cookies({"X-Access-Token": token})
		self.assertEqual(user, iam_users.user_name_for_sub(sub))
		self.assertEqual(self._roles(user), {OFFICER})

	def test_cookie_token_iam_rejects_is_401_like_bearer(self):
		# An expired cookie gets the same 401 as an expired Bearer token: the
		# client refreshes through IAM, this app does not.
		token = self.iam.issue(self._sub())
		del self.iam.principals[token]
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate_cookies({"X-Access-Token": token}, protected=True)

	def test_cookie_post_requires_matching_csrf_header(self):
		token = self.iam.issue(self._sub())
		cookies = {"X-Access-Token": token, "X-CSRF-Token": "abc"}

		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate_cookies(cookies, method="POST", protected=True)
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate_cookies(
				cookies, method="POST", headers={"X-CSRF-Token": "nope"}, protected=True
			)
		self._authenticate_cookies(cookies, method="POST", headers={"X-CSRF-Token": "abc"}, protected=True)

	def test_cookie_names_follow_iam_prefix(self):
		# Mirrors iam_core: the prefix applies to every auth cookie, never the CSRF header.
		sub = self._sub()
		token = self.iam.issue(sub)
		prefixed = {"staff_X-Access-Token": token, "staff_X-CSRF-Token": "abc"}

		# A cookie under the other name is not seen at all (the health path is exempt).
		self.assertEqual(self._authenticate_cookies(prefixed), "Guest")
		self.assertEqual(
			self._authenticate_cookies({"X-Access-Token": token}, iam_auth_cookie_prefix="staff_"), "Guest"
		)
		user = self._authenticate_cookies(
			prefixed, method="POST", headers={"X-CSRF-Token": "abc"}, iam_auth_cookie_prefix="staff_"
		)
		self.assertEqual(user, iam_users.user_name_for_sub(sub))

	def test_stale_cookie_does_not_block_exempt_post(self):
		# A browser resends its expired cookie to /login, /refresh and the like.
		# On an exempt path it counts as "no credentials", never a 401.
		stale = self.iam.issue(self._sub())
		del self.iam.principals[stale]
		valid = self.iam.issue(self._sub())
		cookies = {"X-Access-Token": stale, "X-CSRF-Token": "abc"}

		# Expired token, no CSRF header. No Error Log row on an exempt path.
		with patch("oan_auth_service.api.middleware.frappe.log_error") as log_error:
			self.assertEqual(self._authenticate_cookies(cookies, method="POST"), "Guest")
			log_error.assert_not_called()
		# The request body must survive: the router builds endpoint args from it.
		body = {"usr": "a@example.com", "pwd": "x"}
		self.assertEqual(self._authenticate_cookies(cookies, method="POST", form_dict=body), "Guest")
		self.assertEqual(frappe.form_dict.get("usr"), "a@example.com")
		self.assertEqual(frappe.form_dict.get("pwd"), "x")
		# Expired token, CSRF header present.
		self.assertEqual(
			self._authenticate_cookies(cookies, method="POST", headers={"X-CSRF-Token": "abc"}), "Guest"
		)
		# Valid token but CSRF header missing.
		good = {"X-Access-Token": valid, "X-CSRF-Token": "abc"}
		self.assertEqual(self._authenticate_cookies(good, method="POST"), "Guest")

		# The same stale cookie on a protected path is still a 401.
		with (
			patch("oan_auth_service.api.middleware.frappe.log_error"),
			self.assertRaises(frappe.AuthenticationError),
		):
			self._authenticate_cookies(
				cookies, method="POST", headers={"X-CSRF-Token": "abc"}, protected=True
			)

	def test_http_iam_url_rejected_and_logged_once(self):
		frappe.cache.delete_value("oan_auth:iam_insecure_url_logged")
		with patch("oan_auth_service.api.iam_tokens.frappe.log_error") as log_error:
			for _ in range(3):
				with self.assertRaises(TokenError):
					iam_tokens._require_https("http://iam.cluster.local")
			self.assertEqual(log_error.call_count, 1)

	def test_http_iam_url_allowed_with_opt_out(self):
		with override_conf(iam_allow_insecure_http=True):
			iam_tokens._require_https("http://iam.cluster.local")

	def test_non_ascii_csrf_is_rejected_not_500(self):
		# compare_digest raises TypeError on non-ASCII str; both sides are client-controlled.
		token = self.iam.issue(self._sub())
		cookies = {"X-Access-Token": token, "X-CSRF-Token": "abc"}
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate_cookies(cookies, method="POST", headers={"X-CSRF-Token": "é"}, protected=True)

		# On an exempt path the bad CSRF means "no credentials".
		self.assertEqual(
			self._authenticate_cookies(cookies, method="POST", headers={"X-CSRF-Token": "é"}), "Guest"
		)

	def test_bearer_post_needs_no_csrf(self):
		token = self.iam.issue(self._sub())
		# Same helper path as a Bearer call: no cookie, so no CSRF requirement.
		self._authenticate(token)

	def test_cookie_carries_our_own_token_too(self):
		# Transport and issuer are independent: our token in the cookie verifies
		# in-process, without IAM, and still needs CSRF on writes.
		from oan_auth_service.api import tokens

		with configured_keys():
			own, _ = tokens.issue_access_token("Administrator", ["System Manager"])
		self.assertEqual(self._authenticate_cookies({"X-Access-Token": own}), "Administrator")
		self.assertEqual(self.iam.calls, 0)
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate_cookies({"X-Access-Token": own}, method="POST", protected=True)
