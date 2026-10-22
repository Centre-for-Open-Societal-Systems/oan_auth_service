"""Tests for login delegated to the OpenG2P IAM services.

IAM is faked at the HTTP boundary: `GET /auth/get_user_profile` answers with a
principal for tokens it knows and 401 for anything else, as the real service
does. Login options are real `OAN IAM Service` rows.
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
from oan_auth_service.tests.utils import (
	cleanup_user,
	configured_keys,
	delete_iam_service,
	ensure_role,
	make_iam_service,
)

STAFF = "t-staff"
AGENT = "t-agent"
BENE = "t-bene"
STAFF_URL = "https://staff-iam.test"
AGENT_URL = "https://agent-iam.test"
BENE_URL = "https://bene-iam.test"
STAFF_ISS = "https://idp.test/realms/staff"
AGENT_ISS = "https://idp.test/realms/agent"
BENE_ISS = "https://esignet.test"
APP = "oan-grievance"
OFFICER = "IAM Test Officer"
VIEWER = "IAM Test Viewer"
FARMER = "IAM Test Farmer"

# Login hooks under test, set per test and called by dotted path through frappe.get_hooks.
HOOK_CALLS = []
HOOK_BEHAVIOUR = {"raise": None, "return": False}


def recording_hook(user, principal, login_option):
	HOOK_CALLS.append(("first", user, principal, login_option))
	if HOOK_BEHAVIOUR["raise"] is not None:
		raise HOOK_BEHAVIOUR["raise"]
	return HOOK_BEHAVIOUR["return"]


def second_hook(user, principal, login_option):
	HOOK_CALLS.append(("second", user, principal, login_option))
	return False


class _Response:
	def __init__(self, status_code, payload):
		self.status_code = status_code
		self._payload = payload

	def json(self):
		if isinstance(self._payload, Exception):
			raise self._payload
		return self._payload


class FakeIAM:
	"""The profile endpoint of every IAM: knows the principals registered with `issue`."""

	def __init__(self):
		self.principals = {}
		self.urls = []
		self.down = False
		self.override = None

	@property
	def calls(self):
		return len(self.urls)

	def issue(self, sub, client_roles=None, name="Test Officer", iss=STAFF_ISS, base_url=STAFF_URL, **claims):
		# Default grants a role: principals with none are rejected.
		# The signature is IAM's concern, not ours.
		token = jwt.encode(
			{
				"iss": iss,
				"sub": sub,
				"jti": str(uuid.uuid4()),
				"exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
				**claims,
			},
			"idp-secret",
			algorithm="HS256",
		)
		self.principals[token] = (
			base_url,
			{
				"scheme": "bearer",
				"sub": sub,
				"name": name,
				"client_roles": client_roles if client_roles is not None else {APP: [OFFICER]},
			},
		)
		return token

	def get(self, url, headers=None, **_kwargs):
		self.urls.append(url)
		if self.down:
			raise requests.ConnectionError("IAM down")
		if self.override is not None:
			return self.override
		token = (headers or {}).get("Authorization", "").removeprefix("Bearer ")
		if token not in self.principals:
			return _Response(401, {"errors": [{"code": "G2P-AUT-401"}]})
		base_url, principal = self.principals[token]
		# Each IAM knows only the tokens of its own provider in this fake, so a
		# token sent to the wrong IAM fails, as routing must never do.
		if url != f"{base_url}/auth/get_user_profile":
			return _Response(401, {})
		return _Response(200, principal)


class TestIAMDelegatedLogin(unittest.TestCase):
	def setUp(self):
		ensure_routes_registered()
		for role in (OFFICER, VIEWER, FARMER):
			ensure_role(role)
		make_iam_service(
			STAFF,
			base_url=STAFF_URL,
			provider_id=1,
			issuer=STAFF_ISS,
			application=APP,
			return_origins=["https://ui.test"],
			sort_order=1,
		)
		make_iam_service(
			AGENT,
			base_url=AGENT_URL,
			provider_id=10,
			issuer=AGENT_ISS,
			application=APP,
			cookie_prefix="agent-",
			return_origins=["https://ui.test"],
			sort_order=2,
		)
		make_iam_service(
			BENE,
			base_url=BENE_URL,
			provider_id=1,
			issuer=BENE_ISS,
			default_roles=[FARMER],
			cookie_prefix="bene-",
			return_origins=["https://ui.test"],
			sort_order=3,
		)
		frappe.cache.delete_keys("oan_auth:iam_")
		frappe.cache.delete_keys("oan_auth:login_hook_done:")
		self.iam = FakeIAM()
		self.users = []
		HOOK_CALLS.clear()
		HOOK_BEHAVIOUR.update({"raise": None, "return": False})

	def tearDown(self):
		for user in self.users:
			cleanup_user(user)
		for key in (STAFF, AGENT, BENE):
			delete_iam_service(key)
		frappe.set_user("Administrator")

	def _sub(self, key=STAFF):
		sub = str(uuid.uuid4())
		self.users.append(iam_users.user_name_for_sub(sub, key))
		return sub

	def _patches(self, hooks=None):
		real_get_hooks = frappe.get_hooks

		def get_hooks(name=None, *a, **kw):
			if name == iam_users.LOGIN_HOOK:
				return list(hooks or [])
			return real_get_hooks(name, *a, **kw)

		return (
			configured_keys(),
			patch("oan_auth_service.api.iam_tokens.requests.get", side_effect=self.iam.get),
			patch("frappe.get_hooks", side_effect=get_hooks),
		)

	def _authenticate_cookies(self, cookies, method="GET", headers=None, protected=False, form_dict=None):
		"""`protected` makes the test path non-exempt, as every real endpoint but login-style ones."""
		env = {"HTTP_COOKIE": "; ".join(f"{k}={v}" for k, v in cookies.items())}
		real_match = middleware._match_namespace

		def match(path):
			config = real_match(path)
			return {**config, "exempt_paths": middleware._PathTable()} if config and protected else config

		keys, iam, hooks = self._patches()
		with keys, iam, hooks, patch.object(middleware, "_match_namespace", side_effect=match):
			req = make_test_request(
				"/api/v1/auth/health", method=method, headers=headers or {}, environ_base=env
			)
			frappe.set_user("Guest")
			frappe.local.session = frappe._dict({"user": "Guest"})
			frappe.local.form_dict = frappe._dict(form_dict or {})
			validate_jwt_request(req)
		return frappe.session.user

	def _authenticate(self, token, method="GET", hooks=None):
		keys, iam, get_hooks = self._patches(hooks)
		with keys, iam, get_hooks:
			req = make_test_request(
				"/api/v1/auth/health", method=method, headers={"Authorization": f"Bearer {token}"}
			)
			frappe.set_user("Guest")
			frappe.local.session = frappe._dict({"user": "Guest"})
			validate_jwt_request(req)
		return frappe.session.user

	def _roles(self, user):
		return set(frappe.get_all("Has Role", filters={"parent": user, "parenttype": "User"}, pluck="role"))

	# -- provisioning ---------------------------------------------------------

	def test_first_login_creates_user_with_application_roles(self):
		sub = self._sub()
		token = self.iam.issue(
			sub,
			{APP: [OFFICER, "Not A Frappe Role"], "other-app": [VIEWER]},
			name="Dev Submitter",
		)
		user = self._authenticate(token)

		self.assertEqual(user, iam_users.user_name_for_sub(sub, STAFF))
		self.assertEqual(frappe.db.get_value("User", user, ["first_name", "last_name"]), ("Dev", "Submitter"))
		# Only this application's roles, and only those that exist in Frappe.
		self.assertEqual(self._roles(user), {OFFICER})
		self.assertEqual(frappe.local.oan_auth_issuer_kind, "iam")
		self.assertEqual(frappe.local.oan_auth_login_option, STAFF)
		self.assertEqual(frappe.local.oan_auth_claims["sub"], sub)

	def test_case_and_odd_characters_in_sub_map_to_distinct_valid_users(self):
		base = uuid.uuid4().hex
		subs = [f"Ab{base}", f"aB{base}", f"ab{base}", f"a/b+c d={base}"]
		self.users.extend(iam_users.user_name_for_sub(s, STAFF) for s in subs)
		users = [self._authenticate(self.iam.issue(sub)) for sub in subs]
		self.assertEqual(len(set(users)), len(subs))
		for user in users:
			self.assertTrue(frappe.db.exists("User", user))

	def test_returning_user_reuses_row(self):
		sub = self._sub()
		first = self._authenticate(self.iam.issue(sub))
		second = self._authenticate(self.iam.issue(sub))
		self.assertEqual(first, second)

	def test_same_sub_from_two_rows_gives_two_users(self):
		sub = self._sub(STAFF)
		self.users.append(iam_users.user_name_for_sub(sub, AGENT))
		staff_user = self._authenticate(self.iam.issue(sub))
		agent_user = self._authenticate(self.iam.issue(sub, iss=AGENT_ISS, base_url=AGENT_URL))
		self.assertNotEqual(staff_user, agent_user)
		self.assertEqual(agent_user, iam_users.user_name_for_sub(sub, AGENT))

	def test_roles_follow_iam_exactly(self):
		sub = self._sub()
		user = self._authenticate(self.iam.issue(sub, {APP: [OFFICER, VIEWER]}))
		self.assertEqual(self._roles(user), {OFFICER, VIEWER})

		self._authenticate(self.iam.issue(sub, {APP: [VIEWER]}))
		self.assertEqual(self._roles(user), {VIEWER})

	def test_application_is_per_row(self):
		frappe.db.set_value("OAN IAM Service", AGENT, "application", "agent-app")
		frappe.db.commit()  # nosemgrep: frappe-manual-commit
		frappe.cache.delete_keys("oan_auth:iam_")
		sub = self._sub(AGENT)
		token = self.iam.issue(
			sub, {APP: [OFFICER], "agent-app": [VIEWER]}, iss=AGENT_ISS, base_url=AGENT_URL
		)
		user = self._authenticate(token)
		self.assertEqual(self._roles(user), {VIEWER})

	def test_default_roles_granted_without_roles_in_token(self):
		# eSignet: identity only, no resource_access.
		sub = self._sub(BENE)
		user = self._authenticate(self.iam.issue(sub, {}, iss=BENE_ISS, base_url=BENE_URL))
		self.assertEqual(self._roles(user), {FARMER})

	def test_removing_a_default_role_removes_it_on_next_token(self):
		sub = self._sub(BENE)
		user = self._authenticate(self.iam.issue(sub, {}, iss=BENE_ISS, base_url=BENE_URL))
		doc = frappe.get_doc("OAN IAM Service", BENE)
		doc.default_roles = []
		doc.append("default_roles", {"role": VIEWER})
		doc.save(ignore_permissions=True)
		frappe.db.commit()  # nosemgrep: frappe-manual-commit

		self._authenticate(self.iam.issue(sub, {}, iss=BENE_ISS, base_url=BENE_URL))
		self.assertEqual(self._roles(user), {VIEWER})

	def test_principal_without_roles_is_rejected_and_not_created(self):
		for roles in ({}, {"other-app": [OFFICER]}, {APP: ["No Such Role"]}):
			sub = self._sub()
			with self.assertRaises(frappe.AuthenticationError):
				self._authenticate(self.iam.issue(sub, roles))
			self.assertFalse(frappe.db.exists("User", iam_users.user_name_for_sub(sub, STAFF)))

	def test_application_without_roles_logs_warning(self):
		with patch("oan_auth_service.api.iam_tokens.frappe.log_error") as log_error:
			with self.assertRaises(frappe.AuthenticationError):
				self._authenticate(self.iam.issue(self._sub(), {"other-app": [OFFICER]}))
		titles = [c.kwargs.get("title") for c in log_error.call_args_list]
		self.assertIn("oan_auth_service: IAM token has no roles for application", titles)

	def test_default_roles_only_row_does_not_warn(self):
		with patch("oan_auth_service.api.iam_tokens.frappe.log_error") as log_error:
			self._authenticate(self.iam.issue(self._sub(BENE), {}, iss=BENE_ISS, base_url=BENE_URL))
		titles = [c.kwargs.get("title") for c in log_error.call_args_list]
		self.assertNotIn("oan_auth_service: IAM token has no roles for application", titles)

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

	def test_disabled_user_is_rejected(self):
		sub = self._sub()
		user = self._authenticate(self.iam.issue(sub))
		frappe.db.set_value("User", user, "enabled", 0)

		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(self.iam.issue(sub))

	def test_delegated_user_cannot_use_password_flows(self):
		user = self._authenticate(self.iam.issue(self._sub()))

		self.assertIsNone(_resolve_login_identifier(user))
		with self.assertRaises(frappe.ValidationError):
			issue_temporary_password(user, "Temp1234")

	# -- routing by issuer ----------------------------------------------------

	def test_token_routed_to_iam_of_its_issuer(self):
		self._authenticate(self.iam.issue(self._sub(AGENT), iss=AGENT_ISS, base_url=AGENT_URL))
		self.assertEqual(self.iam.urls, [f"{AGENT_URL}/auth/get_user_profile"])

	def test_unknown_issuer_is_rejected_without_iam_call(self):
		token = self.iam.issue(self._sub(), iss="https://idp.test/realms/other")
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(token)
		self.assertEqual(self.iam.calls, 0)

	def test_issuer_match_is_exact(self):
		token = self.iam.issue(self._sub(), iss=f"{STAFF_ISS}/")
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(token)
		self.assertEqual(self.iam.calls, 0)

	def test_disabled_row_cuts_off_its_tokens_cached_included(self):
		token = self.iam.issue(self._sub())
		self._authenticate(token)
		doc = frappe.get_doc("OAN IAM Service", STAFF)
		doc.enabled = 0
		doc.save(ignore_permissions=True)
		frappe.db.commit()  # nosemgrep: frappe-manual-commit

		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(token)
		self.assertEqual(self.iam.calls, 1)

	def test_azp_mismatch_is_rejected_without_iam_call(self):
		frappe.db.set_value("OAN IAM Service", STAFF, "client_id", "staff-portal")
		frappe.db.commit()  # nosemgrep: frappe-manual-commit
		frappe.cache.delete_keys("oan_auth:iam_")

		for claims in ({"azp": "agent-portal"}, {}):
			with self.assertRaises(frappe.AuthenticationError):
				self._authenticate(self.iam.issue(self._sub(), **claims))
		self.assertEqual(self.iam.calls, 0)

		self._authenticate(self.iam.issue(self._sub(), azp="staff-portal"))
		self.assertEqual(self.iam.calls, 1)

	def test_expired_token_is_refused_without_iam_call(self):
		token = self.iam.issue(self._sub(), exp=int(datetime.now(UTC).timestamp()) - 60)
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(token)
		self.assertEqual(self.iam.calls, 0)

	def test_me_reports_login_option_and_cookie_prefix(self):
		from oan_auth_service.api.v1.auth import get_me

		self._authenticate(self.iam.issue(self._sub(AGENT), iss=AGENT_ISS, base_url=AGENT_URL))
		data = get_me()["data"]
		self.assertEqual((data["login_option"], data["cookie_prefix"]), (AGENT, "agent-"))

		# A session picked up from cookies alone, as after signing in through another OpenG2P UI.
		self._authenticate_cookies({"X-Access-Token": self.iam.issue(self._sub())})
		data = get_me()["data"]
		self.assertEqual((data["login_option"], data["cookie_prefix"]), (STAFF, ""))

	def test_me_reports_local_for_own_tokens(self):
		from oan_auth_service.api import tokens
		from oan_auth_service.api.v1.auth import get_me

		with configured_keys():
			own, _ = tokens.issue_access_token("Administrator", ["System Manager"])
		self._authenticate_cookies({"X-Access-Token": own})
		data = get_me()["data"]
		self.assertEqual((data["login_option"], data["cookie_prefix"]), ("local", None))

	def test_principal_is_cached_per_token(self):
		token = self.iam.issue(self._sub())
		self._authenticate(token)
		self._authenticate(token)
		self.assertEqual(self.iam.calls, 1)

	def test_token_iam_rejects_is_rejected(self):
		unknown = jwt.encode({"iss": STAFF_ISS, "sub": "x"}, "k", algorithm="HS256")
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(unknown)

	def test_malformed_iam_200_is_rejected_not_500(self):
		for payload in (ValueError("not json"), [], "ok", None):
			sub = self._sub()
			token = self.iam.issue(sub)
			self.iam.override = _Response(200, payload)
			with self.assertRaises(frappe.AuthenticationError):
				self._authenticate(token)
			self.assertFalse(frappe.db.exists("User", iam_users.user_name_for_sub(sub, STAFF)))

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

	def test_http_iam_url_rejected_and_logged_once(self):
		frappe.cache.delete_value("oan_auth:iam_insecure_url_logged")
		with patch("oan_auth_service.api.iam_tokens.frappe.log_error") as log_error:
			for _ in range(3):
				with self.assertRaises(TokenError):
					iam_tokens._require_https("http://iam.cluster.local")
			self.assertEqual(log_error.call_count, 1)
		# Loopback stays allowed for local development; there is no other opt-out.
		iam_tokens._require_https("http://localhost:8020")

	# -- cookies --------------------------------------------------------------

	def test_cookie_session_authenticates_get_without_bearer(self):
		sub = self._sub()
		token = self.iam.issue(sub, {APP: [OFFICER]})
		user = self._authenticate_cookies({"X-Access-Token": token})
		self.assertEqual(user, iam_users.user_name_for_sub(sub, STAFF))
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

	def test_cookie_names_follow_row_prefix(self):
		# Mirrors iam_core: the prefix applies to every auth cookie, never the CSRF header.
		sub = self._sub(AGENT)
		token = self.iam.issue(sub, iss=AGENT_ISS, base_url=AGENT_URL)

		# A cookie under a prefix no row uses is not seen at all (the health path is exempt).
		self.assertEqual(self._authenticate_cookies({"other-X-Access-Token": token}), "Guest")
		# The CSRF cookie must carry the same prefix as the access cookie.
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate_cookies(
				{"agent-X-Access-Token": token, "X-CSRF-Token": "abc"},
				method="POST",
				headers={"X-CSRF-Token": "abc"},
				protected=True,
			)
		user = self._authenticate_cookies(
			{"agent-X-Access-Token": token, "agent-X-CSRF-Token": "abc"},
			method="POST",
			headers={"X-CSRF-Token": "abc"},
		)
		self.assertEqual(user, iam_users.user_name_for_sub(sub, AGENT))

	def test_first_cookie_in_sort_order_wins(self):
		staff_sub = self._sub(STAFF)
		staff = self.iam.issue(staff_sub)
		agent = self.iam.issue(self._sub(AGENT), iss=AGENT_ISS, base_url=AGENT_URL)
		user = self._authenticate_cookies({"agent-X-Access-Token": agent, "X-Access-Token": staff})
		self.assertEqual(user, iam_users.user_name_for_sub(staff_sub, STAFF))

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
		self._authenticate(token, method="POST")

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

	# -- login hook -----------------------------------------------------------

	HOOK = f"{__name__}.recording_hook"
	SECOND_HOOK = f"{__name__}.second_hook"

	def test_login_hook_runs_once_per_token(self):
		sub = self._sub()
		token = self.iam.issue(sub)
		user = self._authenticate(token, hooks=[self.HOOK])
		self._authenticate(token, hooks=[self.HOOK])
		self.assertEqual(len(HOOK_CALLS), 1)
		_name, hook_user, principal, login_option = HOOK_CALLS[0]
		self.assertEqual(hook_user, user)
		self.assertEqual(login_option, STAFF)
		self.assertEqual(principal, self.iam.principals[token][1])

		# A new token runs it again.
		self._authenticate(self.iam.issue(sub), hooks=[self.HOOK])
		self.assertEqual(len(HOOK_CALLS), 2)

	def test_login_hook_runs_again_after_failure(self):
		token = self.iam.issue(self._sub())
		HOOK_BEHAVIOUR["raise"] = RuntimeError("registry down")
		with (
			patch("oan_auth_service.api.iam_users.frappe.log_error") as log_error,
			self.assertRaises(frappe.ServiceUnavailableError),
		):
			self._authenticate(token, hooks=[self.HOOK])
		hook_logs = [
			c for c in log_error.call_args_list if iam_users.LOGIN_HOOK in (c.kwargs.get("title") or "")
		]
		self.assertEqual(len(hook_logs), 1)
		self.assertTrue(hook_logs[0].kwargs["defer_insert"])
		self.assertEqual(frappe.session.user, "Guest")

		HOOK_BEHAVIOUR["raise"] = None
		self._authenticate(token, hooks=[self.HOOK])
		self.assertEqual(len(HOOK_CALLS), 2)

	def test_login_denied_is_403_and_commits_nothing(self):
		sub = self._sub()
		HOOK_BEHAVIOUR["raise"] = iam_users.LoginDenied("Not in the farmer registry")
		with patch("frappe.db.commit") as commit, self.assertRaises(frappe.PermissionError):
			self._authenticate(self.iam.issue(sub), hooks=[self.HOOK])
		commit.assert_not_called()
		self.assertEqual(frappe.local.response["message"], "Not in the farmer registry")
		self.assertFalse(frappe.db.exists("User", iam_users.user_name_for_sub(sub, STAFF)))

	def test_login_hook_change_commits_on_get(self):
		token = self.iam.issue(self._sub())
		self._authenticate(token)  # user exists, no change left to commit
		HOOK_BEHAVIOUR["return"] = True
		with patch("frappe.db.commit") as commit:
			self._authenticate(self.iam.issue(self.iam.principals[token][1]["sub"]), hooks=[self.HOOK])
		commit.assert_called_once()

	def test_all_login_hooks_run(self):
		self._authenticate(self.iam.issue(self._sub()), hooks=[self.HOOK, self.SECOND_HOOK])
		self.assertEqual([c[0] for c in HOOK_CALLS], ["first", "second"])
