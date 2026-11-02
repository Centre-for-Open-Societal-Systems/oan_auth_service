"""Tests for the login option endpoints: `/api/v1/auth/iam/{providers,login,logout}`.

IAM and the identity provider are faked at the HTTP boundary.
"""

import json
import time
import unittest
from unittest.mock import patch

import frappe
import jwt
import requests
from urllib3 import HTTPHeaderDict
from werkzeug.datastructures import Headers

from oan_auth_service.api.router import ensure_routes_registered
from oan_auth_service.config import settings
from oan_auth_service.tests.test_router import make_test_request
from oan_auth_service.tests.utils import configured_keys, delete_iam_service, ensure_role, make_iam_service

STAFF = "t-staff"
AGENT = "t-agent"
OFF = "t-off"
STAFF_URL = "https://staff-iam.test"
AGENT_URL = "https://agent-iam.test"
UI = "https://ui.test"
ROLE = "IAM Discovery Test Role"
IDP_LOGIN = "https://kc.test/realms/staff/protocol/openid-connect/auth?client_id=x"
IDP_LOGOUT = "https://kc.test/realms/agent/protocol/openid-connect/logout?id_token_hint=abc"
CLEAR_ACCESS = "agent-X-Access-Token=; Domain=.example.test; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
NEW_ACCESS = "agent-X-Access-Token=new-access; Domain=.example.test; Path=/; HttpOnly; Secure"
NEW_SESSION = "agent-X-Session-Id=new-session; Domain=.example.test; Path=/; HttpOnly; Secure"
CLEAR_SESSION = "agent-X-Session-Id=; Domain=.example.test; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"

STAFF_ISS = "https://kc.test/realms/staff"
AGENT_ISS = "https://kc.test/realms/agent"
OFF_ISS = "https://kc.test/realms/off"
# `jwt_issuer` set by `configured_keys`: this app's own tokens.
OWN_ISS = "test-issuer"


def iam_token(iss: str, **claims) -> str:
	"""An access token from `iss`, already expired: refresh and logout must still route it."""
	payload = {"iss": iss, "sub": "x", "exp": int(time.time()) - 60, **claims}
	return jwt.encode(payload, "idp-secret", algorithm="HS256")


AGENT_COOKIES = {
	"agent-X-Access-Token": "access",
	"agent-X-ID-Token": "id",
	"agent-X-Session-Id": "session",
	"X-Access-Token": "staff-access",
	"agent-X-CSRF-Token": "csrf",
}


class _Response:
	def __init__(self, status_code, payload=None, headers=None):
		self.status_code = status_code
		self._payload = payload
		self.headers = HTTPHeaderDict(headers or [])
		self.raw = type("Raw", (), {"headers": self.headers})()

	def json(self):
		if isinstance(self._payload, Exception):
			raise self._payload
		return self._payload


class FakeIAM:
	def __init__(self):
		self.calls = []
		self.login_response = _Response(200, {"redirectUrl": IDP_LOGIN})
		self.logout_response = _Response(
			302,
			headers=[("Location", IDP_LOGOUT), ("Set-Cookie", CLEAR_ACCESS), ("Set-Cookie", CLEAR_SESSION)],
		)
		self.provider_response = _Response(200)
		self.profile_response = _Response(
			200, {"sub": "x"}, headers=[("Set-Cookie", NEW_ACCESS), ("Set-Cookie", NEW_SESSION)]
		)
		self.post_logout_response = _Response(405)
		self.down = False

	def post(self, url, params=None, **kwargs):
		self.calls.append(("POST", url, params, kwargs))
		if self.down:
			raise requests.ConnectionError("IAM down")
		if url.endswith("/auth/logout"):
			return self.post_logout_response
		return self.login_response

	def get(self, url, cookies=None, **kwargs):
		self.calls.append(("GET", url, cookies, kwargs))
		if url == IDP_LOGOUT:
			if isinstance(self.provider_response, Exception):
				raise self.provider_response
			return self.provider_response
		if self.down:
			raise requests.ConnectionError("IAM down")
		if url.endswith("/auth/get_user_profile"):
			return self.profile_response
		if url.endswith("/auth/get_logged_in_user"):
			return _Response(404, {})
		return self.logout_response


class TestIAMLoginDiscovery(unittest.TestCase):
	def setUp(self):
		ensure_routes_registered()
		ensure_role(ROLE)
		make_iam_service(
			STAFF,
			label="Sign in with Staff SSO",
			icon="/files/staff.png",
			sort_order=-20,
			base_url=STAFF_URL,
			provider_id=1,
			issuer=STAFF_ISS,
			client_id="staff-portal",
			application="staff-app",
			default_roles=[ROLE],
			return_origins=[UI],
		)
		make_iam_service(
			AGENT,
			label="Sign in as field agent",
			sort_order=-10,
			base_url=AGENT_URL,
			provider_id=10,
			issuer=AGENT_ISS,
			application="agent-app",
			cookie_prefix="agent-",
			return_origins=[UI],
		)
		make_iam_service(
			OFF,
			enabled=0,
			base_url=STAFF_URL,
			provider_id=2,
			issuer=OFF_ISS,
			application="off-app",
			return_origins=[UI],
		)
		self.iam = FakeIAM()
		frappe.local.response_headers = Headers()
		frappe.cache.delete_keys("oan_auth:iam_")

	def tearDown(self):
		for key in (STAFF, AGENT, OFF):
			delete_iam_service(key)
		frappe.set_user("Administrator")

	def call(self, path, method="GET", data=None, cookies=None):
		import frappe.api

		env = {"HTTP_COOKIE": "; ".join(f"{k}={v}" for k, v in (cookies or {}).items())} if cookies else None
		with (
			configured_keys(),
			patch("oan_auth_service.api.iam_tokens.requests.post", side_effect=self.iam.post),
			patch("oan_auth_service.api.iam_tokens.requests.get", side_effect=self.iam.get),
		):
			frappe.set_user("Guest")
			res = frappe.api.handle(make_test_request(path, method=method, data=data, environ_base=env))
		return res.status_code, json.loads(res.get_data(as_text=True))

	def login(self, key=STAFF, return_url=f"{UI}/api/auth/iam/complete?key=t-staff&returnUrl=/inbox"):
		return self.call("/api/v1/auth/iam/login", "POST", {"key": key, "return_url": return_url})

	# -- providers ------------------------------------------------------------

	def test_providers_lists_enabled_rows_in_order_with_display_fields_only(self):
		status, body = self.call("/api/v1/auth/iam/providers")
		self.assertEqual(status, 200, body)
		ours = [p for p in body["data"]["providers"] if p["key"] in (STAFF, AGENT, OFF)]
		self.assertEqual(
			ours,
			[
				{"key": STAFF, "label": "Sign in with Staff SSO", "icon_url": "/files/staff.png"},
				{"key": AGENT, "label": "Sign in as field agent", "icon_url": ""},
			],
		)
		for provider in body["data"]["providers"]:
			self.assertEqual(set(provider), {"key", "label", "icon_url"})
		self.assertEqual(self.iam.calls, [])

	def test_providers_includes_local_row(self):
		existed = frappe.db.exists("OAN IAM Service", settings.LOCAL_LOGIN_KEY)
		if not existed:
			make_iam_service(settings.LOCAL_LOGIN_KEY, label="Sign in", sort_order=-30)
			self.addCleanup(delete_iam_service, settings.LOCAL_LOGIN_KEY)
		status, body = self.call("/api/v1/auth/iam/providers")
		self.assertEqual(status, 200, body)
		self.assertIn(settings.LOCAL_LOGIN_KEY, [p["key"] for p in body["data"]["providers"]])

	# -- login ----------------------------------------------------------------

	def test_login_returns_iam_redirect(self):
		return_url = f"{UI}/api/auth/iam/complete?key=t-agent"
		status, body = self.login(AGENT, return_url)
		self.assertEqual(status, 200, body)
		self.assertEqual(body["data"], {"redirect_url": IDP_LOGIN, "iam": AGENT, "cookie_prefix": "agent-"})
		method, url, params, kwargs = self.iam.calls[0]
		self.assertEqual((method, url), ("POST", f"{AGENT_URL}/auth/start_authentication_transaction"))
		self.assertEqual(params, {"id": 10, "redirect_uri": return_url})
		self.assertFalse(kwargs["allow_redirects"])

	def test_unknown_disabled_or_local_key_is_400_without_iam_call(self):
		for key in ("t-nope", OFF, settings.LOCAL_LOGIN_KEY):
			status, body = self.login(key)
			self.assertEqual(status, 400, (key, body))
		self.assertEqual(self.iam.calls, [])

	def test_malformed_return_url_is_400_without_iam_call(self):
		for return_url in (
			"/relative/path",
			"https://evil.test\\@ui.test/x",
			"https://user@ui.test/x",
			"javascript:alert(1)",
			"https://evil.test:99999/x",
		):
			status, body = self.login(return_url=return_url)
			self.assertEqual(status, 400, (return_url, body))
		self.assertEqual(self.iam.calls, [])

	def test_return_url_with_default_port_is_same_origin(self):
		status, body = self.login(return_url="https://ui.test:443/x")
		self.assertEqual(status, 200, body)

	def test_non_http_redirect_from_iam_is_refused(self):
		for payload in ({"redirectUrl": "javascript:alert(1)"}, {}, [], ValueError("not json")):
			self.iam.login_response = _Response(200, payload)
			status, body = self.login()
			self.assertEqual(status, 502, body)
			self.assertEqual(body["code"], "BAD_GATEWAY")

	def test_iam_4xx_is_502_with_iam_body_in_details(self):
		self.iam.login_response = _Response(404, {"detail": "no such provider"})
		status, body = self.login()
		self.assertEqual(status, 502)
		self.assertEqual(body["code"], "BAD_GATEWAY")
		self.assertEqual(body["details"], {"upstream": {"detail": "no such provider"}})

	def test_iam_5xx_or_unreachable_is_503(self):
		self.iam.login_response = _Response(500, {})
		status, body = self.login()
		self.assertEqual(status, 503, body)
		self.assertEqual(body["code"], "SERVICE_UNAVAILABLE")

		self.iam.down = True
		status, _body = self.login()
		self.assertEqual(status, 503)

	def test_login_validates_body(self):
		status, _body = self.call("/api/v1/auth/iam/login", "POST", {"key": STAFF})
		self.assertEqual(status, 400)

	def test_login_defaults_when_only_one_iam_service_enabled(self):
		# Temporarily disable any other enabled IAM service so only STAFF remains
		other_services = frappe.get_all(
			"OAN IAM Service",
			filters={"enabled": 1, "name": ("!=", STAFF)},
			pluck="name",
		)
		for name in other_services:
			frappe.db.set_value("OAN IAM Service", name, "enabled", 0)
		frappe.db.commit()  # nosemgrep: frappe-manual-commit
		settings.clear_iam_services_cache()

		try:
			# GET /api/v1/auth/iam/providers reports default_provider
			status, body = self.call("/api/v1/auth/iam/providers")
			self.assertEqual(status, 200, body)
			self.assertEqual(body["data"]["default_provider"], STAFF)

			# POST /api/v1/auth/iam/login without key defaults to STAFF
			return_url = f"{UI}/api/auth/iam/complete?key=t-staff"
			status, body = self.call("/api/v1/auth/iam/login", "POST", {"return_url": return_url})
			self.assertEqual(status, 200, body)
			self.assertEqual(body["data"]["iam"], STAFF)

			# POST with key="default" also defaults to STAFF
			status, body = self.call(
				"/api/v1/auth/iam/login", "POST", {"key": "default", "return_url": return_url}
			)
			self.assertEqual(status, 200, body)
			self.assertEqual(body["data"]["iam"], STAFF)
		finally:
			for name in other_services:
				frappe.db.set_value("OAN IAM Service", name, "enabled", 1)
			frappe.db.commit()  # nosemgrep: frappe-manual-commit
			settings.clear_iam_services_cache()

	def test_login_omitting_key_fails_when_multiple_services_enabled(self):
		return_url = f"{UI}/api/auth/iam/complete"
		status, body = self.call("/api/v1/auth/iam/login", "POST", {"return_url": return_url})
		self.assertEqual(status, 400, body)
		self.assertIn("Multiple login options exist", body["message"])

	# -- logout ---------------------------------------------------------------

	def logout(self, iss=AGENT_ISS, cookies=None, body=None, **claims):
		return self.call(
			"/api/v1/auth/logout",
			"POST",
			body or {"access_token": iam_token(iss, **claims)},
			cookies=AGENT_COOKIES if cookies is None else cookies,
		)

	def test_logout_ends_iam_and_provider_session(self):
		status, body = self.logout()
		self.assertEqual(status, 200, body)
		self.assertEqual(body["data"], {"logged_out": True, "provider_logout": True})

		method, url, cookies, kwargs = self.iam.calls[0]
		self.assertEqual((method, url), ("GET", f"{AGENT_URL}/auth/logout"))
		# Only this option's session cookies, never another option's or the CSRF cookie.
		self.assertEqual(
			cookies,
			{"agent-X-Access-Token": "access", "agent-X-ID-Token": "id", "agent-X-Session-Id": "session"},
		)
		self.assertFalse(kwargs["allow_redirects"])
		self.assertEqual(self.iam.calls[1][:2], ("GET", IDP_LOGOUT))
		self.assertEqual(frappe.local.response_headers.getlist("Set-Cookie"), [CLEAR_ACCESS, CLEAR_SESSION])

	def test_logout_routes_by_issuer(self):
		# The staff token picks the staff IAM and its unprefixed cookies, even
		# though the browser also holds the agent option's cookies.
		status, body = self.logout(iss=STAFF_ISS, azp="staff-portal")
		self.assertEqual(status, 200, body)
		method, url, cookies, _kwargs = self.iam.calls[0]
		self.assertEqual((method, url), ("GET", f"{STAFF_URL}/auth/logout"))
		self.assertEqual(cookies, {"X-Access-Token": "staff-access"})

	def test_provider_logout_failure_returns_logout_url(self):
		for failure in (_Response(500), requests.ConnectionError("down")):
			frappe.local.response_headers = Headers()
			self.iam.provider_response = failure
			status, body = self.logout()
			self.assertEqual(status, 200, body)
			self.assertEqual(
				body["data"], {"logged_out": True, "provider_logout": False, "logout_url": IDP_LOGOUT}
			)
			self.assertEqual(len(frappe.local.response_headers.getlist("Set-Cookie")), 2)

	def test_logout_retries_as_post_when_iam_logs_out_on_post_only(self):
		# The beneficiary IAM: no GET /auth/logout, and a POST that clears its
		# cookies and answers 200 with no provider redirect.
		self.iam.logout_response = _Response(405)
		self.iam.post_logout_response = _Response(200, headers=[("Set-Cookie", CLEAR_ACCESS)])
		status, body = self.logout()
		self.assertEqual(status, 200, body)
		self.assertEqual(body["data"], {"logged_out": True, "provider_logout": False})

		self.assertEqual(
			[c[:2] for c in self.iam.calls],
			[("GET", f"{AGENT_URL}/auth/logout"), ("POST", f"{AGENT_URL}/auth/logout")],
		)
		self.assertEqual(
			self.iam.calls[1][3]["cookies"],
			{"agent-X-Access-Token": "access", "agent-X-ID-Token": "id", "agent-X-Session-Id": "session"},
		)
		self.assertEqual(frappe.local.response_headers.getlist("Set-Cookie"), [CLEAR_ACCESS])

	def test_iam_401_still_logs_out(self):
		self.iam.logout_response = _Response(401, {}, headers=[("Set-Cookie", CLEAR_ACCESS)])
		status, body = self.logout()
		self.assertEqual(status, 200, body)
		self.assertEqual(body["data"], {"logged_out": True, "provider_logout": False})
		self.assertEqual(frappe.local.response_headers.getlist("Set-Cookie"), [CLEAR_ACCESS])

	def test_logout_refuses_unknown_issuer_and_reports_iam_down(self):
		for iss in ("https://kc.test/realms/other", OFF_ISS):
			status, _body = self.logout(iss=iss)
			self.assertEqual(status, 401, iss)
		# A staff token without the row's client_id as azp.
		status, _body = self.logout(iss=STAFF_ISS)
		self.assertEqual(status, 401)
		self.assertEqual(self.iam.calls, [])

		self.iam.down = True
		status, _body = self.logout()
		self.assertEqual(status, 503)

	def test_local_logout_still_takes_refresh_token(self):
		status, body = self.logout(body={"refresh_token": "not-a-live-token"})
		self.assertEqual(status, 200, body)
		self.assertEqual(body["data"], {"revoked": True})
		self.assertEqual(self.iam.calls, [])

	def test_session_credential_must_be_exactly_one(self):
		for path in ("/api/v1/auth/logout", "/api/v1/auth/refresh"):
			for body in ({}, {"refresh_token": "r", "access_token": iam_token(AGENT_ISS)}):
				status, _body = self.call(path, "POST", body)
				self.assertEqual(status, 400, (path, body))
			# Our own access token: sessions of this app go by refresh_token.
			status, _body = self.call(path, "POST", {"access_token": iam_token(OWN_ISS)})
			self.assertEqual(status, 400, path)
		self.assertEqual(self.iam.calls, [])

	# -- refresh --------------------------------------------------------------

	def refresh(self, iss=AGENT_ISS, cookies=None):
		return self.call(
			"/api/v1/auth/refresh",
			"POST",
			{"access_token": iam_token(iss)},
			cookies=AGENT_COOKIES if cookies is None else cookies,
		)

	def test_refresh_relays_new_cookies(self):
		status, body = self.refresh()
		self.assertEqual(status, 200, body)
		self.assertEqual(body["data"], {"refreshed": True})

		method, url, cookies, kwargs = self.iam.calls[0]
		self.assertEqual((method, url), ("GET", f"{AGENT_URL}/auth/get_user_profile"))
		# Only this option's session cookies, never another option's or the CSRF cookie.
		self.assertEqual(
			cookies,
			{"agent-X-Access-Token": "access", "agent-X-ID-Token": "id", "agent-X-Session-Id": "session"},
		)
		self.assertFalse(kwargs["allow_redirects"])
		self.assertEqual(frappe.local.response_headers.getlist("Set-Cookie"), [NEW_ACCESS, NEW_SESSION])

	def test_refresh_with_still_valid_token_sets_no_cookie(self):
		self.iam.profile_response = _Response(200, {"sub": "x"})
		status, body = self.refresh()
		self.assertEqual(status, 200, body)
		self.assertEqual(body["data"], {"refreshed": False})
		self.assertEqual(frappe.local.response_headers.getlist("Set-Cookie"), [])

	def test_refresh_of_ended_session_is_401_and_relays_clearing_cookies(self):
		self.iam.profile_response = _Response(401, {}, headers=[("Set-Cookie", CLEAR_ACCESS)])
		status, body = self.refresh()
		self.assertEqual(status, 401, body)
		self.assertEqual(body["code"], "AUTHENTICATION_ERROR")
		self.assertEqual(frappe.local.response_headers.getlist("Set-Cookie"), [CLEAR_ACCESS])

	def test_refresh_without_session_cookie_is_401_without_iam_call(self):
		status, _body = self.refresh(cookies={"agent-X-Access-Token": "access", "X-Session-Id": "staff"})
		self.assertEqual(status, 401)
		self.assertEqual(self.iam.calls, [])

	def test_refresh_refuses_unknown_issuer_and_reports_iam_errors(self):
		for iss in ("https://kc.test/realms/other", OFF_ISS):
			status, _body = self.refresh(iss)
			self.assertEqual(status, 401, iss)
		self.assertEqual(self.iam.calls, [])

		self.iam.down = True
		status, body = self.refresh()
		self.assertEqual(status, 503, body)

		self.iam.down = False
		self.iam.profile_response = _Response(404, {})
		status, _body = self.refresh()
		self.assertEqual(status, 502)
