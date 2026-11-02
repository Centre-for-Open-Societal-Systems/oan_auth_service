"""Tests for per-path authentication: each path takes exactly one scheme.

A JWT path takes only a JWT, an API-key path only a Frappe API key, a public
path nothing. Frappe's own API-key and `sid` auth run before the middleware, so
they are simulated by setting the session user and the Authorization header the
way Frappe leaves them.
"""

import unittest

import frappe

from oan_auth_service.api import middleware, tokens
from oan_auth_service.api.middleware import validate_jwt_request
from oan_auth_service.api.router import _resolve_auth, ensure_routes_registered
from oan_auth_service.tests.test_router import make_test_request
from oan_auth_service.tests.utils import cleanup_user, configured_keys, ensure_role, make_user

NS = "/api/v1/pathauth-test"
PUBLIC = f"{NS}/public"
PRIVATE = f"{NS}/private"
HOOK = f"{NS}/hook"
PARTNER = f"{NS}/partner/<bank_id>"
DUAL = f"{NS}/charts/<chart_id>"
PARTNER_ROLE = "Path Auth Partner"
REVOKED = set()


def revoke(user):
	return "revoked for the test" if user in REVOKED else None


class TestPathAuth(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		ensure_routes_registered()
		ensure_role(PARTNER_ROLE)
		middleware.register_namespace(
			NS,
			exempt_paths=[PUBLIC],
			api_key_paths={HOOK: [], PARTNER: [PARTNER_ROLE]},
			jwt_or_api_key_paths={DUAL: [PARTNER_ROLE]},
			revocation_check=revoke,
		)

	def setUp(self):
		self.partner = make_user("oan_pathauth_partner@example.com", "PartnerPass123!", roles=[PARTNER_ROLE])
		self.person = make_user("oan_pathauth_person@example.com", "PersonPass123!", roles=["System Manager"])
		REVOKED.clear()

	def tearDown(self):
		cleanup_user(self.partner)
		cleanup_user(self.person)
		frappe.set_user("Administrator")

	def run_hook(self, path, authorization=None, session_user="Guest"):
		"""Run the middleware as Frappe would, after its own auth set `session_user`."""
		headers = {"Authorization": authorization} if authorization else {}
		with configured_keys():
			req = make_test_request(path, method="GET", headers=headers)
			frappe.set_user("Guest")
			frappe.local.session = frappe._dict({"user": session_user, "sid": "test-sid"})
			validate_jwt_request(req)
		return frappe.session.user

	def jwt(self, user):
		with configured_keys():
			token, _ = tokens.issue_access_token(user, frappe.get_roles(user))
		return f"Bearer {token}"

	# -- API-key paths ----------------------------------------------------

	def test_api_key_on_api_key_path_passes(self):
		user = self.run_hook(HOOK, "token key:secret", session_user=self.partner)
		self.assertEqual(user, self.partner)
		self.assertEqual(frappe.local.oan_auth_issuer_kind, "api_key")

	def test_bearer_on_api_key_path_is_401(self):
		with self.assertRaises(frappe.AuthenticationError):
			self.run_hook(HOOK, self.jwt(self.partner))

	def test_no_credentials_on_api_key_path_is_401(self):
		with self.assertRaises(frappe.AuthenticationError):
			self.run_hook(HOOK)

	def test_desk_session_on_api_key_path_is_401(self):
		# A `sid` cookie sets the session user too; only the `token` scheme counts.
		with self.assertRaises(frappe.AuthenticationError):
			self.run_hook(HOOK, session_user=self.partner)

	def test_api_key_path_role_and_template(self):
		path = f"{NS}/partner/123"
		self.assertEqual(self.run_hook(path, "token k:s", session_user=self.partner), self.partner)
		# A person's key cannot reach a partner route that names a role.
		with self.assertRaises(frappe.AuthenticationError):
			self.run_hook(path, "token k:s", session_user=self.person)
		# One segment per parameter: a deeper path is not the partner route, so it is a JWT path.
		with self.assertRaises(frappe.AuthenticationError):
			self.run_hook(f"{path}/extra", "token k:s", session_user=self.partner)

	# -- JWT paths --------------------------------------------------------

	def test_bearer_on_jwt_path_passes(self):
		self.assertEqual(self.run_hook(PRIVATE, self.jwt(self.person)), self.person)

	def test_api_key_on_jwt_path_is_401(self):
		for scheme in ("token k:s", "Basic az0="):
			with self.assertRaises(frappe.AuthenticationError):
				self.run_hook(PRIVATE, scheme, session_user=self.person)

	def test_api_key_cannot_bypass_revocation_check(self):
		# The SSO rule a consumer enforces through revocation_check holds for
		# every way in: the JWT is refused, and an API key is not accepted instead.
		REVOKED.add(self.person)
		with self.assertRaises(frappe.AuthenticationError):
			self.run_hook(PRIVATE, self.jwt(self.person))
		with self.assertRaises(frappe.AuthenticationError):
			self.run_hook(PRIVATE, "token k:s", session_user=self.person)

	def test_desk_session_on_jwt_path_needs_a_jwt(self):
		with self.assertRaises(frappe.AuthenticationError):
			self.run_hook(PRIVATE, session_user=self.person)
		# With a JWT, the JWT's user is the request user, not the desk session's.
		self.assertEqual(
			self.run_hook(PRIVATE, self.jwt(self.partner), session_user=self.person), self.partner
		)

	# -- JWT-or-API-key paths (transitional) --------------------------------

	def test_dual_path_takes_jwt_or_api_key(self):
		path = f"{NS}/charts/grvKpis"
		self.assertEqual(self.run_hook(path, self.jwt(self.person)), self.person)
		self.assertEqual(self.run_hook(path, "token k:s", session_user=self.partner), self.partner)
		self.assertEqual(frappe.local.oan_auth_issuer_kind, "api_key")

	def test_dual_path_still_refuses_the_rest(self):
		path = f"{NS}/charts/grvKpis"
		# The API-key branch keeps its role check; roles do not apply to the JWT.
		with self.assertRaises(frappe.AuthenticationError):
			self.run_hook(path, "token k:s", session_user=self.person)
		for authorization, session_user in (
			(None, "Guest"),
			(None, self.person),
			("Basic az0=", self.person),
		):
			with self.assertRaises(frappe.AuthenticationError):
				self.run_hook(path, authorization, session_user=session_user)
		# The JWT branch keeps the consumer's revocation_check.
		REVOKED.add(self.person)
		with self.assertRaises(frappe.AuthenticationError):
			self.run_hook(path, self.jwt(self.person))

	def test_only_jwt_and_api_key_combine(self):
		self.assertEqual(
			_resolve_auth("/api/v1/z1", ("api_key", "jwt"), False, ["R"]), (("jwt", "api_key"), ("R",))
		)
		for auth in (("jwt", "public"), ("api_key", "public"), ("jwt", "api_key", "public")):
			with self.assertRaises(ValueError):
				_resolve_auth("/api/v1/z2", auth, False, None)

	# -- public paths -----------------------------------------------------

	def test_public_path_needs_nothing_and_keeps_frappe_session(self):
		self.assertEqual(self.run_hook(PUBLIC), "Guest")
		self.assertEqual(self.run_hook(PUBLIC, "token k:s", session_user=self.partner), self.partner)

	def test_unregistered_path_is_left_to_frappe(self):
		self.assertEqual(
			self.run_hook("/api/method/ping", "token k:s", session_user=self.person), self.person
		)

	# -- declaration ------------------------------------------------------

	def test_one_scheme_per_path(self):
		with self.assertRaises(ValueError):
			middleware.register_namespace(
				f"{NS}-clash", exempt_paths=["/api/v1/x"], api_key_paths=["/api/v1/x/"]
			)
		with self.assertRaises(ValueError):
			_resolve_auth("/api/v1/y", "api_key", True, None)
		with self.assertRaises(ValueError):
			_resolve_auth("/api/v1/y", "jwt", False, ["Some Role"])
		with self.assertRaises(ValueError):
			_resolve_auth("/api/v1/y", "anything", False, None)
		# A path already routed as public cannot be redeclared as JWT.
		with self.assertRaises(ValueError):
			_resolve_auth("/api/v1/auth/login", "jwt", False, None)

	def test_router_declares_auth_per_route(self):
		from oan_auth_service.tests.test_router import registered_routes

		by_path = {r["path"]: r for r in registered_routes()}
		self.assertEqual(by_path["/api/v1/auth/login"]["auth"], "public")
		self.assertEqual(by_path["/api/v1/auth/me"]["auth"], "jwt")
		self.assertEqual(
			middleware.path_auth(middleware._match_namespace("/api/v1/auth/me"), "/api/v1/auth/me")[0], "jwt"
		)
