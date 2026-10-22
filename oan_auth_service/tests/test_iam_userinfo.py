"""The identity provider's userinfo is merged into IAM's principal, for rows with a `userinfo_url`."""

import time
import unittest
from unittest.mock import MagicMock, patch

import frappe
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from oan_auth_service.api import iam_tokens
from oan_auth_service.config import settings
from oan_auth_service.tests.utils import delete_iam_service, ensure_role, make_iam_service

KEY = "t-userinfo"
IAM_URL = "https://bene-iam.test"
ISS = "https://esignet.test/v1/esignet"
USERINFO = "https://esignet.test/v1/esignet/oidc/userinfo"
JWKS = "https://esignet.test/v1/esignet/oauth/.well-known/jwks.json"
ROLE = "IAM Userinfo Test Role"


def _response(status=200, json_body=None, text=None, content_type="application/json"):
	response = MagicMock()
	response.status_code = status
	response.headers = {"Content-Type": content_type}
	response.json.return_value = json_body
	response.text = text if text is not None else ""
	return response


def _token(sub="psut-1"):
	return jwt.encode({"iss": ISS, "sub": sub, "exp": int(time.time()) + 600}, "idp", algorithm="HS256")


class TestIamUserinfo(unittest.TestCase):
	def setUp(self):
		ensure_role(ROLE)
		self.make_row(userinfo_url=USERINFO, jwks_url=JWKS)
		frappe.cache.delete_keys("oan_auth:iam_")
		self.addCleanup(delete_iam_service, KEY)

	def make_row(self, **fields):
		make_iam_service(KEY, base_url=IAM_URL, provider_id=1, issuer=ISS, default_roles=[ROLE], **fields)

	def principal(self, userinfo, token=None, iam_name="Token Name"):
		"""`get_principal` with IAM answering `{sub, name}` and the provider answering `userinfo`."""
		token = token or _token()
		iam = _response(json_body={"sub": "psut-1", "name": iam_name, "client_roles": {}})
		service = settings.iam_service(KEY)

		def get(url, **_kwargs):
			if url.endswith("/auth/get_user_profile"):
				return iam
			if url == USERINFO:
				if isinstance(userinfo, Exception):
					raise userinfo
				return userinfo
			raise AssertionError(url)

		with patch("oan_auth_service.api.iam_tokens.requests.get", side_effect=get) as mock_get:
			return iam_tokens.get_principal(token, service), mock_get

	def test_json_userinfo_adds_claims_but_never_replaces_the_token_subject(self):
		userinfo = _response(
			json_body={
				"sub": "psut-1",
				"individual_id": "1234567890123456",
				"phone_number": "+251911234503",
				"client_roles": {"x": ["System Manager"]},
				"name": "Provider Name",
			}
		)

		principal, _ = self.principal(userinfo)

		self.assertEqual(principal["individual_id"], "1234567890123456")
		self.assertEqual(principal["phone_number"], "+251911234503")
		self.assertEqual(principal["sub"], "psut-1")
		self.assertEqual(principal["client_roles"], {})
		# IAM's own answer wins on a name both gave.
		self.assertEqual(principal["name"], "Token Name")

	def test_an_empty_name_from_iam_does_not_hide_the_providers(self):
		userinfo = _response(json_body={"sub": "psut-1", "name": "Provider Name"})

		principal, _ = self.principal(userinfo, iam_name=None)

		self.assertEqual(principal["name"], "Provider Name")

	def test_userinfo_is_asked_once_per_token(self):
		userinfo = _response(json_body={"sub": "psut-1", "phone_number": "+251911234503"})
		token = _token()
		self.principal(userinfo, token)

		_, mock_get = self.principal(userinfo, token)

		self.assertEqual(mock_get.call_count, 0)

	def test_userinfo_for_another_subject_is_not_merged(self):
		userinfo = _response(json_body={"sub": "someone-else", "phone_number": "+251900000000"})

		principal, _ = self.principal(userinfo)

		self.assertNotIn("phone_number", principal)

	def test_failures_leave_the_principal_as_iam_gave_it(self):
		for failure in (
			_response(status=500),
			_response(status=401),
			_response(json_body=["not", "an", "object"]),
			ConnectionError("down"),
		):
			frappe.cache.delete_keys("oan_auth:iam_principal")
			principal, _ = self.principal(failure)
			self.assertEqual(principal["sub"], "psut-1", failure)
			self.assertNotIn("phone_number", principal)

	def test_a_row_without_userinfo_url_never_calls_the_provider(self):
		self.make_row()
		frappe.cache.delete_keys("oan_auth:iam_")

		principal, mock_get = self.principal(AssertionError("must not be called"))

		self.assertEqual(mock_get.call_count, 1)  # IAM only
		self.assertNotIn("phone_number", principal)

	def test_signed_userinfo_is_verified_against_the_provider_keys(self):
		private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		signed = jwt.encode(
			{"iss": ISS, "sub": "psut-1", "individual_id": "1234567890123456"}, private, algorithm="RS256"
		)
		signing_key = MagicMock()
		signing_key.key = private.public_key()

		with patch("oan_auth_service.api.iam_tokens.jwt.PyJWKClient") as client:
			client.return_value.get_signing_key_from_jwt.return_value = signing_key
			principal, _ = self.principal(_response(text=signed, content_type="application/jwt"))

		self.assertEqual(principal["individual_id"], "1234567890123456")

	def test_signed_userinfo_with_a_bad_signature_is_ignored(self):
		attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		provider = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		forged = jwt.encode(
			{"iss": ISS, "sub": "psut-1", "individual_id": "9999999999999999"}, attacker, algorithm="RS256"
		)
		signing_key = MagicMock()
		signing_key.key = provider.public_key()

		with patch("oan_auth_service.api.iam_tokens.jwt.PyJWKClient") as client:
			client.return_value.get_signing_key_from_jwt.return_value = signing_key
			principal, _ = self.principal(_response(text=forged, content_type="application/jwt"))

		self.assertNotIn("individual_id", principal)

	def test_signed_userinfo_without_a_keys_url_is_taken_as_received(self):
		self.make_row(userinfo_url=USERINFO)
		frappe.cache.delete_keys("oan_auth:iam_")
		signed = jwt.encode(
			{"iss": ISS, "sub": "psut-1", "individual_id": "1234567890123456"}, "any-key", algorithm="HS256"
		)

		principal, _ = self.principal(_response(text=signed, content_type="application/jwt"))

		self.assertEqual(principal["individual_id"], "1234567890123456")

	def test_row_refuses_a_plain_http_userinfo_url(self):
		with self.assertRaises(frappe.ValidationError):
			self.make_row(userinfo_url="http://esignet.example.org/userinfo")
