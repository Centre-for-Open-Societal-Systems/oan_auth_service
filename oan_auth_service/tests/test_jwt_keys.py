"""Key resolution and rotation."""

import unittest

from oan_auth_service.api import jwt_keys
from oan_auth_service.tests.utils import TEST_SECRETS, configured_keys, override_conf


class TestSigningKey(unittest.TestCase):
	def test_signs_with_the_current_kid(self):
		with configured_keys(current_kid="v2"):
			kid, secret = jwt_keys.get_signing_key()

		self.assertEqual(kid, "v2")
		self.assertEqual(secret, TEST_SECRETS["v2"])

	def test_falls_back_to_v1_when_no_current_kid_is_set(self):
		with override_conf(jwt_secrets=dict(TEST_SECRETS), jwt_current_kid=None):
			kid, _secret = jwt_keys.get_signing_key()

		self.assertEqual(kid, jwt_keys.FALLBACK_KID)

	def test_missing_key_material_is_a_configuration_error(self):
		with override_conf(jwt_secrets=None):
			with self.assertRaises(jwt_keys.JWTKeyConfigurationError):
				jwt_keys.get_signing_key()

	def test_current_kid_naming_an_absent_secret_is_a_configuration_error(self):
		"""Pointing the site at a key that was never added must fail loudly.

		Silently falling back to another key would mint tokens under a kid the
		operator did not choose, which is the one thing rotation must never do.
		"""
		with override_conf(jwt_secrets=dict(TEST_SECRETS), jwt_current_kid="v9"):
			with self.assertRaises(jwt_keys.JWTKeyConfigurationError):
				jwt_keys.get_signing_key()

	def test_secrets_as_a_bare_string_is_rejected(self):
		with override_conf(jwt_secrets="a-single-secret-with-no-kid-at-all"):
			with self.assertRaises(jwt_keys.JWTKeyConfigurationError):
				jwt_keys.get_signing_key()

	def test_short_secret_is_refused_at_signing_time(self):
		with override_conf(jwt_secrets={"v1": "too-short"}, jwt_current_kid="v1"):
			with self.assertRaises(jwt_keys.JWTKeyConfigurationError):
				jwt_keys.get_signing_key()


class TestVerificationKey(unittest.TestCase):
	def test_returns_the_secret_for_a_known_kid(self):
		with configured_keys():
			self.assertEqual(jwt_keys.get_verification_key("v1"), TEST_SECRETS["v1"])

	def test_retired_kid_still_verifies_while_listed(self):
		"""The whole point of the kid map: v1 keeps verifying after v2 takes over."""
		with configured_keys(current_kid="v2"):
			self.assertEqual(jwt_keys.get_verification_key("v1"), TEST_SECRETS["v1"])

	def test_unknown_kid_returns_none(self):
		with configured_keys():
			self.assertIsNone(jwt_keys.get_verification_key("v9"))

	def test_absent_kid_returns_none_rather_than_defaulting(self):
		"""A token with no kid must not pick up the current key by default.

		Defaulting would let an attacker strip the header and still land on a
		valid signature check.
		"""
		with configured_keys():
			self.assertIsNone(jwt_keys.get_verification_key(None))

	def test_short_legacy_secret_still_verifies(self):
		"""The length floor applies to signing only.

		Enforcing it on verification would retroactively invalidate every token
		already issued under a short key.
		"""
		with override_conf(jwt_secrets={"v1": "short"}, jwt_current_kid="v1"):
			self.assertEqual(jwt_keys.get_verification_key("v1"), "short")
