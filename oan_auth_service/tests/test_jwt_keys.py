"""Key resolution and rotation."""

import os
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from oan_auth_service.api import jwt_keys
from oan_auth_service.tests.utils import TEST_PRIVATE_KEYS, configured_keys, generate_rsa_pem, override_conf


def _public_numbers_of(pem: str):
	key = serialization.load_pem_private_key(pem.encode(), password=None)
	return key.public_key().public_numbers()


class TestSigningKey(unittest.TestCase):
	def test_signs_with_the_current_kid(self):
		with configured_keys(current_kid="v2"):
			kid, key = jwt_keys.get_signing_key()

		self.assertEqual(kid, "v2")
		self.assertEqual(key.public_key().public_numbers(), _public_numbers_of(TEST_PRIVATE_KEYS["v2"]))

	def test_falls_back_to_v1_when_no_current_kid_is_set(self):
		with override_conf(jwt_private_keys=dict(TEST_PRIVATE_KEYS), jwt_current_kid=None):
			kid, _key = jwt_keys.get_signing_key()

		self.assertEqual(kid, jwt_keys.FALLBACK_KID)

	def test_missing_key_material_is_a_configuration_error(self):
		with override_conf(jwt_private_keys=None):
			with self.assertRaises(jwt_keys.JWTKeyConfigurationError):
				jwt_keys.get_signing_key()

	def test_current_kid_naming_an_absent_key_is_a_configuration_error(self):
		"""Pointing the site at a key that was never added must fail loudly.

		Silently falling back to another key would mint tokens under a kid the
		operator did not choose, which is the one thing rotation must never do.
		"""
		with override_conf(jwt_private_keys=dict(TEST_PRIVATE_KEYS), jwt_current_kid="v9"):
			with self.assertRaises(jwt_keys.JWTKeyConfigurationError):
				jwt_keys.get_signing_key()

	def test_keys_as_a_bare_string_is_rejected(self):
		with override_conf(jwt_private_keys=TEST_PRIVATE_KEYS["v1"]):
			with self.assertRaises(jwt_keys.JWTKeyConfigurationError):
				jwt_keys.get_signing_key()

	def test_short_rsa_key_is_refused(self):
		with override_conf(jwt_private_keys={"v1": generate_rsa_pem(1024)}, jwt_current_kid="v1"):
			with self.assertRaises(jwt_keys.JWTKeyConfigurationError):
				jwt_keys.get_signing_key()

	def test_non_rsa_key_is_refused(self):
		pem = (
			ec.generate_private_key(ec.SECP256R1())
			.private_bytes(
				serialization.Encoding.PEM,
				serialization.PrivateFormat.PKCS8,
				serialization.NoEncryption(),
			)
			.decode()
		)
		with override_conf(jwt_private_keys={"v1": pem}, jwt_current_kid="v1"):
			with self.assertRaises(jwt_keys.JWTKeyConfigurationError):
				jwt_keys.get_signing_key()

	def test_garbage_pem_is_a_configuration_error(self):
		with override_conf(jwt_private_keys={"v1": "-----BEGIN PRIVATE KEY-----\nnope\n"}):
			with self.assertRaises(jwt_keys.JWTKeyConfigurationError):
				jwt_keys.get_signing_key()

	def test_key_loads_from_a_file_path(self):
		with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
			f.write(TEST_PRIVATE_KEYS["v1"])
		try:
			with override_conf(jwt_private_keys={"v1": f.name}, jwt_current_kid="v1"):
				_kid, key = jwt_keys.get_signing_key()
		finally:
			os.unlink(f.name)

		self.assertEqual(key.public_key().public_numbers(), _public_numbers_of(TEST_PRIVATE_KEYS["v1"]))

	def test_missing_key_file_is_a_configuration_error(self):
		with override_conf(jwt_private_keys={"v1": "/nonexistent/jwt_v1.pem"}, jwt_current_kid="v1"):
			with self.assertRaises(jwt_keys.JWTKeyConfigurationError):
				jwt_keys.get_signing_key()


class TestVerificationKey(unittest.TestCase):
	def test_returns_the_public_key_for_a_known_kid(self):
		with configured_keys():
			key = jwt_keys.get_verification_key("v1")

		self.assertEqual(key.public_numbers(), _public_numbers_of(TEST_PRIVATE_KEYS["v1"]))

	def test_retired_kid_still_verifies_while_listed(self):
		"""The whole point of the kid map: v1 keeps verifying after v2 takes over."""
		with configured_keys(current_kid="v2"):
			self.assertIsNotNone(jwt_keys.get_verification_key("v1"))

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


class TestPublicJWKS(unittest.TestCase):
	def test_publishes_every_listed_kid(self):
		"""Retired kids stay published so cached verifiers can check older tokens."""
		with configured_keys(current_kid="v2"):
			jwks = jwt_keys.get_public_jwks()

		self.assertEqual([k["kid"] for k in jwks], ["v1", "v2"])
		for jwk in jwks:
			self.assertEqual((jwk["kty"], jwk["alg"], jwk["use"]), ("RSA", "RS256", "sig"))

	def test_never_leaks_private_components(self):
		with configured_keys():
			jwks = jwt_keys.get_public_jwks()

		for jwk in jwks:
			self.assertEqual(set(jwk) - {"kid", "kty", "alg", "use", "key_ops"}, {"n", "e"})
