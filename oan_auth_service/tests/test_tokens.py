"""The token codec: what it accepts, and what it must refuse."""

import unittest
from datetime import UTC, datetime, timedelta

import jwt as pyjwt

from oan_auth_service.api import tokens
from oan_auth_service.tests.utils import TEST_SECRETS, configured_keys, override_conf


def _encode(claims: dict, kid: str = "v1", secret: str | None = None) -> str:
	"""Hand-roll a token so tests can produce ones the codec would never mint."""
	return pyjwt.encode(
		claims,
		secret or TEST_SECRETS[kid],
		algorithm=tokens.ALGORITHM,
		headers={"kid": kid},
	)


def _valid_claims(**overrides) -> dict:
	now = datetime.now(UTC)
	claims = {
		"iss": "test-issuer",
		"sub": "someone@example.com",
		"iat": now,
		"exp": now + timedelta(minutes=15),
		"typ": tokens.ACCESS_TOKEN_TYPE,
		"roles": [],
	}
	claims.update(overrides)
	return claims


class TestAccessTokenRoundTrip(unittest.TestCase):
	def test_issued_token_decodes_to_its_claims(self):
		with configured_keys():
			token, ttl = tokens.issue_access_token("a@example.com", ["Bank Agent"])
			claims = tokens.decode_access_token(token)

		self.assertEqual(claims["sub"], "a@example.com")
		self.assertEqual(claims["roles"], ["Bank Agent"])
		self.assertEqual(claims["typ"], tokens.ACCESS_TOKEN_TYPE)
		self.assertEqual(claims["iss"], "test-issuer")
		self.assertEqual(ttl, 15 * 60)

	def test_token_carries_the_signing_kid_in_its_header(self):
		with configured_keys(current_kid="v2"):
			token, _ = tokens.issue_access_token("a@example.com", [])

		self.assertEqual(pyjwt.get_unverified_header(token)["kid"], "v2")

	def test_scope_is_omitted_entirely_when_not_requested(self):
		"""Absent, not null. A consumer branching on presence must see a difference."""
		with configured_keys():
			token, _ = tokens.issue_access_token("a@example.com", ["X"])
			claims = tokens.decode_access_token(token)

		self.assertNotIn("scope", claims)

	def test_scope_survives_the_round_trip(self):
		with configured_keys():
			token, _ = tokens.issue_access_token("a@example.com", ["X", "Y"], scope=["X"])
			claims = tokens.decode_access_token(token)

		self.assertEqual(claims["scope"], ["X"])
		self.assertEqual(claims["roles"], ["X", "Y"])

	def test_each_token_gets_a_distinct_jti(self):
		with configured_keys():
			first, _ = tokens.issue_access_token("a@example.com", [])
			second, _ = tokens.issue_access_token("a@example.com", [])

			self.assertNotEqual(
				tokens.decode_access_token(first)["jti"],
				tokens.decode_access_token(second)["jti"],
			)

	def test_ttl_follows_configuration(self):
		with configured_keys(), override_conf(jwt_access_token_ttl=60):
			_token, ttl = tokens.issue_access_token("a@example.com", [])

		self.assertEqual(ttl, 60)


class TestAccessTokenRejection(unittest.TestCase):
	def assert_rejected(self, token):
		with self.assertRaises(tokens.TokenError):
			tokens.decode_access_token(token)

	def test_empty_token(self):
		with configured_keys():
			self.assert_rejected("")
			self.assert_rejected(None)

	def test_garbage(self):
		with configured_keys():
			self.assert_rejected("not-a-jwt")

	def test_tampered_payload(self):
		"""Flipping a claim must break the signature."""
		with configured_keys():
			token, _ = tokens.issue_access_token("a@example.com", ["Viewer"])
			header, _payload, signature = token.split(".")
			forged, _ = tokens.issue_access_token("a@example.com", ["Administrator"])
			swapped_payload = forged.split(".")[1]

			self.assert_rejected(f"{header}.{swapped_payload}.{signature}")

	def test_expired_token(self):
		with configured_keys():
			past = datetime.now(UTC) - timedelta(hours=1)
			self.assert_rejected(_encode(_valid_claims(iat=past, exp=past + timedelta(minutes=1))))

	def test_signed_with_a_key_we_do_not_hold(self):
		with configured_keys():
			self.assert_rejected(_encode(_valid_claims(), secret="an-entirely-different-secret-value"))

	def test_unknown_kid(self):
		with configured_keys():
			token = pyjwt.encode(
				_valid_claims(), TEST_SECRETS["v1"], algorithm=tokens.ALGORITHM, headers={"kid": "v9"}
			)
			self.assert_rejected(token)

	def test_no_kid_header(self):
		with configured_keys():
			token = pyjwt.encode(_valid_claims(), TEST_SECRETS["v1"], algorithm=tokens.ALGORITHM)
			self.assert_rejected(token)

	def test_issuer_mismatch(self):
		"""A token from another deployment must not verify here."""
		with configured_keys():
			self.assert_rejected(_encode(_valid_claims(iss="some-other-site")))

	def test_wrong_token_type(self):
		"""A JWT signed with the same key for another purpose is not an access token."""
		with configured_keys():
			self.assert_rejected(_encode(_valid_claims(typ="password-reset")))

	def test_missing_required_claims(self):
		with configured_keys():
			claims = _valid_claims()
			del claims["sub"]
			self.assert_rejected(_encode(claims))

	def test_alg_none_is_refused(self):
		"""The classic JWT forgery: strip the signature, claim it was intended."""
		with configured_keys():
			token = pyjwt.encode(_valid_claims(), key="", algorithm="none", headers={"kid": "v1"})
			self.assert_rejected(token)


class TestRefreshTokens(unittest.TestCase):
	def test_generated_tokens_are_unique(self):
		self.assertNotEqual(tokens.generate_refresh_token(), tokens.generate_refresh_token())

	def test_hash_is_stable_and_hex(self):
		token = tokens.generate_refresh_token()
		digest = tokens.hash_refresh_token(token)

		self.assertEqual(digest, tokens.hash_refresh_token(token))
		self.assertEqual(len(digest), 64)
		self.assertNotIn(token, digest)

	def test_distinct_tokens_hash_differently(self):
		self.assertNotEqual(
			tokens.hash_refresh_token(tokens.generate_refresh_token()),
			tokens.hash_refresh_token(tokens.generate_refresh_token()),
		)
