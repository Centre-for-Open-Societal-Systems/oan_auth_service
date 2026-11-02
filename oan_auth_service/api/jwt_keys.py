"""Resolution of the keys used to sign and verify access tokens.

Deliberately outside the versioned `api/v1/` namespace: `v1` versions the HTTP
contract clients depend on, while key resolution is internal. Rotating a key
must never require a new API version, and shipping `v2` endpoints must never
force a re-keying.

Tokens are signed RS256. Only this service holds a private key; every other
party (Kong, sibling apps) verifies with the public half, published as a JWKS
at `/api/v1/auth/keys`. Holding a verification key therefore no longer confers
the ability to mint, which is what a shared HS256 secret got wrong.

Keys are indexed by `kid` so rotation is possible: new tokens are signed with
the key `jwt_current_kid` names, while every key still listed in
`jwt_private_keys` is published and accepted on verification. A zero-downtime
rotation is therefore: add the new kid, wait for verifiers to pick up the JWKS,
point `jwt_current_kid` at it, then drop the old kid once the longest-lived
access token has expired.

Configuration (site_config.json):

    "jwt_private_keys": {"v1": "keys/jwt_v1.pem", "v2": "keys/jwt_v2.pem"},
    "jwt_current_kid": "v2"

Each value is a path to an unencrypted PEM private key — relative paths resolve
against the site directory — or the PEM text itself, for deployments that
inject secrets through the environment rather than as files. Generate one with:

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out jwt_v1.pem

The signing key is kept separate from `encryption_key` on purpose:
`encryption_key` is Frappe's Fernet key for data at rest and must stay stable
for the life of the site, whereas rotating a token-signing key is the response
to a suspected leak and has to be cheap. One value serving both roles makes the
cheap action inherit the expensive action's cost, which in practice means the
rotation never happens.
"""

import functools
import os

import frappe
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from jwt.algorithms import RSAAlgorithm

ALGORITHM = "RS256"

FALLBACK_KID = "v1"

# NIST SP 800-57 floor for RSA past 2030 is 3072; 2048 is the floor below which
# a key is refused outright.
MIN_KEY_BITS = 2048

PEM_PREFIX = "-----BEGIN"


class JWTKeyConfigurationError(Exception):
	"""The site has no usable JWT key material at all.

	Distinct from "this token names a kid we don't know": callers map the two to
	different responses so a server misconfiguration is not reported as a bad token.
	"""


def _key_sources() -> dict[str, str]:
	"""Return the configured kid -> PEM source map, or raise if unusable."""
	sources = frappe.conf.get("jwt_private_keys")

	if not sources:
		raise JWTKeyConfigurationError(
			"No `jwt_private_keys` in site_config.json. This app cannot mint or verify "
			"tokens until at least one RSA signing key is configured."
		)

	if not isinstance(sources, dict):
		raise JWTKeyConfigurationError(
			"`jwt_private_keys` must be a JSON object mapping kid -> PEM path, e.g. "
			'{"v1": "keys/jwt_v1.pem"}. A bare value is the shape of a single '
			"un-rotatable key, which is the situation the kid indirection exists to avoid."
		)

	return sources


def _read_pem(source: str) -> bytes:
	if source.lstrip().startswith(PEM_PREFIX):
		return source.encode()

	path = source if os.path.isabs(source) else frappe.get_site_path(source)
	try:
		with open(path, "rb") as f:  # nosemgrep
			return f.read()
	except OSError as e:
		raise JWTKeyConfigurationError(f"Cannot read JWT private key at {path!r}: {e.strerror}")


# Keyed on the configured source string, so a parse happens once per worker per
# key rather than once per request. Rotation adds a new kid with a new source,
# which misses the cache naturally; overwriting a PEM file in place under the
# same kid is not rotation and needs a restart.
@functools.lru_cache(maxsize=16)
def _load_private_key(source: str) -> RSAPrivateKey:
	try:
		key = load_pem_private_key(_read_pem(source), password=None)
	except (ValueError, TypeError) as e:
		raise JWTKeyConfigurationError(f"JWT private key is not an unencrypted PEM key: {e}")

	if not isinstance(key, RSAPrivateKey):
		raise JWTKeyConfigurationError(
			f"JWT private key is {type(key).__name__}, but tokens are signed {ALGORITHM}."
		)

	if key.key_size < MIN_KEY_BITS:
		raise JWTKeyConfigurationError(
			f"JWT private key is {key.key_size} bits; {ALGORITHM} keys below {MIN_KEY_BITS} "
			"are factorable. Generate one with "
			"`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072`."
		)

	return key


def get_signing_key() -> tuple[str, RSAPrivateKey]:
	"""Return the (kid, private key) that new access tokens must be signed with."""
	sources = _key_sources()
	kid = frappe.conf.get("jwt_current_kid") or FALLBACK_KID
	source = sources.get(kid)

	if not source:
		raise JWTKeyConfigurationError(
			f"`jwt_current_kid` is {kid!r} but `jwt_private_keys` has no entry for it. "
			"Add the key before pointing the site at it — the ordering matters, since "
			"tokens signed with a kid nobody else knows verify nowhere."
		)

	return kid, _load_private_key(source)


def get_verification_key(kid: str | None) -> RSAPublicKey | None:
	"""Return the public key for `kid`, or None when the kid is absent or unknown.

	Raises JWTKeyConfigurationError when the site has no key material at all.
	"""
	sources = _key_sources()

	# An absent kid is a token this app did not mint: every token it issues
	# carries one. Treated as unknown rather than defaulted to the current key,
	# because defaulting would let a header-stripped token pick up a valid
	# signature check it was never entitled to.
	if not kid or not sources.get(kid):
		return None

	return _load_private_key(sources[kid]).public_key()


def get_public_jwks() -> list[dict]:
	"""Return every verifiable key as a public JWK, in config order.

	Retired-but-listed kids are included: a verifier that fetched the set before
	a rotation must still be able to check tokens minted before it.
	"""
	jwks = []
	for kid, source in _key_sources().items():
		jwk = RSAAlgorithm.to_jwk(_load_private_key(source).public_key(), as_dict=True)
		jwk.update(kid=kid, alg=ALGORITHM, use="sig")
		jwks.append(jwk)
	return jwks
