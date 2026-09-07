"""Resolution of the secrets used to sign and verify access tokens.

Deliberately outside the versioned `api/v1/` namespace: `v1` versions the HTTP
contract clients depend on, while key resolution is internal. Rotating a key
must never require a new API version, and shipping `v2` endpoints must never
force a re-keying.

Keys are indexed by `kid` so rotation is possible: new tokens are signed with
the key `jwt_current_kid` names, while every key still listed in `jwt_secrets`
is accepted on verification. A zero-downtime rotation is therefore: add the new
kid, point `jwt_current_kid` at it, then drop the old kid once the longest-lived
access token has expired.

Configuration (site_config.json):

    "jwt_secrets": {"v1": "<random>", "v2": "<random>"},
    "jwt_current_kid": "v2"

The signing secret is kept separate from `encryption_key` on purpose:
`encryption_key` is Frappe's Fernet key for data at rest and must stay stable
for the life of the site, whereas rotating a token-signing secret is the
response to a suspected leak and has to be cheap. One value serving both roles
makes the cheap action inherit the expensive action's cost, which in practice
means the rotation never happens.

NOTE ON SHARING: these secrets are per-site. Two deployments of this app do not
share key material, and must not — HS256 is symmetric, so any holder of the
secret can mint as well as verify. Federating identity across deployments is a
move to asymmetric signing (RS256 + JWKS), not a shared secret.
"""

import frappe

FALLBACK_KID = "v1"

MIN_SECRET_LENGTH = 32


class JWTKeyConfigurationError(Exception):
	"""The site has no usable JWT key material at all.

	Distinct from "this token names a kid we don't know": callers map the two to
	different responses so a server misconfiguration is not reported as a bad token.
	"""


def _secrets() -> dict[str, str]:
	"""Return the configured kid -> secret map, or raise if unusable."""
	secrets = frappe.conf.get("jwt_secrets")

	if not secrets:
		raise JWTKeyConfigurationError(
			"No `jwt_secrets` in site_config.json. This app cannot mint or verify tokens "
			"until at least one signing key is configured."
		)

	if not isinstance(secrets, dict):
		raise JWTKeyConfigurationError(
			"`jwt_secrets` must be a JSON object mapping kid -> secret, e.g. "
			'{"v1": "<random>"}. A bare string is the shape of a single un-rotatable '
			"key, which is the situation the kid indirection exists to avoid."
		)

	return secrets


def get_signing_key() -> tuple[str, str]:
	"""Return the (kid, secret) that new access tokens must be signed with."""
	secrets = _secrets()
	kid = frappe.conf.get("jwt_current_kid") or FALLBACK_KID
	secret = secrets.get(kid)

	if not secret:
		raise JWTKeyConfigurationError(
			f"`jwt_current_kid` is {kid!r} but `jwt_secrets` has no entry for it. "
			"Add the key before pointing the site at it — the ordering matters, since "
			"tokens signed with a kid nobody else knows verify nowhere."
		)

	# Enforced at signing time only. Verification must keep accepting a short
	# legacy secret, or tightening this rule would retroactively invalidate every
	# token already in the wild.
	if len(secret) < MIN_SECRET_LENGTH:
		raise JWTKeyConfigurationError(
			f"The secret for kid {kid!r} is {len(secret)} characters. HS256 keys are "
			f"brute-forceable below {MIN_SECRET_LENGTH}; generate one with "
			"`python -c 'import secrets; print(secrets.token_urlsafe(48))'`."
		)

	return kid, secret


def get_verification_key(kid: str | None) -> str | None:
	"""Return the secret for `kid`, or None when the kid is absent or unknown.

	Raises JWTKeyConfigurationError when the site has no key material at all.
	"""
	secrets = _secrets()

	# An absent kid is a token this app did not mint: every token it issues
	# carries one. Treated as unknown rather than defaulted to the current key,
	# because defaulting would let a header-stripped token pick up a valid
	# signature check it was never entitled to.
	if not kid:
		return None

	return secrets.get(kid)
