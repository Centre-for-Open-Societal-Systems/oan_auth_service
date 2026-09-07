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

FALLBACK_KID = "v1"


class JWTKeyConfigurationError(Exception):
	"""The site has no usable JWT key material at all.

	Distinct from "this token names a kid we don't know": callers map the two to
	different responses so a server misconfiguration is not reported as a bad token.
	"""


def get_signing_key() -> tuple[str, str]:
	"""Return the (kid, secret) that new access tokens must be signed with."""
	raise NotImplementedError


def get_verification_key(kid: str | None) -> str | None:
	"""Return the secret for `kid`, or None when the kid is absent or unknown.

	Raises JWTKeyConfigurationError when the site has no key material at all.
	"""
	raise NotImplementedError
