"""Encoding and decoding of the two token types.

Internal, and outside `api/v1/` for the reason given in `api/jwt_keys.py`: the
wire format of a token is not the HTTP contract clients code against, and the
two version independently.

The two tokens are deliberately different in kind:

**Access token** — a signed JWT, carrying claims, verified with no I/O. Nothing
consults storage to decide it is valid, which is what makes it cheap and what
makes it impossible to revoke before it expires. Hence the short TTL.

**Refresh token** — opaque random bytes, meaningless on their own, checked
against a stored SHA-256 hash. Revocable precisely because verifying it is a
lookup. It buys revocability with a database round-trip, and is presented rarely
enough for that to be the right trade.

Storing only the hash means a database disclosure yields no replayable token.
SHA-256 rather than a password hash is correct here and not a shortcut: the
input is 256 bits of CSPRNG output, so there is no low-entropy guess space for a
slow KDF to defend, and refresh is on the hot path for every session resumption.
"""

import hashlib
import secrets as pysecrets
from datetime import UTC, datetime, timedelta

import frappe
import jwt

from oan_auth_service.api.jwt_keys import get_signing_key, get_verification_key
from oan_auth_service.config import settings

ALGORITHM = "HS256"

ACCESS_TOKEN_TYPE = "access"

# 32 bytes of CSPRNG output, url-safe base64 encoded.
REFRESH_TOKEN_BYTES = 32


class TokenError(Exception):
	"""A presented token is absent, malformed, expired or not ours.

	One exception for every failure mode on purpose. Callers turn this into a
	single opaque 401: distinguishing "expired" from "bad signature" from
	"unknown kid" in a response tells an attacker which half of a forgery
	attempt worked.
	"""


def issue_access_token(user: str, roles: list[str], scope: list[str] | None = None) -> tuple[str, int]:
	"""Mint a signed access token for `user`. Returns (token, ttl_seconds).

	`roles` is the caller's full role set as the server resolved it. `scope`, when
	given, is the narrowed subset the token is issued under — see `api/v1/auth.py`
	for what that does and, more importantly, what it does not do.
	"""
	kid, secret = get_signing_key()
	ttl = settings.access_token_ttl()
	now = datetime.now(UTC)

	claims = {
		"iss": settings.issuer(),
		"sub": user,
		"iat": now,
		"exp": now + timedelta(seconds=ttl),
		# Distinguishes an access token from any other JWT the site might sign
		# with the same key. Without it, a token minted for another purpose that
		# happens to carry a `sub` would authenticate a request.
		"typ": ACCESS_TOKEN_TYPE,
		# Identifies this specific token in logs without logging the token.
		"jti": pysecrets.token_urlsafe(16),
		"roles": roles,
	}

	if scope is not None:
		claims["scope"] = scope

	token = jwt.encode(claims, secret, algorithm=ALGORITHM, headers={"kid": kid})
	return token, ttl


def decode_access_token(token: str) -> dict:
	"""Verify `token` and return its claims, or raise TokenError."""
	if not token:
		raise TokenError("No token presented")

	# The kid is read from the unverified header, which is safe only because it
	# selects a key rather than granting anything: an attacker naming a kid they
	# like still has to produce a signature under that key.
	try:
		kid = jwt.get_unverified_header(token).get("kid")
	except jwt.PyJWTError:
		raise TokenError("Malformed token header")

	secret = get_verification_key(kid)
	if not secret:
		raise TokenError("Token names an unknown signing key")

	try:
		claims = jwt.decode(
			token,
			secret,
			algorithms=[ALGORITHM],
			issuer=settings.issuer(),
			options={"require": ["exp", "iat", "sub", "iss"]},
		)
	except jwt.PyJWTError:
		raise TokenError("Token failed verification")

	if claims.get("typ") != ACCESS_TOKEN_TYPE:
		raise TokenError("Token is not an access token")

	return claims


def generate_refresh_token() -> str:
	"""Return a fresh opaque refresh token. Never stored in this form."""
	return pysecrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> str:
	"""Return the SHA-256 hex digest stored in place of the token itself."""
	return hashlib.sha256(token.encode()).hexdigest()


def resolve_roles(user: str) -> list[str]:
	"""Return the roles that go into a token, as the server resolved them.

	Never accepts a role from the caller.

	The three ambient roles are dropped: `get_roles` appends them from user type
	rather than from any grant (frappe/permissions.py:558-560), so they are
	implied by having authenticated at all and would bloat every token with
	claims no consumer branches on.

	This is deliberately *not* Frappe's `AUTOMATIC_ROLES`, which also contains
	"Administrator". Filtering on that constant would be redundant for normal
	users — line 553 already excludes "Administrator" from the query and, unlike
	the other three, never adds it back — and its only real effect would be to
	strip the role from the one user that legitimately reports it.

	CAVEAT: for the Administrator user, `get_roles` returns every Role on the
	site (line 545), so that one token carries a claim per role. Fine on a small
	site, and worth capping if a consumer ever puts Administrator on a hot path.
	"""
	from frappe.permissions import ALL_USER_ROLE, GUEST_ROLE, SYSTEM_USER_ROLE

	ambient = {ALL_USER_ROLE, GUEST_ROLE, SYSTEM_USER_ROLE}
	return sorted(r for r in frappe.get_roles(user) if r not in ambient)
