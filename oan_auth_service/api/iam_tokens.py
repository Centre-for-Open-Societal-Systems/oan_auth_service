"""Validation of tokens issued through the OpenG2P IAM service.

The frontend logs in against IAM, which proxies whichever identity provider it
is configured with (Keycloak today, eSignet or others tomorrow). This app does
not know or care which: it hands the bearer token to IAM's
`GET /auth/get_user_profile` and gets back IAM's provider-neutral principal,

    {"sub": ..., "name": ..., "client_roles": {"<application>": [roles]}}

IAM does the signature, issuer and expiry checks with its own per-provider
adapters. A token IAM rejects is rejected here. Nothing provider-specific
(JWKS, claim shapes, client secrets) lives in this app.

The principal is cached by token hash until the token's `exp`, so IAM is
asked once per token rather than once per request. The cost is that a token
IAM would stop accepting mid-life (it does not do so today) keeps working here
until it expires, the same window every other OpenG2P service has.
"""

import hashlib
import time

import frappe
import jwt
import requests

from oan_auth_service.api.tokens import TokenError
from oan_auth_service.config import settings

HTTP_TIMEOUT = 5

# Used when a token carries no readable `exp`: short enough that a revoked
# token does not linger, long enough to spare IAM a call per request.
FALLBACK_CACHE_TTL = 60


def peek_issuer(token: str) -> str | None:
	"""Return the token's `iss` without verifying anything, or None.

	Only used to route the token: our own issuer is verified in-process, any
	other goes to IAM. A forged `iss` gains nothing, IAM still verifies it.
	"""
	try:
		return jwt.decode(token, options={"verify_signature": False}).get("iss")
	except jwt.PyJWTError:
		return None


def get_principal(token: str) -> dict:
	"""Return IAM's principal for `token`, or raise TokenError if IAM rejects it."""
	key = f"oan_auth:iam_principal:{hashlib.sha256(token.encode()).hexdigest()}"
	principal = frappe.cache.get_value(key)
	if principal:
		return principal

	base_url = settings.iam_base_url()
	if not base_url:
		raise TokenError("iam_base_url is not configured")

	try:
		response = requests.get(
			f"{base_url}/auth/get_user_profile",
			headers={"Authorization": f"Bearer {token}"},
			timeout=HTTP_TIMEOUT,
			allow_redirects=False,
		)
	except requests.RequestException as exc:
		frappe.log_error(title="oan_auth_service: IAM unreachable", message=str(exc))
		raise TokenError("Could not reach IAM")

	if response.status_code != 200:
		raise TokenError(f"IAM rejected the token ({response.status_code})")

	principal = response.json()
	if not principal.get("sub"):
		raise TokenError("IAM principal has no sub")

	frappe.cache.set_value(key, principal, expires_in_sec=_seconds_until_expiry(token))
	return principal


def _seconds_until_expiry(token: str) -> int:
	# Read unverified: IAM has just verified this token, `exp` only sizes the cache.
	try:
		exp = jwt.decode(token, options={"verify_signature": False}).get("exp")
	except jwt.PyJWTError:
		exp = None
	if not exp:
		return FALLBACK_CACHE_TTL
	return max(1, int(exp - time.time()))
