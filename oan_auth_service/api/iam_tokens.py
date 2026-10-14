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
from urllib.parse import urlparse

import frappe
import jwt
import requests

from oan_auth_service.api.tokens import TokenError
from oan_auth_service.config import settings

HTTP_TIMEOUT = 5
# One Error Log row per window during an IAM outage, not one per failing request.
OUTAGE_LOG_WINDOW_SEC = 60


class IAMUnavailableError(Exception):
	"""IAM could not be asked (unreachable, timed out or answered 5xx).

	Deliberately not a `TokenError`: the token was not judged, so the caller
	should get a 503, not a 401 that a frontend reads as an expired session.
	"""


def _iam_unavailable(detail: str) -> IAMUnavailableError:
	key = "oan_auth:iam_outage_logged"
	if not frappe.cache.get_value(key):
		frappe.cache.set_value(key, 1, expires_in_sec=OUTAGE_LOG_WINDOW_SEC)
		frappe.log_error(title="oan_auth_service: IAM unavailable", message=detail)
	return IAMUnavailableError(detail)


def _require_https(base_url: str) -> None:
	"""Refuse to send bearer tokens to IAM over plain http. Loopback is exempt."""
	parsed = urlparse(base_url)
	if parsed.scheme == "https" or parsed.hostname in ("localhost", "127.0.0.1", "::1"):
		return
	raise TokenError("iam_base_url must use https")


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
	_require_https(base_url)

	try:
		response = requests.get(
			f"{base_url}/auth/get_user_profile",
			headers={"Authorization": f"Bearer {token}"},
			timeout=HTTP_TIMEOUT,
			allow_redirects=False,
		)
	except requests.RequestException as exc:
		raise _iam_unavailable(f"Could not reach IAM: {exc}")

	if response.status_code >= 500:
		raise _iam_unavailable(f"IAM answered {response.status_code}")
	if response.status_code != 200:
		raise TokenError(f"IAM rejected the token ({response.status_code})")

	try:
		principal = response.json()
	except ValueError:
		frappe.log_error(
			title="oan_auth_service: IAM bad response", message="IAM returned 200 with a non-JSON body"
		)
		raise TokenError("IAM returned a non-JSON response")
	if not isinstance(principal, dict):
		frappe.log_error(
			title="oan_auth_service: IAM bad response", message="IAM returned 200 with a non-object JSON body"
		)
		raise TokenError("IAM returned an unexpected response")
	if not principal.get("sub"):
		raise TokenError("IAM principal has no sub")

	frappe.cache.set_value(key, principal, expires_in_sec=_seconds_until_expiry(token))
	return principal


# IAM's base cookie names (iam_core AuthCookieName). Read them through
# `cookie_name`, which applies the deployment's prefix the way iam_core does.
ACCESS_COOKIE = "X-Access-Token"
CSRF_COOKIE = "X-CSRF-Token"
# iam_core never prefixes the CSRF header, only the cookie.
CSRF_HEADER = "X-CSRF-Token"


def cookie_name(base: str) -> str:
	"""`base` with the deployment's IAM cookie prefix applied (iam_core `cookie_name`)."""
	return f"{settings.iam_auth_cookie_prefix()}{base}"


def _seconds_until_expiry(token: str) -> int:
	# Read unverified: IAM has just verified this token, `exp` only sizes the cache.
	try:
		exp = jwt.decode(token, options={"verify_signature": False}).get("exp")
	except jwt.PyJWTError:
		exp = None
	if not exp:
		return FALLBACK_CACHE_TTL
	return max(1, int(exp - time.time()))
