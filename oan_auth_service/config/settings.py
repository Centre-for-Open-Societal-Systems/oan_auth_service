"""Tunable lifetimes and identifiers, resolved from site_config.json.

Exposed as functions rather than module constants on purpose: site_config is
re-read at runtime, and a constant bound at import time would pin whatever the
value happened to be when the worker booted. A TTL you cannot change without a
process restart is a TTL nobody changes during an incident.

Configuration (site_config.json), all optional:

    "jwt_access_token_ttl": 900,
    "jwt_refresh_token_ttl": 2592000,
    "jwt_refresh_token_ttl_remember_me": 7776000,
    "jwt_issuer": "oan-auth",
    "password_reset_otp_ttl": 600,
    "password_reset_otp_length": 6,
    "password_reset_otp_max_attempts": 5
"""

import frappe

# Short by design. The access token carries a roles claim, and a claim is a
# snapshot: it stops reflecting reality the moment roles change. The TTL is the
# window in which a revoked role is still believed, so it buys staleness with
# every second it grows. Fifteen minutes keeps that window smaller than the time
# it takes a human to notice and act on a bad grant.
DEFAULT_ACCESS_TOKEN_TTL = 15 * 60

DEFAULT_REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60
DEFAULT_REFRESH_TOKEN_TTL_REMEMBER_ME = 90 * 24 * 60 * 60


def access_token_ttl() -> int:
	"""Lifetime in seconds of a newly issued access token."""
	return int(frappe.conf.get("jwt_access_token_ttl") or DEFAULT_ACCESS_TOKEN_TTL)


def refresh_token_ttl(remember_me: bool = False) -> int:
	"""Lifetime in seconds of a newly issued refresh token."""
	if remember_me:
		return int(
			frappe.conf.get("jwt_refresh_token_ttl_remember_me") or DEFAULT_REFRESH_TOKEN_TTL_REMEMBER_ME
		)
	return int(frappe.conf.get("jwt_refresh_token_ttl") or DEFAULT_REFRESH_TOKEN_TTL)


# A phone-only account cannot be sent a reset link, so it is sent a numeric code
# instead. Six digits is only ~20 bits, which is why the two settings below
# exist at all: the code is worth guessing unless its lifetime is short and the
# number of guesses is capped. Ten minutes is long enough to survive slow SMS
# delivery on a rural network and short enough that an unused code is not left
# standing.
DEFAULT_PASSWORD_RESET_OTP_TTL = 10 * 60
DEFAULT_PASSWORD_RESET_OTP_LENGTH = 6

# Five wrong guesses burns the code entirely rather than merely rejecting the
# attempt, so an attacker cannot keep working through the keyspace by retrying.
# The cost of getting this wrong is a legitimate user requesting a new code.
DEFAULT_PASSWORD_RESET_OTP_MAX_ATTEMPTS = 5


def password_reset_otp_ttl() -> int:
	"""Seconds a password-reset OTP stays valid."""
	return int(frappe.conf.get("password_reset_otp_ttl") or DEFAULT_PASSWORD_RESET_OTP_TTL)


def password_reset_otp_length() -> int:
	"""Number of digits in a password-reset OTP."""
	return int(frappe.conf.get("password_reset_otp_length") or DEFAULT_PASSWORD_RESET_OTP_LENGTH)


def password_reset_otp_max_attempts() -> int:
	"""Wrong guesses allowed against one OTP before it is destroyed."""
	return int(frappe.conf.get("password_reset_otp_max_attempts") or DEFAULT_PASSWORD_RESET_OTP_MAX_ATTEMPTS)


def issuer() -> str:
	"""The `iss` claim, and the value verification demands.

	Defaults to the site name, which makes tokens from a staging site fail
	closed against production rather than being silently accepted — the two
	share code and could otherwise share a secret by deployment accident.
	"""
	return frappe.conf.get("jwt_issuer") or frappe.local.site
