"""Tunable lifetimes and identifiers, resolved from site_config.json.

Exposed as functions rather than module constants on purpose: site_config is
re-read at runtime, and a constant bound at import time would pin whatever the
value happened to be when the worker booted. A TTL you cannot change without a
process restart is a TTL nobody changes during an incident.

Configuration (site_config.json), all optional:

    "jwt_access_token_ttl": 900,
    "jwt_refresh_token_ttl": 2592000,
    "jwt_refresh_token_ttl_remember_me": 7776000,
    "jwt_issuer": "oan-auth"
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


def issuer() -> str:
	"""The `iss` claim, and the value verification demands.

	Defaults to the site name, which makes tokens from a staging site fail
	closed against production rather than being silently accepted — the two
	share code and could otherwise share a secret by deployment accident.
	"""
	return frappe.conf.get("jwt_issuer") or frappe.local.site
