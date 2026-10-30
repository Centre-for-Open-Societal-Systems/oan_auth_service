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
    "password_reset_otp_max_attempts": 5,
    "jwt_self_registerable_roles": []

Login delegated to the OpenG2P IAM service is not configured here: each login
option is a row of the `OAN IAM Service` DocType, read through `iam_services()`
below. See api/iam_tokens.py and api/iam_users.py.
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

# Codes texted to one account per day. Counted per resolved user and never reset
# by issuing a code, so requesting fresh codes cannot refill the guess budget or
# flood the owner's phone.
DEFAULT_PASSWORD_RESET_OTP_MAX_ISSUED_PER_DAY = 5


def password_reset_otp_ttl() -> int:
	"""Seconds a password-reset OTP stays valid."""
	return int(frappe.conf.get("password_reset_otp_ttl") or DEFAULT_PASSWORD_RESET_OTP_TTL)


def password_reset_otp_length() -> int:
	"""Number of digits in a password-reset OTP."""
	return int(frappe.conf.get("password_reset_otp_length") or DEFAULT_PASSWORD_RESET_OTP_LENGTH)


def password_reset_otp_max_attempts() -> int:
	"""Wrong guesses allowed against one OTP before it is destroyed."""
	return int(frappe.conf.get("password_reset_otp_max_attempts") or DEFAULT_PASSWORD_RESET_OTP_MAX_ATTEMPTS)


def password_reset_otp_max_issued_per_day() -> int:
	"""Password-reset OTPs one account may be sent in 24 hours."""
	return int(
		frappe.conf.get("password_reset_otp_max_issued_per_day")
		or DEFAULT_PASSWORD_RESET_OTP_MAX_ISSUED_PER_DAY
	)


def issuer() -> str:
	"""The `iss` claim, and the value verification demands.

	Defaults to the site name, which makes tokens from a staging site fail
	closed against production rather than being silently accepted — the two
	share code and could otherwise share a secret by deployment accident.
	"""
	return frappe.conf.get("jwt_issuer") or frappe.local.site


def enforce_https() -> bool:
	"""Whether HTTPS transport is strictly required for auth API calls."""
	return bool(frappe.conf.get("jwt_enforce_https") or frappe.conf.get("enforce_https"))


def self_registerable_roles() -> list[str]:
	"""List of roles permitted for self-registration by guest callers."""
	return list(frappe.conf.get("jwt_self_registerable_roles") or [])


def name_in_scope(name: str, prefixes: tuple[str, ...]) -> bool:
	"""Whether `name` is a prefix itself or starts with a prefix and a space (`A2C Lead`, not `A2Cfoo`)."""
	return any(name == p or name.startswith(f"{p} ") for p in prefixes)


def service_prefixes() -> tuple[str, ...]:
	"""Bare name prefixes of the roles and doctypes this deployment's services own, e.g. `("A2C",)`.

	The admin endpoints expose only roles, doctypes and users matching one. A
	consuming app declares its prefix with the `oan_service_prefix` hook; the
	`service_prefix` site config key (a string or list) takes precedence.
	"""
	configured = frappe.conf.get("service_prefix")
	if isinstance(configured, str):
		configured = [configured]
	values = configured or frappe.get_hooks("oan_service_prefix")
	return tuple(dict.fromkeys(v.strip() for v in values if v and v.strip()))


IAM_SERVICE_DOCTYPE = "OAN IAM Service"
IAM_SERVICES_CACHE_KEY = "oan_auth:iam_services"
# The row key reserved for this app's own username and password login.
LOCAL_LOGIN_KEY = "local"

_IAM_SERVICE_FIELDS = (
	"key",
	"label",
	"icon",
	"sort_order",
	"base_url",
	"provider_id",
	"issuer",
	"client_id",
	"application",
	"cookie_prefix",
	"userinfo_url",
	"jwks_url",
)


def iam_services() -> list[frappe._dict]:
	"""Enabled login options (`OAN IAM Service` rows) in `sort_order`.

	Cached until a row changes (the DocType clears the cache on save and
	delete), so token validation costs no query per request. Each entry carries
	its `default_roles` as a plain list.
	"""
	services = frappe.cache.get_value(IAM_SERVICES_CACHE_KEY)
	if services is None:
		services = _load_iam_services()
		frappe.cache.set_value(IAM_SERVICES_CACHE_KEY, services)
	return [frappe._dict(s) for s in services]


def _load_iam_services() -> list[dict]:
	# Not bank-scoped or otherwise permission-filtered: this is server-side
	# configuration, read on behalf of every request, guests included.
	rows = frappe.get_all(
		IAM_SERVICE_DOCTYPE,
		filters={"enabled": 1},
		fields=list(_IAM_SERVICE_FIELDS),
		order_by="sort_order asc, name asc",
	)
	if not rows:
		return []

	names = [r.key for r in rows]
	roles: dict[str, list[str]] = {}
	for d in frappe.get_all(
		"OAN IAM Service Role",
		filters={"parenttype": IAM_SERVICE_DOCTYPE, "parent": ("in", names)},
		fields=["parent", "role"],
		order_by="idx asc",
	):
		roles.setdefault(d.parent, []).append(d.role)

	return [
		{
			**{f: r.get(f) for f in _IAM_SERVICE_FIELDS},
			"base_url": (r.base_url or "").rstrip("/"),
			"cookie_prefix": r.cookie_prefix or "",
			"userinfo_url": r.userinfo_url or "",
			"jwks_url": r.jwks_url or "",
			"default_roles": roles.get(r.key, []),
		}
		for r in rows
	]


def clear_iam_services_cache() -> None:
	frappe.cache.delete_value(IAM_SERVICES_CACHE_KEY)


def iam_service(key: str | None = None) -> frappe._dict | None:
	"""The enabled IAM login option named `key`, or None. Never the `local` row.

	If `key` is None, empty, or 'default', and exactly one IAM option is enabled,
	that option is returned as the default.
	"""
	if not key or key == "default":
		iam_options = [s for s in iam_services() if s.key != LOCAL_LOGIN_KEY]
		if len(iam_options) == 1:
			return iam_options[0]
		return None
	if key == LOCAL_LOGIN_KEY:
		return None
	return next((s for s in iam_services() if s.key == key), None)


def iam_service_for_issuer(iss: str, azp: str | None = None) -> frappe._dict | None:
	"""The enabled IAM login option whose `issuer` is exactly `iss`, or None.

	When multiple options share the same issuer, `azp` (client_id) disambiguates.
	"""
	if not iss:
		return None
	candidates = [s for s in iam_services() if s.key != LOCAL_LOGIN_KEY and s.issuer == iss]
	if not candidates:
		return None
	if azp:
		for s in candidates:
			if s.client_id == azp:
				return s
	for s in candidates:
		if not s.client_id:
			return s
	return candidates[0]
