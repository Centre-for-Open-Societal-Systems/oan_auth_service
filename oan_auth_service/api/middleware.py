"""JWT validation bound to Frappe's auth_hooks.

One hook serves every consuming app. Each app registers the API namespace it
owns plus the paths within it that are reachable without a bearer token; the
middleware matches the incoming path against that registry and leaves anything
unregistered — desk, standard Frappe APIs — to Frappe's own auth.

Registration keeps this app free of any knowledge of its consumers, which is
what lets it be shared without becoming a dependency in both directions.

ORDERING. `validate_auth_via_hooks` runs last in Frappe's `validate_auth`
(frappe/auth.py:639), after OAuth and after API-key auth. So by the time this
runs, something else may already have established a session, and clobbering it
would silently downgrade a request that authenticated by another accepted means.
Hence the guard in `validate_jwt_request` against an already-set user.

THE BEARER COLLISION. Frappe's `validate_oauth` claims the `Bearer` scheme and
runs first (auth.py:637). It looks our token up in `OAuth Bearer Token`, misses,
and swallows the resulting error. The net effect is one wasted query per
authenticated request and no incorrect behaviour — it works, but by accident
rather than by design. Documented here because the accident is load-bearing: if
Frappe ever makes that path throw instead of swallow, this breaks, and the fix
is a distinct Authorization scheme rather than a patch to the exception handling.
"""

import frappe

from oan_auth_service.api import tokens
from oan_auth_service.api.jwt_keys import JWTKeyConfigurationError

# namespace prefix -> config for that consumer.
_NAMESPACES: dict[str, dict] = {}


def register_namespace(prefix: str, exempt_paths: list[str] | None = None, revocation_check=None):
	"""Declare an API namespace as JWT-protected.

	prefix           e.g. "/api/method/grievance_backend."
	exempt_paths     full paths reachable without a token (login, refresh, webhooks)
	revocation_check optional callable(user) -> str | None; a returned string is
	                 the rejection reason. Lets a consumer invalidate live tokens
	                 on its own conditions without this app knowing the rule.

	Call from the consumer's `after_app_install`/module import — anywhere that
	runs in every worker process. The registry is per-process in-memory state,
	so registering inside a request handler would protect only the worker that
	happened to serve that request.
	"""
	if not prefix.startswith("/api/method/"):
		raise ValueError(
			f"Namespace prefix {prefix!r} must start with '/api/method/'. Matching is by "
			"request path, and a prefix that cannot appear in one would register a "
			"namespace that silently never matches."
		)

	_NAMESPACES[prefix] = {
		"exempt_paths": set(exempt_paths or []),
		"revocation_check": revocation_check,
	}


def _match_namespace(path: str) -> dict | None:
	"""Return the config for the namespace owning `path`, or None."""
	# Longest prefix wins, so a consumer can register a sub-namespace with
	# different exemptions inside one it already owns.
	best = None
	best_len = -1

	for prefix, config in _NAMESPACES.items():
		if path.startswith(prefix) and len(prefix) > best_len:
			best, best_len = config, len(prefix)

	return best


def _bearer_token() -> str | None:
	"""Return the token from the Authorization header, if it carries one."""
	header = frappe.get_request_header("Authorization") or ""
	parts = header.split(None, 1)

	if len(parts) != 2 or parts[0].lower() != "bearer":
		return None

	return parts[1].strip() or None


def validate_jwt_request(request=None):
	"""Entry point registered as `auth_hooks` in hooks.py."""
	if not _NAMESPACES:
		return

	request = request or getattr(frappe.local, "request", None)
	if request is None:
		return

	path = request.path
	config = _match_namespace(path)

	# Not ours. Desk, standard Frappe APIs and unregistered apps keep Frappe's
	# own auth untouched.
	if config is None:
		return

	if path in config["exempt_paths"]:
		return

	# Something earlier in validate_auth already authenticated this request (see
	# ORDERING above). Leave it alone.
	session = getattr(frappe.local, "session", None)
	if session and session.user and session.user != "Guest":
		return

	token = _bearer_token()
	if not token:
		_reject("Missing bearer token")

	try:
		claims = tokens.decode_access_token(token)
	except JWTKeyConfigurationError:
		# A server misconfiguration, not a bad token. Reported separately so an
		# operator sees "we have no keys" rather than a flood of 401s that look
		# like clients misbehaving.
		frappe.log_error(title="oan_auth_service: JWT key material unusable")
		frappe.throw("Authentication is misconfigured on this server", frappe.ValidationError)
	except tokens.TokenError:
		_reject("Invalid or expired token")

	user = claims.get("sub")
	if not user or not frappe.db.exists("User", user):
		_reject("Invalid or expired token")

	if not frappe.db.get_value("User", user, "enabled"):
		_reject("Invalid or expired token")

	revocation_check = config.get("revocation_check")
	if revocation_check:
		reason = revocation_check(user)
		if reason:
			_reject(reason)

	_verify_scope_still_held(user, claims)

	frappe.set_user(user)

	# Exposed so consumer code can read the token it was authenticated with —
	# notably the `scope` claim, which this app records but cannot itself
	# enforce against Frappe's DocPerm layer (see api/v1/auth.py:_narrow_to_scope).
	frappe.local.oan_auth_claims = claims


def _verify_scope_still_held(user: str, claims: dict) -> None:
	"""Reject a scoped token naming a role the user has since lost.

	Without this the `scope` claim would be a frozen assertion from issuance
	time, and a consumer branching on it would act on a grant that has been
	revoked. Re-checking against live roles is what makes the claim safe to
	trust for the length of a request.
	"""
	scope = claims.get("scope")
	if not scope:
		return

	held = set(tokens.resolve_roles(user))
	if not set(scope).issubset(held):
		_reject("Token scope is no longer valid")


def _reject(reason: str):
	"""Fail authentication with a uniform response.

	`reason` is for the server-side log. The client gets one undifferentiated
	401 regardless: telling a caller whether their token was expired, forged or
	revoked helps them work out which half of an attempt succeeded.
	"""
	frappe.local.response["message"] = "Authentication failed"
	frappe.log_error(title="oan_auth_service: rejected request", message=reason)
	raise frappe.AuthenticationError
