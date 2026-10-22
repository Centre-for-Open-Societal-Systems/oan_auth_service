"""Per-path authentication bound to Frappe's auth_hooks.

One hook serves every consuming app. Each app registers the API namespace it
owns, and within it the paths that are public and the paths that take a Frappe
API key; every other path in the namespace takes a JWT. The middleware matches
the incoming path against that registry and leaves anything unregistered —
desk, standard Frappe APIs — to Frappe's own auth.

Registration keeps this app free of any knowledge of its consumers, which is
what lets it be shared without becoming a dependency in both directions.

ONE SCHEME PER PATH. Each kind of path accepts exactly one way in:

    jwt      Bearer JWT (ours or an IAM token), or an IAM access cookie.
             `token`/`Basic` credentials and desk `sid` sessions are refused.
    api_key  A session Frappe set from `Authorization: token <key>:<secret>`,
             optionally holding one of the path's roles. Anything else is refused.
    public   Nothing required.

A path may take both `jwt` and `api_key`, as a transition for callers moving
from API keys to JWTs: an `Authorization: token` header goes the API-key way,
anything else the JWT way. Prefer one scheme; see api/router.py.

ORDERING. `validate_auth_via_hooks` runs last in Frappe's `validate_auth`
(frappe/auth.py:639), after OAuth and after API-key auth, and a desk `sid`
cookie sets the session user even earlier. So by the time this runs, Frappe may
already have set a user. On a JWT path that session is not trusted: the checks
that come with a JWT (the consumer's `revocation_check`, `must_change_password`,
the `scope` re-check) would otherwise be skipped by anyone holding an API key
or a desk session. On an API-key path it is the credential, and the header
scheme proves where it came from: a `sid` cookie sets the user too.

THE BEARER COLLISION. Frappe's `validate_oauth` claims the `Bearer` scheme and
runs first (auth.py:637). It looks our token up in `OAuth Bearer Token`, misses,
and swallows the resulting error. The net effect is one wasted query per
authenticated request and no incorrect behaviour — it works, but by accident
rather than by design. Documented here because the accident is load-bearing: if
Frappe ever makes that path throw instead of swallow, this breaks, and the fix
is a distinct Authorization scheme rather than a patch to the exception handling.
"""

import hmac
import re

import frappe
from frappe import _

from oan_auth_service.api import iam_tokens, iam_users, tokens
from oan_auth_service.api.jwt_keys import JWTKeyConfigurationError
from oan_auth_service.config import settings
from oan_auth_service.setup.install import MUST_CHANGE_PASSWORD_FIELD

# namespace prefix -> config for that consumer.
_NAMESPACES: dict[str, dict] = {}

AUTH_JWT = "jwt"
AUTH_API_KEY = "api_key"
AUTH_PUBLIC = "public"
AUTH_KINDS = (AUTH_JWT, AUTH_API_KEY, AUTH_PUBLIC)
# A path that takes either a JWT or an API key. Transitional; see the module docstring.
AUTH_JWT_OR_API_KEY = "jwt_or_api_key"

# A Werkzeug `<param>` / `<int:param>` or OpenAPI `{param}` path segment.
_TEMPLATE_PARAM = re.compile(r"<[^>]+>|\{[^}]+\}")


class _PathTable:
	"""Paths of one kind, each mapped to a value; exact or with template segments.

	Templates match one path segment per parameter, so a consumer can register
	`/api/v1/partner/banks/<bank_id>` instead of expanding every id.
	"""

	def __init__(self):
		self.exact: dict[str, tuple] = {}
		self.patterns: list[tuple[re.Pattern, tuple]] = []

	def add(self, path: str, value: tuple = ()) -> None:
		path = _normalize(path)
		if _TEMPLATE_PARAM.search(path):
			parts = _TEMPLATE_PARAM.split(path)
			self.patterns.append((re.compile("^" + "[^/]+".join(re.escape(p) for p in parts) + "$"), value))
		else:
			self.exact[path] = value

	def match(self, path: str) -> tuple | None:
		"""The value registered for `path`, or None when no entry matches."""
		path = _normalize(path)
		if path in self.exact:
			return self.exact[path]
		for pattern, value in self.patterns:
			if pattern.match(path):
				return value
		return None


def _normalize(path: str) -> str:
	return path.rstrip("/") or "/"


def register_namespace(
	prefix: str,
	exempt_paths: list[str] | None = None,
	revocation_check=None,
	api_key_paths: dict[str, list[str]] | list[str] | None = None,
	jwt_or_api_key_paths: dict[str, list[str]] | list[str] | None = None,
):
	"""Declare an API namespace whose paths this middleware authenticates.

	prefix           e.g. "/api/method/grievance_backend." or "/api/v1/grievance"
	exempt_paths     public paths, reachable with no credentials (login, refresh)
	api_key_paths    paths that take only a Frappe API key (`Authorization: token
	                 <key>:<secret>`), e.g. partner webhooks behind the gateway. A
	                 dict maps each path to roles of which the key's user must hold
	                 one; a list requires none
	jwt_or_api_key_paths
	                 paths that take a JWT or an API key, the roles applying to the
	                 API key. Transitional, for callers moving to JWTs
	revocation_check optional callable(user) -> str | None; a returned string is
	                 the rejection reason. Lets a consumer invalidate live tokens
	                 on its own conditions without this app knowing the rule.

	Every other path under `prefix` takes a JWT. Paths are exact or carry
	`<param>` / `{param}` segments. A path registered as both public and API-key
	raises: one scheme per path.

	Call from the consumer's `after_app_install`/module import — anywhere that
	runs in every worker process. The registry is per-process in-memory state,
	so registering inside a request handler would protect only the worker that
	happened to serve that request.
	"""
	if not (prefix.startswith("/api/") or prefix == "/api"):
		raise ValueError(
			f"Namespace prefix {prefix!r} must start with '/api/'. Matching is by "
			"request path, and a prefix that cannot appear in one would register a "
			"namespace that silently never matches."
		)

	api_keys = _with_roles(api_key_paths)
	dual = _with_roles(jwt_or_api_key_paths)
	groups = [
		{_normalize(p) for p in exempt_paths or []},
		{_normalize(p) for p in api_keys},
		{_normalize(p) for p in dual},
	]
	clash = (groups[0] & groups[1]) | (groups[0] & groups[2]) | (groups[1] & groups[2])
	if clash:
		raise ValueError(f"Paths registered under two schemes: {sorted(clash)}")

	config = _NAMESPACES.setdefault(
		prefix,
		{
			"exempt_paths": _PathTable(),
			"api_key_paths": _PathTable(),
			"jwt_or_api_key_paths": _PathTable(),
			"revocation_check": None,
		},
	)
	for path in exempt_paths or []:
		config["exempt_paths"].add(path)
	for path, roles in api_keys.items():
		config["api_key_paths"].add(path, roles)
	for path, roles in dual.items():
		config["jwt_or_api_key_paths"].add(path, roles)
	if revocation_check:
		config["revocation_check"] = revocation_check


def _with_roles(paths) -> dict[str, tuple]:
	if isinstance(paths, dict):
		return {p: tuple(roles or ()) for p, roles in paths.items()}
	return dict.fromkeys(paths or [], ())


def path_auth(config: dict, path: str) -> tuple[str, tuple]:
	"""The auth kind of `path` in a namespace `config`, and the roles an API key there requires."""
	roles = config["api_key_paths"].match(path)
	if roles is not None:
		return AUTH_API_KEY, roles
	roles = config["jwt_or_api_key_paths"].match(path)
	if roles is not None:
		return AUTH_JWT_OR_API_KEY, roles
	if config["exempt_paths"].match(path) is not None:
		return AUTH_PUBLIC, ()
	return AUTH_JWT, ()


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


def _auth_scheme() -> str | None:
	"""The lowercased scheme of the Authorization header (`bearer`, `token`, `basic`), or None."""
	header = (frappe.get_request_header("Authorization") or "").strip()
	return header.split(None, 1)[0].lower() if header else None


def _session_user() -> str | None:
	"""The user Frappe set before this hook ran, or None for Guest."""
	session = getattr(frappe.local, "session", None)
	user = session.user if session else None
	return user if user and user != "Guest" else None


def _bearer_token() -> str | None:
	"""Return the token from the Authorization header, if it carries one."""
	header = frappe.get_request_header("Authorization") or ""
	parts = header.split(None, 1)

	if len(parts) != 2 or parts[0].lower() != "bearer":
		return None

	return parts[1].strip() or None


_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _cookie_session_token(request) -> tuple[str | None, str]:
	"""The access token from an IAM access cookie, and that cookie's prefix.

	Used when there is no Authorization header. Each enabled login option's
	`cookie_prefix` is tried in `sort_order`, and the first access cookie found
	wins. A browser logged in to two options sends both; the token's `iss`
	still decides which IAM checks it, so the wrong IAM is never asked, but
	the request is treated as the first option's identity. Bearer avoids this.
	"""
	prefixes = dict.fromkeys(
		s.cookie_prefix for s in settings.iam_services() if s.key != settings.LOCAL_LOGIN_KEY
	)
	for prefix in prefixes:
		token = request.cookies.get(iam_tokens.cookie_name(iam_tokens.ACCESS_COOKIE, prefix))
		if token:
			return token, prefix
	return None, ""


def _check_csrf(request, prefix: str) -> None:
	"""Double-submit check for cookie-authenticated, state-changing requests.

	A browser attaches cookies by itself, so a cookie alone proves nothing about
	who made the request. IAM's CSRF token is readable by the page but not by
	another site: the header must repeat the cookie. Bearer requests are exempt,
	nothing attaches an Authorization header automatically.
	"""
	if request.method in _SAFE_METHODS:
		return
	header = request.headers.get(iam_tokens.CSRF_HEADER) or ""
	cookie = request.cookies.get(iam_tokens.cookie_name(iam_tokens.CSRF_COOKIE, prefix)) or ""
	# Bytes, not str: compare_digest raises TypeError on a non-ASCII str, which
	# a client controls, and that would surface as a 500 instead of a 401.
	if not header or not hmac.compare_digest(header.encode(), cookie.encode()):
		_reject("CSRF token missing or mismatched")


def validate_jwt_request(request=None):
	"""Entry point registered as `auth_hooks` in hooks.py."""
	# No installed-app check: Frappe only runs auth_hooks of apps installed on
	# the current site.
	request = request or getattr(frappe.local, "request", None)
	if request is None:
		return

	path = request.path
	config = _match_namespace(path)

	# Not ours. Desk, standard Frappe APIs and unregistered apps keep Frappe's
	# own auth untouched.
	if config is None:
		return

	kind, roles = path_auth(config, path)
	if kind == AUTH_JWT_OR_API_KEY:
		# The header scheme picks the branch: an API key here is checked as on
		# an API-key path, anything else must be a JWT.
		kind = AUTH_API_KEY if _auth_scheme() == "token" else AUTH_JWT
	if kind == AUTH_API_KEY:
		_require_api_key_session(roles)
		return

	is_exempt = kind == AUTH_PUBLIC
	if is_exempt and _session_user():
		# Public path, and Frappe already authenticated the request some other
		# way. Nothing to require here; leave it alone.
		return

	if not is_exempt:
		# A JWT path takes only a JWT (see ORDERING). Other Authorization schemes
		# are refused outright; a session Frappe set from a desk `sid` cookie is
		# ignored, so the request still needs a JWT below.
		scheme = _auth_scheme()
		if scheme and scheme != "bearer":
			_reject(f"{scheme} credentials are not accepted on a JWT path")

	# Transport only decides whether CSRF applies; the issuer alone decides how
	# the token is verified.
	token = _bearer_token()
	if token:
		_authenticate_token(token, config)
		return

	token, prefix = _cookie_session_token(request)
	if not token:
		if is_exempt:
			return
		_reject("Missing bearer token")

	if not is_exempt:
		_check_csrf(request, prefix)
		_authenticate_token(token, config)
		return

	# A browser sends its cookie on every request, including to the endpoints a
	# user needs to recover from a bad one (login, refresh, password reset). On an
	# exempt path a cookie that fails any check is "no credentials", not a 401,
	# otherwise a stale cookie locks the user out until it is cleared by hand.
	# Rejections here are expected and client-triggerable, so they skip the
	# Error Log table (a DB write per request, floodable by anyone).
	frappe.flags.oan_quiet_reject = True
	try:
		_check_csrf(request, prefix)
		_authenticate_token(token, config)
	except (frappe.AuthenticationError, frappe.PermissionError, frappe.ServiceUnavailableError):
		frappe.local.response.pop("message", None)
	finally:
		frappe.flags.oan_quiet_reject = False


def _require_api_key_session(roles: tuple) -> None:
	"""Accept only a session Frappe set from `Authorization: token <key>:<secret>`.

	Frappe validated the key and secret before this hook ran. The scheme check
	matters because a desk `sid` cookie also sets the session user. When the path
	names roles, the key's user must hold one, so a key belonging to a person
	cannot reach a partner route.
	"""
	user = _session_user()
	if _auth_scheme() != "token" or not user:
		_reject("API key required")
	if roles and not set(roles) & set(frappe.get_roles(user)):
		_reject(f"API key user {user} holds none of {sorted(roles)}")
	frappe.local.oan_auth_claims = None
	frappe.local.oan_auth_issuer_kind = AUTH_API_KEY
	frappe.local.oan_auth_login_option = None


def _authenticate_token(token: str, config: dict) -> None:
	"""Verify `token` and, when valid, make its user the request user."""
	# Dispatch on the unverified issuer: our own tokens verify in-process, any
	# other issuer must be the `issuer` of an enabled login option, whose IAM
	# validates it.
	issuer = iam_tokens.peek_issuer(token)
	delegated = issuer is not None and issuer != settings.issuer()
	service = None

	try:
		if delegated:
			service = iam_tokens.service_for_token(token)
			claims = iam_tokens.get_principal(token, service)
		else:
			claims = tokens.decode_access_token(token)
	except JWTKeyConfigurationError:
		# A server misconfiguration, not a bad token. Reported separately so an
		# operator sees "we have no keys" rather than a flood of 401s that look
		# like clients misbehaving.
		frappe.log_error(title="oan_auth_service: JWT key material unusable")
		frappe.throw(_("Authentication is misconfigured on this server"), frappe.ValidationError)
	except iam_tokens.IAMUnavailableError:
		# Not a verdict on the token: a 503 tells the frontend to retry, where a
		# 401 would log the user out. Already logged (rate-limited) by iam_tokens.
		frappe.local.response["message"] = _("Identity service unavailable")
		raise frappe.ServiceUnavailableError
	except tokens.TokenError as exc:
		_reject(f"Invalid or expired token: {exc}")

	# IAM's `sub` is the identity provider's id; the local user is derived from it.
	user = _provision_delegated_user(claims, service, token) if delegated else claims.get("sub")
	if not user or not frappe.db.exists("User", user):
		_reject("Invalid or expired token")

	enabled, must_change_password = frappe.db.get_value("User", user, ["enabled", MUST_CHANGE_PASSWORD_FIELD])
	if not enabled:
		_reject("Invalid or expired token")

	# An access token cannot be revoked, so one issued before a temporary password was
	# set would keep working for its remaining lifetime. The flag is what cuts it off.
	if must_change_password:
		_reject("Password change required")

	revocation_check = config.get("revocation_check")
	if revocation_check:
		reason = revocation_check(user)
		if reason:
			_reject(reason)

	# IAM principals carry no `scope` claim of ours; their roles were just synced.
	if not delegated:
		_verify_scope_still_held(user, claims)

	form_dict = getattr(frappe.local, "form_dict", None)
	# Deliberately sets the authenticated request user from validated JWT claims
	frappe.set_user(user)  # nosemgrep: frappe-semgrep-rules.rules.security.frappe-setuser
	if form_dict is not None:
		frappe.local.form_dict = form_dict

	# Exposed so consumer code can read the token it was authenticated with —
	# notably the `scope` claim, which this app records but cannot itself
	# enforce against Frappe's DocPerm layer (see api/v1/auth.py:_narrow_to_scope).
	frappe.local.oan_auth_claims = claims
	frappe.local.oan_auth_issuer_kind = "iam" if delegated else "local"
	# The `OAN IAM Service` row key the token came through, None for our own tokens.
	frappe.local.oan_auth_login_option = service.key if delegated else None


def _provision_delegated_user(claims: dict, service, token: str) -> str:
	"""Resolve or create the local user for an IAM principal, sync its roles and run login hooks.

	On safe methods (GET, HEAD, OPTIONS) it commits, and only when a user was
	created, roles changed or a hook reported a change: Frappe only commits
	unsafe methods, so a GET would otherwise roll back the user it just created.
	"""
	try:
		sub = claims.get("sub")
		if not sub or not isinstance(sub, str):
			raise tokens.TokenError("Principal has no sub")
		user = iam_users.user_name_for_sub(sub, service.key)
		if not iam_users.granted_roles(claims, service):
			# No role for this app: never create the user. An existing user
			# that lost its last role is stripped before the request is refused.
			# The strip persists only on safe methods, where it is committed here.
			# On POST/PUT/DELETE Frappe rolls back the rejected request, so the
			# strip is undone and the user stays blocked (no roles in the IAM
			# answer) until their next safe-method request commits it.
			if (
				frappe.db.exists("User", user)
				and iam_users.sync_roles(user, claims, service)
				and _is_safe_method()
			):
				frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit
			_reject(f"Principal {sub} of login option {service.key} has no roles for this application")
		created = not frappe.db.exists("User", user)
		iam_users.resolve_user(claims, service)
	except tokens.TokenError as exc:
		_reject(f"Invalid or expired token: {exc}")

	changed = created
	hooks_done_key = None
	if frappe.db.get_value("User", user, "enabled"):
		changed = iam_users.sync_roles(user, claims, service) or created
		hooks_done_key = _login_hooks_due(service, token)
		if hooks_done_key:
			# Once per token, before the consumer hooks, so they see the person's details.
			changed = iam_users.sync_profile(user, claims) or changed
			changed = _run_login_hooks(user, claims, service) or changed

	safe = _is_safe_method()
	if changed and safe:
		# Frappe rolls back safe methods, which would undo the provisioning. For
		# unsafe methods it commits on success and rolls back on failure, which
		# is the right outcome for provisioning too.
		frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit

	if hooks_done_key:
		ttl = iam_tokens.seconds_until_expiry(token)

		def mark_done():
			frappe.cache.set_value(hooks_done_key, 1, expires_in_sec=ttl)

		if safe:
			mark_done()
		else:
			# Only once the hooks' writes are committed: a request that fails
			# after this point rolls them back, and the hooks must run again.
			frappe.db.after_commit.add(mark_done)

	return user


def _login_hooks_due(service, token: str) -> str | None:
	"""The done-key for this token's login hooks, or None when they need not run.

	Hooks run once per token, not per request: until their done-key is set. A
	hook that fails leaves it unset, so it runs again on the next request.
	"""
	key = f"oan_auth:login_hook_done:{service.key}:{iam_tokens.token_digest(token)}"
	return None if frappe.cache.get_value(key) else key


def _run_login_hooks(user: str, claims: dict, service) -> bool:
	"""Run the consumer login hooks. Any failure refuses the request with nothing committed."""
	try:
		return iam_users.run_login_hooks(user, claims, service.key)
	except iam_users.LoginDenied as exc:
		frappe.db.rollback()
		frappe.local.response["message"] = exc.reason
		frappe.logger("oan_auth_service").info("login denied by hook for %s: %s", user, exc.reason)
		raise frappe.PermissionError(exc.reason)
	except Exception:
		# Already logged by run_login_hooks. Never grant: a broken hook must not
		# let a user in without the check it exists for.
		frappe.db.rollback()
		frappe.local.response["message"] = _("Login could not be completed")
		raise frappe.ServiceUnavailableError


def _is_safe_method() -> bool:
	request = getattr(frappe.local, "request", None)
	return request is not None and request.method in ("GET", "HEAD", "OPTIONS")


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
	frappe.local.response["message"] = _("Authentication failed")
	if frappe.flags.get("oan_quiet_reject"):
		frappe.logger("oan_auth_service").info("rejected request (exempt path): %s", reason)
	else:
		frappe.log_error(title="oan_auth_service: rejected request", message=reason)
	raise frappe.AuthenticationError
