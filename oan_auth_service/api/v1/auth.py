"""Login, registration and token lifecycle endpoints.

These are whitelisted and must be listed as exempt paths by every consumer that
registers a namespace — they are how a caller obtains the token the middleware
demands, so requiring one here would deadlock.
"""

import frappe
from frappe import _
from frappe.utils import cint
from frappe.utils.password import passlibctx

from oan_auth_service.api import tokens
from oan_auth_service.config import settings

REFRESH_TOKEN_DOCTYPE = "OAN User Refresh Token"

# A precomputed hash of a value no password can equal, verified against on the
# user-not-found path so that path costs the same as the wrong-password path.
# See _authenticate() for why. Computed once at import: doing it per call would
# add the cost of *hashing* on top of the cost of verifying, making the miss
# path measurably slower than the hit path and reopening the oracle in the
# opposite direction.
_DUMMY_PASSWORD_HASH = passlibctx.hash("oan-auth-service:not-a-real-password:8f3c1d5e")


def _authenticate(usr: str, pwd: str) -> str:
	"""Validate credentials and return the canonical user id, or throw.

	Goes through Frappe's `LoginManager.authenticate()` rather than calling
	`check_password()` directly. That method owns the per-IP and per-user
	`LoginAttemptTracker` lockout, the disabled-user check and the 2FA
	interaction; reimplementing the credential check here would silently opt out
	of all three, and would keep opting out of whatever gets added to it later.

	`LoginManager.__init__` is bypassed deliberately. Its constructor either runs
	a full interactive login or resumes a desk session depending on the request
	path, and neither is what a token endpoint wants — we need the credential
	check on its own, without a session cookie being created as a side effect.

	The dummy-hash step closes a user-enumeration oracle in Frappe itself.
	`User.find_by_credentials` (frappe/core/doctype/user/user.py:855-857) returns
	early when no user row matches, so `check_password` — and its deliberately
	expensive pbkdf2_sha256 verify — never runs. An unknown user therefore
	answers in about a millisecond while a known user with a bad password takes
	tens. That gap is trivially measurable across a network and turns this
	endpoint into a "does this email have an account here?" lookup. Burning one
	equivalent verify on the miss path flattens it.
	"""
	from frappe.auth import LoginManager

	# __new__ without __init__: we want authenticate() alone. LoginManager sets
	# only `self.user` in that method and reads nothing else it does not set.
	login_manager = LoginManager.__new__(LoginManager)

	try:
		login_manager.authenticate(user=usr, pwd=pwd)
	except frappe.AuthenticationError:
		_equalize_timing_for_unknown_user(usr)
		raise

	return login_manager.user


def _equalize_timing_for_unknown_user(usr: str) -> None:
	"""Spend a password-verify if the failure was "no such user".

	Only runs on the already-failing path, so it costs nothing in the normal
	case. The extra `exists` query is dwarfed by the verify it guards.
	"""
	try:
		if not frappe.db.exists("User", {"name": usr}):
			passlibctx.verify("", _DUMMY_PASSWORD_HASH)
	except Exception:
		# This is a timing-hygiene measure, not a control. If it fails we still
		# want the caller to get their AuthenticationError, not a 500 that
		# announces the existence check went wrong.
		pass


def _narrow_to_scope(roles: list[str], requested: str | list[str] | None) -> list[str] | None:
	"""Resolve a client-requested scope against the roles the server resolved.

	This is the only safe reading of "pass the role at login". The request can
	name a subset of what the user already holds, and the token records that it
	was minted for that purpose. It can never add a role: every name is checked
	against the server-resolved set, and anything not held is rejected outright
	rather than quietly dropped, so a client asking for something it cannot have
	learns that instead of receiving a token that silently does less.

	IMPORTANT — what this does not do. The scope narrows the `scope` claim, which
	consumers can branch on. It does NOT narrow Frappe's own DocPerm layer:
	`frappe.set_user()` re-derives the full role set from
	`frappe.cache.hget("roles", ...)`, and overriding that cache is process-wide
	shared state that would leak across requests. A scoped token is therefore a
	statement of intent that consumer code can enforce, not a capability
	reduction enforced by the framework. Treat it as defence in depth.
	"""
	if not requested:
		return None

	if isinstance(requested, str):
		requested = [r.strip() for r in requested.split(",") if r.strip()]

	held = set(roles)
	unheld = [r for r in requested if r not in held]

	if unheld:
		# Deliberately reported only to an already-authenticated caller, so this
		# leaks nothing to an unauthenticated attacker.
		frappe.throw(
			_("Requested scope includes roles you do not hold: {0}").format(", ".join(sorted(unheld))),
			frappe.PermissionError,
		)

	return sorted(set(requested))


def _issue_token_pair(user: str, remember_me: bool, scope: list[str] | None = None) -> dict:
	"""Mint an access/refresh pair and persist the refresh token's hash."""
	roles = tokens.resolve_roles(user)
	access_token, expires_in = tokens.issue_access_token(user, roles, scope=scope)

	refresh_token = tokens.generate_refresh_token()
	refresh_ttl = settings.refresh_token_ttl(remember_me)

	frappe.get_doc(
		{
			"doctype": REFRESH_TOKEN_DOCTYPE,
			"user": user,
			"token_hash": tokens.hash_refresh_token(refresh_token),
			"expires_at": frappe.utils.add_to_date(frappe.utils.now_datetime(), seconds=refresh_ttl),
			"remember_me": cint(remember_me),
		}
	).insert(ignore_permissions=True)

	return {
		"access_token": access_token,
		"refresh_token": refresh_token,
		"token_type": "Bearer",
		"expires_in": expires_in,
		"user": user,
		"roles": roles,
		"scope": scope,
	}


@frappe.whitelist(allow_guest=True)
def login(usr: str, pwd: str, remember_me: bool = False, scope: str | list[str] | None = None):
	"""Authenticate and issue an access token plus a refresh token.

	`scope` is optional and may only narrow — see `_narrow_to_scope`. Roles are
	always resolved server-side from the authenticated user; nothing the caller
	sends can widen them.
	"""
	user = _authenticate(usr, pwd)

	roles = tokens.resolve_roles(user)
	narrowed = _narrow_to_scope(roles, scope)

	pair = _issue_token_pair(user, remember_me=cint(remember_me), scope=narrowed)

	frappe.db.commit()
	return pair


@frappe.whitelist(allow_guest=True)
def register_user(**kwargs):
	"""Create a User and its role assignment, then issue a first token pair."""
	raise NotImplementedError(
		"Registration is intentionally unimplemented in the shared service. Which "
		"roles a new account may self-assign, whether signup is open at all, and what "
		"verification it requires are product decisions that differ per consumer — "
		"and a wrong default here is a privilege-escalation hole in every consumer at "
		"once. Implement it in the consuming app and call _issue_token_pair()."
	)


@frappe.whitelist(allow_guest=True)
def refresh(refresh_token: str):
	"""Exchange a refresh token for a new pair, rotating the stored row.

	The presented token is single-use: the row backing it is deleted whether the
	exchange succeeds or fails, so a replayed token cannot mint a second pair.
	"""
	if not refresh_token:
		raise frappe.AuthenticationError(_("Invalid refresh token"))

	token_hash = tokens.hash_refresh_token(refresh_token)

	row = frappe.db.get_value(
		REFRESH_TOKEN_DOCTYPE,
		{"token_hash": token_hash},
		["name", "user", "expires_at", "remember_me"],
		as_dict=True,
	)

	if not row:
		raise frappe.AuthenticationError(_("Invalid refresh token"))

	# Deleted before any validity decision. Rotation has to be unconditional: if
	# the row survived a rejected exchange, a stolen token could be retried, and
	# if it survived a successful one, the old token would remain live alongside
	# its replacement.
	frappe.delete_doc(
		REFRESH_TOKEN_DOCTYPE, row.name, ignore_permissions=True, force=True, delete_permanently=True
	)
	frappe.db.commit()

	if frappe.utils.get_datetime(row.expires_at) < frappe.utils.now_datetime():
		raise frappe.AuthenticationError(_("Invalid refresh token"))

	if not frappe.db.get_value("User", row.user, "enabled"):
		# A user disabled since the token was issued. Caught here because this is
		# the only point in a session's life where storage is consulted at all.
		raise frappe.AuthenticationError(_("Invalid refresh token"))

	# Roles are re-resolved from the database on every refresh, which is what
	# bounds the staleness of the roles claim to one access-token TTL.
	pair = _issue_token_pair(row.user, remember_me=cint(row.remember_me))

	frappe.db.commit()
	return pair


@frappe.whitelist(allow_guest=True)
def logout(refresh_token: str):
	"""Revoke a refresh token. Access tokens expire on their own."""
	if not refresh_token:
		return {"revoked": False}

	token_hash = tokens.hash_refresh_token(refresh_token)
	name = frappe.db.get_value(REFRESH_TOKEN_DOCTYPE, {"token_hash": token_hash}, "name")

	if name:
		frappe.delete_doc(
			REFRESH_TOKEN_DOCTYPE, name, ignore_permissions=True, force=True, delete_permanently=True
		)
		frappe.db.commit()

	# Reports success either way. Whether a given token string was live is not
	# something an unauthenticated caller should be able to probe for.
	return {"revoked": True}


def revoke_all_for_user(user: str) -> int:
	"""Delete every refresh token held by `user`. Returns the number removed.

	Not whitelisted: this is the primitive behind "log out everywhere" and
	behind a consumer's own response to a compromise, and the policy for when
	either fires belongs to the consumer.
	"""
	names = frappe.get_all(REFRESH_TOKEN_DOCTYPE, filters={"user": user}, pluck="name")

	for name in names:
		frappe.delete_doc(
			REFRESH_TOKEN_DOCTYPE, name, ignore_permissions=True, force=True, delete_permanently=True
		)

	return len(names)


def on_logout(login_manager):
	"""Registered as Frappe's `on_logout` hook.

	Without this, a desk logout ends the session cookie but leaves every refresh
	token live for its full lifetime — a user who believes they logged out has
	not, from this service's point of view.
	"""
	user = getattr(login_manager, "user", None)
	if user and user != "Guest":
		revoke_all_for_user(user)


@frappe.whitelist(allow_guest=True)
def forgot_password(usr: str):
	"""Send a password-reset email, without revealing whether the account exists.

	Delegates to Frappe's own `reset_password`, which already returns an
	identical response for a missing, disabled or restricted user (user.py:1159)
	and clears the messages that would otherwise leak the difference. Duplicating
	that logic here would mean maintaining a second copy of an enumeration
	defence that Frappe has already thought carefully about.
	"""
	from frappe.core.doctype.user.user import reset_password as frappe_reset_password

	frappe_reset_password(user=usr)
	frappe.db.commit()

	return {"message": _("If that account exists, a reset link has been sent.")}


@frappe.whitelist(allow_guest=True)
def reset_password(key: str, new_password: str):
	"""Complete a reset using the key from the email, and revoke live sessions."""
	from frappe.core.doctype.user.user import update_password as frappe_update_password
	from frappe.utils.data import sha256_hash

	# Resolved before the update, not after: update_password clears the key on
	# success, so looking it up afterwards would always miss and silently skip
	# the revocation below. The column stores a SHA-256 of the emailed key
	# (user.py:491), so the raw key has to be hashed to match it.
	user = frappe.db.get_value("User", {"reset_password_key": sha256_hash(key)}, "name")

	result = frappe_update_password(new_password=new_password, key=key)

	if user:
		# A password change has to invalidate refresh tokens. Otherwise the reset
		# a user performs *because* they were compromised leaves the attacker's
		# session running — the exact scenario the reset was meant to end.
		revoke_all_for_user(user)
		frappe.db.commit()

	return {"message": result}
