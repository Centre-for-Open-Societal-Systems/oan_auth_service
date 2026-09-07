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
from oan_auth_service.api.utils import handle_api_errors
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


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@handle_api_errors
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

	# Explicit commit to immediately persist token hash before returning
	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit
	return pair


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@handle_api_errors
def register_user(
	email: str,
	password: str,
	full_name: str,
	phone_number: str | None = None,
	role: str | None = None,
	roles: list[str] | str | None = None,
	**kwargs,
):
	"""Create a User and its role assignment, trigger registered hooks, and issue the first token pair.

	- Guest callers can self-assign roles listed in `jwt_self_registerable_roles` in site_config.json.
	- If no role is requested, `jwt_default_registration_role` is assigned (if configured).
	- Authenticated administrators (e.g. System Manager) can assign any valid role.
	- Broadcasts `on_user_registered` hooks for consuming apps to initialize and link domain DocTypes.
	"""
	from oan_auth_service.api.utils import (
		parse_multi_value,
		validate_email_string,
		validate_password_complexity,
		validate_phone_string,
	)

	if not email or not str(email).strip():
		frappe.throw(_("Email is required."), frappe.ValidationError)

	if not password or not str(password).strip():
		frappe.throw(_("Password is required."), frappe.ValidationError)

	if not full_name or not str(full_name).strip():
		frappe.throw(_("Full name is required."), frappe.ValidationError)

	validate_email_string(email)
	validate_password_complexity(password)

	if phone_number:
		phone_number = validate_phone_string(phone_number)

	if frappe.db.exists("User", email):
		frappe.throw(_("A user with this email address already exists."), frappe.ValidationError)

	if phone_number and frappe.db.exists("User", {"mobile_no": phone_number}):
		frappe.throw(_("A user with this phone number already exists."), frappe.ValidationError)

	# Combine singular `role` or `roles` list/string
	raw_roles = []
	if role:
		raw_roles.append(role)
	if roles:
		raw_roles.extend(parse_multi_value(roles))

	requested_roles = parse_multi_value(raw_roles)

	is_admin_caller = frappe.session.user != "Guest" and "System Manager" in frappe.get_roles(
		frappe.session.user
	)

	if not requested_roles:
		default_role = frappe.conf.get("jwt_default_registration_role")
		if default_role:
			requested_roles = [default_role]
	elif not is_admin_caller:
		# Enforce self-registration whitelist for non-admin / guest callers
		allowed_roles = frappe.conf.get("jwt_self_registerable_roles") or []
		if not allowed_roles:
			frappe.throw(
				_("Role assignment is not allowed during public registration."), frappe.PermissionError
			)
		unallowed = [r for r in requested_roles if r not in allowed_roles]
		if unallowed:
			frappe.throw(
				_("The following roles cannot be self-assigned: {0}").format(", ".join(sorted(unallowed))),
				frappe.PermissionError,
			)

	first_name, _sep, last_name = full_name.strip().partition(" ")

	user_doc = frappe.get_doc(
		{
			"doctype": "User",
			"email": email,
			"first_name": first_name,
			"last_name": last_name,
			"mobile_no": phone_number if phone_number else None,
			"send_welcome_email": 0,
			"enabled": 1,
			"new_password": password,
			"roles": [{"role": r} for r in requested_roles],
		}
	)
	user_doc.insert(ignore_permissions=True)

	# Broadcast on_user_registered so consuming apps can create and link their own
	# domain records. Every subscriber is called on every registration — the auth
	# service does not know which roles map to which doctypes, so each handler is
	# responsible for checking `roles` and returning early if it isn't concerned.
	#
	# Failures deliberately propagate: handle_api_errors rolls the transaction back,
	# so a handler that cannot create its record also undoes the User insert. A
	# registration that half-succeeded — an account with a role but no linked
	# record, and a token pair already in the caller's hands — is worse than one
	# that visibly failed and can be retried.
	hook_kwargs = {k: v for k, v in kwargs.items() if k != "cmd"}
	for hook_path in frappe.get_hooks("on_user_registered"):
		try:
			fn = frappe.get_attr(hook_path)
			fn(user_doc=user_doc, role=role, roles=requested_roles, **hook_kwargs)
		except Exception:
			frappe.logger().error(f"on_user_registered hook failed, aborting registration: {hook_path}")
			raise

	pair = _issue_token_pair(email, remember_me=False)
	# Explicit commit to ensure user and initial token state are persisted
	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit
	return pair


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@handle_api_errors
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
	# Unconditionally commit deletion to prevent replay attacks
	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit

	if frappe.utils.get_datetime(row.expires_at) < frappe.utils.now_datetime():
		raise frappe.AuthenticationError(_("Invalid refresh token"))

	if not frappe.db.get_value("User", row.user, "enabled"):
		# A user disabled since the token was issued. Caught here because this is
		# the only point in a session's life where storage is consulted at all.
		raise frappe.AuthenticationError(_("Invalid refresh token"))

	# Roles are re-resolved from the database on every refresh, which is what
	# bounds the staleness of the roles claim to one access-token TTL.
	pair = _issue_token_pair(row.user, remember_me=cint(row.remember_me))

	# Explicit commit to persist newly rotated token pair
	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit
	return pair


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@handle_api_errors
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
		# Explicit commit to ensure revoked token cannot be re-used
		frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit

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


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@handle_api_errors
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
	# Explicit commit to ensure queued email and reset key are stored
	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit

	return {"message": _("If that account exists, a reset link has been sent.")}


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@handle_api_errors
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
		# Explicit commit to ensure session revocation and password change are finalized
		frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit

	return {"message": result}
