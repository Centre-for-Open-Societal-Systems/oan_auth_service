"""Login, registration and token lifecycle endpoints.

These are whitelisted and must be listed as exempt paths by every consumer that
registers a namespace — they are how a caller obtains the token the middleware
demands, so requiring one here would deadlock.
"""

import secrets

import frappe
from frappe import _
from frappe.utils import cint
from frappe.utils.password import passlibctx
from pydantic import BaseModel, Field, field_validator, model_validator

from oan_auth_service.api import tokens
from oan_auth_service.api.utils import (
	SafeEmail,
	SafePhone,
	check_rate_limit,
	handle_api_errors,
	parse_multi_value,
	success_response,
	validate_password_complexity,
	validate_request,
)
from oan_auth_service.config import settings
from oan_auth_service.setup.install import LOGIN_EMAIL_FIELD

REFRESH_TOKEN_DOCTYPE = "OAN User Refresh Token"

# A precomputed hash of a value no password can equal, verified against on the
# user-not-found path so that path costs the same as the wrong-password path.
# See _authenticate() for why. Computed once at import: doing it per call would
# add the cost of *hashing* on top of the cost of verifying, making the miss
# path measurably slower than the hit path and reopening the oracle in the
# opposite direction.
_DUMMY_PASSWORD_HASH = passlibctx.hash("oan-auth-service:not-a-real-password:8f3c1d5e")


# The handles a person may type at login, in the order they are tried, each
# paired with the User field it resolves against. A list rather than an if-chain
# because this set grows: Frappe's own issue #26189 lists external login
# providers as the next case, and adding one should be a row here.
#
# `name` is first and is the synthetic id itself — service-to-service callers
# and anything holding a JWT `sub` already have it, so they resolve without
# touching the other lookups.
LOGIN_HANDLE_FIELDS = ("name", LOGIN_EMAIL_FIELD, "mobile_no")


def _resolve_login_identifier(usr: str) -> str | None:
	"""Map whatever the caller typed onto the canonical `User.name`, or None.

	Accounts are keyed by an opaque synthetic address that is never shown to the
	account holder, so with the sole exception of internal callers the string a
	person types at login is not the primary key and has to be looked up.

	Resolution lives here rather than in Frappe's `allow_login_using_mobile_number`
	/ `allow_login_using_user_name` system settings on purpose. Those are
	site-wide and would also change desk login, and the username one is actively
	unsafe on this schema: `User.validate_username` fills a blank username in
	from `first_name` (user/user.py:744) and silently blanks it on collision
	(user.py:753-758), so enabling it would make every account answer to its
	owner's first name.

	Ambiguity fails closed. `oan_login_email` and `mobile_no` are both unique at
	the database level, so two matches should be impossible — but a lookup that
	silently took the first row would turn any future loss of that guarantee, to
	a bad migration or a hand-edit, into an account-takeover path rather than an
	error. Two rows is a bug, and it is reported as one.
	"""
	for fieldname in LOGIN_HANDLE_FIELDS:
		matches = frappe.get_all("User", filters={fieldname: usr}, pluck="name", limit=2)

		if len(matches) == 1:
			return matches[0]

		if len(matches) > 1:
			frappe.logger().error(
				f"Ambiguous login identifier: {len(matches)} users share a value on User.{fieldname}. "
				"Refusing to resolve."
			)
			return None

	return None


def set_login_email(user: str, email: str | None) -> None:
	"""Change the address an account signs in with, in both places it is stored.

	The address lives twice: `User.oan_login_email`, which is authoritative and
	the only thing `_resolve_login_identifier` reads, and `Contact Email`, which
	exists so the rest of Frappe and any ERPNext-shaped integration can find it
	as ordinary contact data. Two writable homes for one value drift the moment
	either is updated alone — a user who changed their contact email would find
	their login unchanged, with nothing to flag the mismatch.

	So there is one function, and it is this one. Not whitelisted: who may change
	an account's login handle is a policy question, and the answer belongs to the
	consuming app rather than to the auth service.
	"""
	email = str(email).strip().lower() if email else None

	frappe.db.set_value("User", user, LOGIN_EMAIL_FIELD, email)

	contact = frappe.db.get_value("Contact", {"user": user}, "name")
	if not contact:
		return

	contact_doc = frappe.get_doc("Contact", contact)
	contact_doc.set("email_ids", [{"email_id": email, "is_primary": 1}] if email else [])
	contact_doc.save(ignore_permissions=True)


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
	`User.find_by_credentials` (frappe/core/doctype/user/user.py:844-846) returns
	early when no user row matches, so `check_password` — and its deliberately
	expensive pbkdf2_sha256 verify — never runs. An unknown user therefore
	answers in about a millisecond while a known user with a bad password takes
	tens. That gap is trivially measurable across a network and turns this
	endpoint into a "does this email have an account here?" lookup. Burning one
	equivalent verify on the miss path flattens it.

	Resolving the identifier first is what makes that defence exact rather than
	approximate. Frappe is handed the canonical `User.name`, so its own lookup
	always hits and always reaches `check_password`; the only path that skips the
	verify is the one this function pays for explicitly. The previous form
	guessed at existence with `frappe.db.exists("User", {"name": usr})`, which was
	right only while the typed identifier *was* the primary key — it would have
	answered "unknown" for every phone and every login-email sign-in and burned a
	second verify on top of a real one.
	"""
	from frappe.auth import LoginManager

	user = _resolve_login_identifier(usr)

	if user is None:
		try:
			passlibctx.verify("", _DUMMY_PASSWORD_HASH)
		except Exception:
			# Timing hygiene, not a control. If it fails the caller still gets
			# their AuthenticationError rather than a 500 that announces the
			# measure went wrong.
			pass
		raise frappe.AuthenticationError(_("Invalid login credentials"))

	# __new__ without __init__: we want authenticate() alone. LoginManager sets
	# only `self.user` in that method and reads nothing else it does not set.
	login_manager = LoginManager.__new__(LoginManager)
	login_manager.authenticate(user=user, pwd=pwd)

	return login_manager.user


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


class LoginSchema(BaseModel):
	usr: str = Field(..., min_length=1)
	pwd: str = Field(..., min_length=1)
	remember_me: bool = False
	scope: str | list[str] | None = None


class RegisterUserSchema(BaseModel):
	model_config = {"extra": "allow"}

	email: SafeEmail | None = None
	password: str = Field(..., min_length=8, max_length=128)
	full_name: str = Field(..., min_length=1, max_length=140)
	phone_number: SafePhone | None = None
	role: str | None = None
	roles: list[str] | str | None = None

	@field_validator("password")
	@classmethod
	def validate_password(cls, v: str) -> str:
		return validate_password_complexity(v)


class RefreshTokenSchema(BaseModel):
	refresh_token: str = Field(..., min_length=1)


class LogoutSchema(BaseModel):
	refresh_token: str = Field(..., min_length=1)


class ForgotPasswordSchema(BaseModel):
	usr: str = Field(..., min_length=1)


class ResetPasswordSchema(BaseModel):
	"""Completion of a reset over either channel.

	`key` arrives from an emailed link; `usr` + `otp` from an SMS code. One
	endpoint serves both because the caller should not have to know which channel
	their account was given — `forgot_password` decided that, from what the
	account actually has.
	"""

	key: str | None = None
	usr: str | None = None
	otp: str | None = None
	new_password: str = Field(..., min_length=8, max_length=128)

	@field_validator("new_password")
	@classmethod
	def validate_password(cls, v: str) -> str:
		return validate_password_complexity(v)

	@model_validator(mode="after")
	def exactly_one_channel(self):
		"""Reject a request that proves itself twice, or not at all.

		Accepting both would mean deciding which one wins, and the safe answer is
		that a request carrying a valid key *and* a wrong OTP is malformed rather
		than authorised.
		"""
		has_key = bool(self.key)
		has_otp = bool(self.usr and self.otp)

		if has_key == has_otp:
			raise ValueError(
				"Provide either `key` (from the emailed link) or both `usr` and `otp` "
				"(from the SMS code), but not both."
			)

		return self


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@validate_request(LoginSchema)
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
	return success_response(data=pair)


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@validate_request(RegisterUserSchema)
@handle_api_errors
def register_user(
	password: str,
	full_name: str,
	email: str | None = None,
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
	if email and str(email).strip():
		# Lowercased because this is a login handle and the resolver matches it
		# exactly. Frappe normalises the case of `User.email` in `autoname`
		# (user/user.py:196); nothing normalises a custom field, so it is done
		# here — otherwise "A@b.com" and "a@b.com" become two accounts that both
		# satisfy the unique index and neither of which the owner can predict.
		email = str(email).strip().lower()
		if (
			frappe.db.exists("User", {LOGIN_EMAIL_FIELD: email})
			or frappe.db.exists("Contact Email", {"email_id": email})
			or frappe.db.exists("User", email)
		):
			frappe.throw(_("A user with this email address already exists."), frappe.ValidationError)
	else:
		email = None

	if phone_number:
		if frappe.db.exists("User", {"mobile_no": phone_number}) or frappe.db.exists(
			"Contact Phone", {"phone": phone_number}
		):
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

	name = f"{frappe.generate_hash(length=16)}@id.openagrinet.internal"
	while frappe.db.exists("User", name):
		name = f"{frappe.generate_hash(length=16)}@id.openagrinet.internal"

	user_doc = frappe.get_doc(
		{
			"doctype": "User",
			# Forces `name` to the synthetic id: User.autoname copies `email` into
			# `name` on insert (user/user.py:197). The real address goes to
			# LOGIN_EMAIL_FIELD instead, because `validate` reassigns
			# `self.email = self.name` on every save (user/user.py:222) and would
			# overwrite anything else stored here.
			"email": name,
			LOGIN_EMAIL_FIELD: email,
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

	if email or phone_number:
		contact_doc = frappe.get_doc(
			{
				"doctype": "Contact",
				"first_name": first_name,
				"last_name": last_name,
				"user": user_doc.name,
				"email_ids": [{"email_id": email, "is_primary": 1}] if email else [],
				"phone_nos": (
					[{"phone": phone_number, "is_primary_mobile_no": 1, "is_primary_phone": 1}]
					if phone_number
					else []
				),
				"links": [{"link_doctype": "User", "link_name": user_doc.name}],
			}
		)
		contact_doc.insert(ignore_permissions=True)

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

	pair = _issue_token_pair(user_doc.name, remember_me=False)
	# Explicit commit to ensure user and initial token state are persisted
	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit
	return success_response(data=pair)


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@validate_request(RefreshTokenSchema)
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
	return success_response(data=pair)


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@validate_request(LogoutSchema)
@handle_api_errors
def logout(refresh_token: str):
	"""Revoke a refresh token. Access tokens expire on their own."""
	if not refresh_token:
		return success_response(data={"revoked": False})

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
	return success_response(data={"revoked": True})


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


def _otp_cache_key(user: str) -> str:
	return f"oan_auth:pwreset_otp:{user}"


def _otp_attempts_cache_key(user: str) -> str:
	return f"oan_auth:pwreset_otp_attempts:{user}"


def _sms_gateway_configured() -> bool:
	"""Whether an SMS actually has somewhere to go.

	Worth checking because `_send_sms` does not fail when it has nowhere to send:
	with no gateway URL it calls `msgprint` and returns normally
	(sms_settings.py:112). Left unguarded, a phone-only reset would report
	success to the caller, record nothing, and deliver nothing — the user would
	wait for a code that was never sent.
	"""
	if frappe.get_hooks("send_sms"):
		return True

	return bool(frappe.db.get_single_value("SMS Settings", "sms_gateway_url"))


def _deliver_reset_by_sms(user: str, mobile_no: str) -> None:
	"""Generate a numeric reset code and text it to the account's phone."""
	from frappe.core.doctype.sms_settings.sms_settings import _send_sms

	if not _sms_gateway_configured():
		# Logged, not raised. The caller must not learn that this account was the
		# phone-only kind, and must not be able to tell a misconfigured site from
		# an address that has no account — both of which a distinct error here
		# would reveal.
		frappe.logger().error(
			"Password reset requested for a phone-only account but no SMS gateway is configured; "
			"no code was sent."
		)
		return

	otp = "".join(secrets.choice("0123456789") for _ in range(settings.password_reset_otp_length()))

	# Stored as a pbkdf2 hash rather than the raw code or a SHA-256 of it. Frappe
	# stores emailed reset keys as a plain SHA-256 (user/user.py:491), which is
	# fine for a 32-character random key but not for a six-digit one: anyone
	# reading a Redis dump could enumerate the whole 10^6 keyspace against a fast
	# hash in milliseconds.
	frappe.cache.set_value(
		_otp_cache_key(user),
		passlibctx.hash(otp),
		expires_in_sec=settings.password_reset_otp_ttl(),
	)
	# Cleared so a fresh code always gets its full allowance, rather than
	# inheriting the failed guesses spent against the code it replaced.
	frappe.cache.delete_value(_otp_attempts_cache_key(user))

	minutes = settings.password_reset_otp_ttl() // 60
	_send_sms(
		[mobile_no],
		_("{0} is your password reset code. It expires in {1} minutes.").format(otp, minutes),
		success_msg=False,
	)


def _deliver_reset_by_email(user_doc, login_email: str) -> None:
	"""Mail a reset link to the address the account actually signs in with.

	Frappe addresses this mail to `self.email` (user/user.py:578), which on this
	schema is always the synthetic `@id.openagrinet.internal` address — no
	mailbox exists behind it, so the link would be delivered nowhere.

	The recipient is redirected by assigning the real address to the in-memory
	document and letting Frappe send as it normally would. The alternative,
	taking the link from `_reset_password(send_email=False)` and calling
	`frappe.sendmail` directly, means restating the argument set that
	`send_login_mail` assembles (user/user.py:556-562) — `first_name`,
	`created_by` and the rest that `password_reset.html` renders — and losing the
	`reset_password_template` System Setting, which lets a site replace the mail
	with its own Email Template (user/user.py:510). Both would be silently wrong:
	a missing arg renders as a blank, not an error.

	Nothing persists. `_reset_password` writes the key with `db_set`, which
	updates only that column, and this document is discarded afterwards — so the
	assignment below never reaches `tabUser.email`, where `validate` would
	overwrite it with `name` on the next save anyway (user/user.py:222).
	"""
	user_doc.email = login_email
	user_doc._reset_password(send_email=True)


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@validate_request(ForgotPasswordSchema)
@handle_api_errors
def forgot_password(usr: str):
	"""Start a reset over whichever channel the account actually has.

	One endpoint, two deliveries. An account with a login email gets a link; a
	phone-only account gets a numeric code by SMS, because on this schema the
	link would otherwise be mailed to a synthetic address with no mailbox behind
	it. The caller does not choose, and is not told which happened: the client
	knows which kind of identifier its user typed, so it can show the right next
	screen without the server confirming that an account exists.

	Every path returns the same message and the same status. Frappe's own
	`reset_password` is careful about this (user/user.py:1150-1152) and so is
	this: an unknown identifier, a disabled account, a site with no SMS gateway
	and a successful send are indistinguishable *in the response*.

	They are not indistinguishable in timing, and this deliberately does not try
	to be. The three paths cost wildly different amounts — a synchronous
	`sendmail`, a pbkdf2 hash, an immediate return — and flattening that would
	mean padding every request to the slowest one, which hands an attacker a
	cheap way to tie up workers. The rate limit below is the control that makes
	the remaining timing signal impractical to harvest; it is not zero, and
	should not be described as such.
	"""
	# Rate limited on the caller rather than the account, because the account is
	# exactly what an attacker is trying to discover — a per-user limit would
	# not apply until after the lookup that answers their question.
	check_rate_limit(f"oan_auth:pwreset:{frappe.local.request_ip}", limit=10, window=3600)

	user = _resolve_login_identifier(usr)

	if user:
		login_email, mobile_no, enabled = frappe.db.get_value(
			"User", user, [LOGIN_EMAIL_FIELD, "mobile_no", "enabled"]
		)

		if enabled:
			if login_email:
				_deliver_reset_by_email(frappe.get_doc("User", user), login_email)
			elif mobile_no:
				_deliver_reset_by_sms(user, mobile_no)

		# Explicit commit to ensure the reset key and any queued mail are stored
		frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit

	return success_response(message=_("If that account exists, reset instructions have been sent."))


def _verify_password_reset_otp(user: str, otp: str) -> bool:
	"""Check a submitted code, spending one of its allowed attempts.

	The code is destroyed on success and on exhausting the attempt budget, so a
	given code can be used once and guessed at only a bounded number of times.
	Burning it at the cap rather than merely refusing the attempt is what stops
	an attacker from working through the keyspace: without it, six digits and an
	unlimited retry loop is not a control at all.
	"""
	# `expires=True` on both reads. Without it `get_value` memoises into
	# frappe.local (redis_wrapper.py:79-85), and for a key that is meant to
	# expire that means a long-running request could still be served a code
	# Redis has already dropped.
	stored = frappe.cache.get_value(_otp_cache_key(user), expires=True)
	if not stored:
		return False

	attempts = cint(frappe.cache.get_value(_otp_attempts_cache_key(user), expires=True))
	if attempts >= settings.password_reset_otp_max_attempts():
		frappe.cache.delete_value(_otp_cache_key(user))
		frappe.cache.delete_value(_otp_attempts_cache_key(user))
		return False

	# Recorded before the comparison, so a guess still counts if verification
	# raises or the request dies partway through.
	frappe.cache.set_value(
		_otp_attempts_cache_key(user),
		attempts + 1,
		expires_in_sec=settings.password_reset_otp_ttl(),
	)

	if not passlibctx.verify(otp, stored):
		return False

	frappe.cache.delete_value(_otp_cache_key(user))
	frappe.cache.delete_value(_otp_attempts_cache_key(user))
	return True


def _mint_reset_key(user: str) -> str:
	"""Issue a reset key for someone who has already proved themselves by OTP.

	Converges the SMS path onto the emailed-link path instead of writing the
	password directly. Both channels then run the same `update_password` and get
	the same bookkeeping — strength test, `logout_on_password_reset` handling,
	`last_password_reset_date`, key clearing — rather than a second
	implementation that would drift the first time Frappe changed any of it.

	Mirrors `User._reset_password` (user/user.py:490-493): the column stores a
	SHA-256 of the key, and the expiry check reads
	`last_reset_password_key_generated_on`, so both are written here too.
	"""
	from frappe.utils.data import sha256_hash

	key = frappe.generate_hash()

	frappe.db.set_value(
		"User",
		user,
		{
			"reset_password_key": sha256_hash(key),
			"last_reset_password_key_generated_on": frappe.utils.now_datetime(),
		},
		update_modified=False,
	)

	return key


@frappe.whitelist(allow_guest=True)  # nosemgrep: frappe-semgrep-rules.rules.security.guest-whitelisted-method
@validate_request(ResetPasswordSchema)
@handle_api_errors
def reset_password(new_password: str, key: str | None = None, usr: str | None = None, otp: str | None = None):
	"""Complete a reset from either channel, and revoke live sessions.

	Takes the `key` from an emailed link, or `usr` plus the `otp` texted to a
	phone-only account. The schema guarantees exactly one of the two arrived. The
	OTP path exchanges a verified code for a freshly minted key and then follows
	the identical path, so there is only one place where a password is actually
	changed.
	"""
	from frappe.core.doctype.user.user import update_password as frappe_update_password
	from frappe.utils.data import sha256_hash

	if otp:
		check_rate_limit(f"oan_auth:pwreset_otp:{frappe.local.request_ip}", limit=20, window=3600)

		resolved = _resolve_login_identifier(usr)

		if not resolved or not _verify_password_reset_otp(resolved, otp):
			# One message for an unknown identifier, a wrong code, an expired code
			# and an exhausted one. Distinguishing them would tell an attacker
			# which half of the pair to keep working on.
			raise frappe.AuthenticationError(_("Invalid or expired reset code"))

		key = _mint_reset_key(resolved)

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

	return success_response(message=result)
