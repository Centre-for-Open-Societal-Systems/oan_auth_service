"""Local `User` records for people who sign in through an OpenG2P IAM service.

Identity is the login option's key plus the principal's `sub`, the identity
provider's stable user id: it does not change when the person's email or
username does. The key is part of it because the `sub` values of two identity
providers can collide. The local `User.name` is
`<sha256(f"{key}:{sub}")[:32]>@iam.internal`, the same synthetic-name
convention local accounts use (`<hash>@id.openagrinet.internal`, see
api/v1/auth.py). Hashing keeps the name a valid email whatever characters the
provider puts in `sub`, and keeps case-sensitive subs distinct (Frappe
lowercases `User.name`; hex is already lowercase). `User.name` is the primary
key, so the lookup is indexed. This is why a row's `key` cannot change: a
renamed key would create new local users.

Accounts are created on first sign-in with no password. They must never gain
one: a password would be a way in that survives removal from the identity
provider, so the local login, reset and temporary-password flows refuse these
accounts (see `is_delegated_user`).

The login option is the only source of these users' roles. Their Frappe roles
are set to exactly the row's `default_roles` plus the roles IAM lists under the
row's `application` (`client_roles[application]`), keeping those that exist as
Frappe roles. Role names are used as-is. IAM's principal is cached until the
token's `exp` (see `iam_tokens.get_principal`), so a role added or removed in
the identity provider takes effect when the user gets a new token, not on the
next request.
"""

import hashlib
import re
from datetime import date, datetime

import frappe

from oan_auth_service.api.tokens import TokenError

DELEGATED_USER_DOMAIN = "iam.internal"

# Consumer apps list functions under this hook to act on a delegated login.
LOGIN_HOOK = "oan_auth_on_delegated_login"


# Never granted by a login option, whether as a default role or by IAM's token roles:
# `default_roles` go to anyone the provider authenticates, and IAM's role names are
# used as-is, so a privileged role of that name would make its holder an admin here.
REFUSED_ROLES = frozenset({"System Manager", "Administrator", "Guest", "All", "Desk User"})


class LoginDenied(Exception):
	"""Raised by an `oan_auth_on_delegated_login` hook to refuse the login with a 403."""

	def __init__(self, reason: str = "Login denied"):
		super().__init__(reason)
		self.reason = reason


def user_name_for_sub(sub: str, login_option: str) -> str:
	digest = hashlib.sha256(f"{login_option}:{sub}".encode()).hexdigest()[:32]
	return f"{digest}@{DELEGATED_USER_DOMAIN}"


def is_delegated_user(user: str | None) -> bool:
	"""Whether `user` was provisioned by delegated login and must stay passwordless."""
	return bool(user) and user.endswith(f"@{DELEGATED_USER_DOMAIN}")


def resolve_user(principal: dict, service) -> str:
	"""Return the local `User` for an IAM `principal` of login option `service`, creating it on first login."""
	sub = principal.get("sub")
	if not sub or not isinstance(sub, str):
		raise TokenError("Principal has no sub")

	user = user_name_for_sub(sub, service.key)
	if not frappe.db.exists("User", user):
		_create_user(user, principal)
	return user


def _names(principal: dict) -> tuple[str, str]:
	"""`(first_name, last_name)` of the person: the provider's `given_name` and `family_name`, else its `name` split at the first space."""
	given = (principal.get("given_name") or "").strip()
	family = (principal.get("family_name") or "").strip()
	if given or family:
		return given, family
	first, _sep, last = (principal.get("name") or "").strip().partition(" ")
	return first, last.strip()


def _create_user(user: str, principal: dict) -> None:
	first_name, last_name = _names(principal)
	user_doc = frappe.get_doc(
		{
			"doctype": "User",
			# Forces `name` to the sub-derived id; see register_user for why.
			"email": user,
			"first_name": first_name or "IAM User",
			"last_name": last_name or None,
			"send_welcome_email": 0,
			"enabled": 1,
		}
	)
	try:
		user_doc.insert(ignore_permissions=True)
	except frappe.DuplicateEntryError:
		# Two first requests raced; the other one created it.
		frappe.db.rollback()


_MOBILE_PATTERN = re.compile(r"^\+?\d{6,15}$")
_BIRTH_DATE_FORMATS = ("%Y-%m-%d", "%Y/%m/%d")


def _birth_date(value) -> date | None:
	for fmt in _BIRTH_DATE_FORMATS:
		try:
			parsed = datetime.strptime(str(value).strip(), fmt).date()
		except ValueError:
			continue
		return parsed if parsed <= date.today() else None
	return None


def sync_profile(user: str, principal: dict) -> bool:
	"""Copy the person's details from the identity provider's claims onto their `User`.

	The provider is the authority for who the person is, so its claims replace
	what the account holds; a claim it does not send leaves the field as it is.
	`full_name` is derived from the two names, as Frappe does on save. Returns
	whether anything changed.

	Covers the fields a `User` has: names, mobile number, birth date, gender.
	Anything else (national id, address, ...) belongs to the consuming app's
	own records, which read the principal in an `oan_auth_on_delegated_login`
	hook.
	"""
	current = frappe.db.get_value(
		"User",
		user,
		["first_name", "last_name", "full_name", "mobile_no", "birth_date", "gender", "oan_login_email"],
		as_dict=True,
	)
	if not current:
		return False

	wanted: dict = {}
	first, last = _names(principal)
	if first or last:
		wanted["first_name"] = first or "IAM User"
		wanted["last_name"] = last or None
		wanted["full_name"] = " ".join(p for p in (first, last) if p)
	mobile = str(principal.get("phone_number") or "").strip().replace(" ", "")
	if _MOBILE_PATTERN.match(mobile):
		wanted["mobile_no"] = mobile
	birth_date = _birth_date(principal.get("birthdate")) if principal.get("birthdate") else None
	if birth_date:
		wanted["birth_date"] = birth_date
	gender = str(principal.get("gender") or "").strip().title()
	if gender and frappe.db.exists("Gender", gender):
		wanted["gender"] = gender

	changes = {k: v for k, v in wanted.items() if (current.get(k) or None) != (v or None)}
	email_changed = _sync_login_email(user, principal.get("email"), current.get("oan_login_email"))
	if not changes:
		return email_changed
	frappe.db.set_value("User", user, changes, update_modified=False)
	return True


def _sync_login_email(user: str, claim, current: str | None) -> bool:
	"""Record the provider's `email` claim as the account's login email.

	The column is unique, so a claim another account already holds is skipped
	rather than failing the sign-in. These accounts have no password, so the
	address is only an identifier, never a way in.
	"""
	email = str(claim or "").strip().lower()
	if not email or "@" not in email or email == (current or None):
		return False
	if frappe.db.exists("User", {"oan_login_email": email, "name": ("!=", user)}):
		return False
	from oan_auth_service.api.v1.auth import set_login_email

	set_login_email(user, email)
	return True


def granted_roles(principal: dict, service) -> set[str]:
	"""Frappe roles login option `service` grants `principal`.

	The row's `default_roles` plus the principal's roles under the row's
	`application`, limited to roles that exist in Frappe and are not in
	`REFUSED_ROLES`. Callers must treat empty as "no access".
	"""
	wanted = set(service.default_roles or [])
	if service.application:
		wanted |= set(((principal.get("client_roles") or {}).get(service.application)) or [])
	wanted -= REFUSED_ROLES
	if not wanted:
		return set()
	# One query for all roles, not an `exists` per role on every request.
	return set(frappe.get_all("Role", filters={"name": ("in", list(wanted))}, pluck="name"))


def sync_roles(user: str, principal: dict, service) -> bool:
	"""Set the user's Frappe roles to what `service` grants `principal`.

	Returns whether any role was added or removed.
	"""
	wanted = granted_roles(principal, service)
	held = set(frappe.get_all("Has Role", filters={"parent": user, "parenttype": "User"}, pluck="role"))

	to_add = sorted(wanted - held)
	to_remove = sorted(held - wanted)
	if not (to_add or to_remove):
		return False

	user_doc = frappe.get_doc("User", user)
	user_doc.flags.ignore_permissions = True
	if to_add:
		user_doc.add_roles(*to_add)
	if to_remove:
		user_doc.remove_roles(*to_remove)
	return True


def run_login_hooks(user: str, principal: dict, login_option: str) -> bool:
	"""Call every `oan_auth_on_delegated_login` hook, in app install order.

	Hook contract:
	    def on_delegated_login(user: str, principal: dict, login_option: str) -> bool:
	        # True if it changed anything, so the middleware commits on safe methods.
	        # Raise LoginDenied(reason) to refuse the login.

	`LoginDenied` propagates. Any other exception is logged and re-raised: a
	broken hook refuses the request, it never lets the user in without the
	check it exists for. Returns whether any hook reported a change.
	"""
	changed = False
	for hook_path in frappe.get_hooks(LOGIN_HOOK):
		try:
			hook = frappe.get_attr(hook_path)
			changed = bool(hook(user=user, principal=principal, login_option=login_option)) or changed
		except LoginDenied:
			raise
		except Exception:
			# Deferred: the refused request is rolled back, and an inserted row with it.
			frappe.log_error(
				title=f"{LOGIN_HOOK} hook failed: {hook_path}",
				message=frappe.get_traceback(),
				defer_insert=True,
			)
			raise
	return changed
