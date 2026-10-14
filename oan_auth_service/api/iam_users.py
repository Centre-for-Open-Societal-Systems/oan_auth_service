"""Local `User` records for people who sign in through the OpenG2P IAM service.

Identity is the principal's `sub`, the identity provider's stable user id: it
does not change when the person's email or username does. The local
`User.name` is `<sha256(sub)[:32]>@iam.internal`, the same synthetic-name
convention local accounts use (`<hash>@id.openagrinet.internal`, see
api/v1/auth.py). Hashing keeps the name a valid email whatever characters the
provider puts in `sub`, and keeps case-sensitive subs distinct (Frappe
lowercases `User.name`; hex is already lowercase). `User.name` is the primary
key, so the lookup is indexed.

Accounts are created on first sign-in with no password. They must never gain
one: a password would be a way in that survives removal from the identity
provider, so the local login, reset and temporary-password flows refuse these
accounts (see `is_delegated_user`).

IAM is the only source of these users' roles. Their Frappe roles are set to
exactly the roles IAM lists for this app (`client_roles[iam_application]`) that
also exist as Frappe roles. Role names are used as-is. IAM's principal is cached
until the token's `exp` (see `iam_tokens.get_principal`), so a role added or
removed in the identity provider takes effect when the user gets a new token,
not on the next request.
"""

import hashlib

import frappe

from oan_auth_service.api.tokens import TokenError
from oan_auth_service.config import settings

DELEGATED_USER_DOMAIN = "iam.internal"


def user_name_for_sub(sub: str) -> str:
	digest = hashlib.sha256(sub.encode()).hexdigest()[:32]
	return f"{digest}@{DELEGATED_USER_DOMAIN}"


def is_delegated_user(user: str | None) -> bool:
	"""Whether `user` was provisioned by delegated login and must stay passwordless."""
	return bool(user) and user.endswith(f"@{DELEGATED_USER_DOMAIN}")


def resolve_user(principal: dict) -> str:
	"""Return the local `User` for an IAM `principal`, creating it on first login."""
	sub = principal.get("sub")
	if not sub or not isinstance(sub, str):
		raise TokenError("Principal has no sub")

	user = user_name_for_sub(sub)
	if not frappe.db.exists("User", user):
		_create_user(user, principal)
	return user


def _create_user(user: str, principal: dict) -> None:
	first_name, _sep, last_name = (principal.get("name") or "").strip().partition(" ")
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


def granted_roles(principal: dict) -> set[str]:
	"""Frappe roles IAM grants `principal` for this application.

	Empty when `iam_application` is unset, the principal has no entry for it, or
	none of its roles exist in Frappe. Callers must treat empty as "no access".
	"""
	application = settings.iam_application()
	if not application:
		frappe.log_error(
			title="oan_auth_service: iam_application not set",
			message="Delegated login rejected: set `iam_application` in site config.",
		)
		return set()
	iam_roles = set(((principal.get("client_roles") or {}).get(application)) or [])
	return {r for r in iam_roles if frappe.db.exists("Role", r)}


def sync_roles(user: str, principal: dict) -> bool:
	"""Set the user's Frappe roles to IAM's roles for this application.

	Returns whether any role was added or removed.
	"""
	wanted = granted_roles(principal)
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
