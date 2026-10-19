"""Admin user, role and permission endpoints, under `/api/v1/admin`. Rules: docs/ADMIN_API_RULES.md."""

import secrets
import string

import frappe
from frappe import _
from frappe.core.page.permission_manager import permission_manager
from frappe.permissions import ALL_USER_ROLE, GUEST_ROLE, SYSTEM_USER_ROLE
from frappe.permissions import rights as RIGHTS
from frappe.query_builder.functions import Count
from pydantic import BaseModel, Field, field_validator

from oan_auth_service.api import tokens
from oan_auth_service.api.iam_users import is_delegated_user
from oan_auth_service.api.router import prefixed
from oan_auth_service.api.utils import (
	PageParams,
	SafeEmail,
	assemble_phone_number,
	handle_api_errors,
	page_meta,
	parse_multi_value,
	require_role,
	split_phone_number,
	success_response,
	validate_mobile,
	validate_request,
	validate_temporary_password,
)
from oan_auth_service.api.v1.auth import (
	LOGIN_EMAIL_FIELD,
	MUST_CHANGE_PASSWORD_FIELD,
	collect_profiles,
	create_account,
	issue_temporary_password,
	revoke_all_for_user,
	set_login_email,
)
from oan_auth_service.config import settings

route = prefixed("/api/v1/admin")

ADMIN_ROLES = ["System Manager", "Administrator"]

# Implied by user type rather than granted (see `tokens.resolve_roles`), so
# assigning or removing one is meaningless.
_AMBIENT_ROLES = {ALL_USER_ROLE, GUEST_ROLE, SYSTEM_USER_ROLE}

_DELEGATED_ROLES_MESSAGE = "Roles for IAM-delegated users are managed by the identity provider."


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


def _check_temporary_password(v: str | None) -> str | None:
	return validate_temporary_password(v) if v else v


class UserRefSchema(BaseModel):
	user_id: str = Field(..., min_length=1, description="User id")


class RoleRefSchema(UserRefSchema):
	role: str = Field(..., min_length=1)


class AdminCreateUserSchema(BaseModel):
	model_config = {"extra": "allow"}

	full_name: str = Field(..., min_length=1, max_length=140)
	email: SafeEmail | None = None
	phone_number: str | None = Field(
		default=None,
		description="E.164 number, or national digits when country_code is provided.",
	)
	country_code: str | None = None
	roles: list[str] | str | None = None
	temporary_password: str | None = Field(
		default=None, max_length=128, description="Generated and returned when omitted."
	)

	_temporary_password = field_validator("temporary_password")(_check_temporary_password)


class AdminListUsersSchema(PageParams):
	search: str | None = Field(default=None, description="Matches name, user id, login email or mobile")
	email: SafeEmail | None = Field(default=None, description="Exact login email")
	phone_number: str | None = Field(default=None, description="Exact mobile number, E.164")
	role: str | None = None
	enabled: bool | None = None


class AdminUpdateUserSchema(UserRefSchema):
	first_name: str | None = Field(default=None, min_length=1, max_length=140)
	last_name: str | None = Field(default=None, max_length=140)
	email: SafeEmail | None = Field(default=None, description="Empty string or null clears it")
	phone_number: str | None = Field(default=None, description="Empty string or null clears it")
	country_code: str | None = None
	enabled: bool | None = None


class AdminRolesSchema(UserRefSchema):
	roles: list[str] | str = Field(..., description="Role names, as a list or comma-separated")


class PermissionQuerySchema(BaseModel):
	role: str | None = Field(default=None, description="Limit to one role")
	doctype: str | None = Field(default=None, description="Limit to one doctype")


class PermissionTargetSchema(BaseModel):
	role: str = Field(..., min_length=1)
	doctype: str = Field(..., min_length=1)


class SetPermissionSchema(PermissionTargetSchema):
	permlevel: int = Field(default=0, ge=0, le=9)
	if_owner: bool = False
	permissions: dict[str, bool] = Field(
		..., min_length=1, description='Right name to granted flag, e.g. {"read": true, "write": false}'
	)


class DeletePermissionSchema(PermissionTargetSchema):
	permlevel: int = Field(default=0, ge=0, le=9)
	if_owner: bool = False


class AdminTemporaryPasswordSchema(UserRefSchema):
	temporary_password: str | None = Field(
		default=None, max_length=128, description="Generated and returned when omitted."
	)

	_temporary_password = field_validator("temporary_password")(_check_temporary_password)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_temporary_password(length: int = 16) -> str:
	"""A random password that always satisfies `validate_temporary_password`."""
	alphabet = string.ascii_letters + string.digits
	while True:
		pwd = "".join(secrets.choice(alphabet) for _ in range(length))
		if any(c.isalpha() for c in pwd) and any(c.isdigit() for c in pwd):
			return pwd


def _service_prefix() -> tuple[str, ...]:
	"""The configured prefixes; `str.startswith` accepts the tuple directly."""
	prefixes = settings.service_prefixes()
	if not prefixes:
		frappe.throw(
			_("No service prefix is configured: set the oan_service_prefix hook or service_prefix."),
			frappe.ValidationError,
		)
	return prefixes


def _escape_like(value: str) -> str:
	"""Escape `\\`, `%` and `_` so `value` matches literally inside a LIKE pattern."""
	return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _like_any(column, prefixes: tuple[str, ...]):
	"""Query Builder condition matching `column` against any prefix."""
	cond = column.like(f"{_escape_like(prefixes[0])}%")
	for p in prefixes[1:]:
		cond = cond | column.like(f"{_escape_like(p)}%")
	return cond


def _resolve_target(user_id: str) -> str:
	"""Return `user_id` if it names a real account holding a service role, or raise 404."""
	user_id = user_id.strip()
	prefix = _service_prefix()
	if (
		user_id == "Guest"
		or not frappe.db.exists("User", user_id)
		or not any(r.startswith(prefix) for r in tokens.resolve_roles(user_id))
	):
		raise frappe.DoesNotExistError(_("User not found"))
	return user_id


def _guard_protected(user: str, action: str) -> None:
	"""Refuse `action` on the Administrator account or on the caller's own."""
	if user == "Administrator":
		frappe.throw(_("Cannot {0} the Administrator account.").format(action), frappe.PermissionError)
	if user == frappe.session.user:
		frappe.throw(_("Cannot {0} your own account.").format(action), frappe.PermissionError)


def _guard_privileged(user: str) -> None:
	"""Refuse changes to the Administrator account, or to a holder of the Administrator role, unless the caller is Administrator.

	Contact edits, password resets, role changes and session revocation each let
	a caller sign in as, or lock out, the target. A System Manager must not do
	that to the top-level account.
	"""
	caller = frappe.session.user
	if caller == "Administrator" or user == caller:
		return
	if user == "Administrator" or "Administrator" in tokens.resolve_roles(user):
		frappe.throw(
			_("Only the Administrator user may modify an administrator account."), frappe.PermissionError
		)


def _guard_role_change(user: str) -> None:
	_guard_protected(user, "change roles of")
	if is_delegated_user(user):
		frappe.throw(_(_DELEGATED_ROLES_MESSAGE), frappe.PermissionError)


def _validate_roles(roles: list[str]) -> list[str]:
	"""Check every role exists and the caller may grant it."""
	prefix = _service_prefix()
	for r in roles:
		if not r.startswith(prefix) or r in _AMBIENT_ROLES or not frappe.db.exists("Role", r):
			frappe.throw(_("Role '{0}' cannot be assigned").format(r), frappe.ValidationError)
		if r == "Administrator" and frappe.session.user != "Administrator":
			frappe.throw(
				_("Only the Administrator user may grant the Administrator role."), frappe.PermissionError
			)
	return roles


def _assert_unique(field: str, value: str, user: str, message: str) -> None:
	"""Raise unless no other User or Contact already holds `value`."""
	if field == "email":
		taken = frappe.db.exists(
			"User", {LOGIN_EMAIL_FIELD: value, "name": ("!=", user)}
		) or frappe.db.exists(
			"Contact Email", {"email_id": value, "parent": ("not in", _contacts_of(user) or [""])}
		)
	else:
		taken = frappe.db.exists("User", {"mobile_no": value, "name": ("!=", user)}) or frappe.db.exists(
			"Contact Phone", {"phone": value, "parent": ("not in", _contacts_of(user) or [""])}
		)
	if taken:
		frappe.throw(message, frappe.ValidationError)


def _contacts_of(user: str) -> list[str]:
	return frappe.get_all("Contact", filters={"user": user}, pluck="name")


def _roles_by_user(users: list[str]) -> dict[str, list[str]]:
	"""Granted roles of every user in `users`, from one query, in `tokens.resolve_roles` form."""
	has_role = frappe.qb.DocType("Has Role")
	rows = (
		frappe.qb.from_(has_role)
		.select(has_role.parent, has_role.role)
		.where((has_role.parenttype == "User") & has_role.parent.isin(users or [""]))
		.run()
	)
	out: dict[str, list[str]] = {u: [] for u in users}
	for parent, role in rows:
		if role not in _AMBIENT_ROLES:
			out[parent].append(role)
	return {u: sorted(set(r)) for u, r in out.items()}


def _user_summary(row, roles: list[str] | None = None) -> dict:
	"""The public shape of a user, from a User doc or a row carrying the same fields.

	Pass `roles` when summarising many rows, so they are not resolved one by one.
	"""
	phone_cc, phone_nat = split_phone_number(row.mobile_no)
	return {
		"user": row.name,
		"first_name": row.first_name,
		"last_name": row.last_name,
		"full_name": row.full_name,
		"login_email": row.get(LOGIN_EMAIL_FIELD),
		"mobile_no": row.mobile_no,
		"country_code": phone_cc,
		"phone_number": phone_nat,
		"roles": tokens.resolve_roles(row.name) if roles is None else roles,
		"enabled": bool(row.enabled),
		"must_change_password": bool(row.get(MUST_CHANGE_PASSWORD_FIELD)),
		"is_delegated": is_delegated_user(row.name),
		"creation": str(row.creation),
	}


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@route(
	"/users",
	methods=("GET",),
	summary="Admin: list users",
	description="List user accounts holding a role of this service, newest first. Filter by free-text `search`, exact `email` or `phone_number`, `role` and `enabled`.",
)
@validate_request(AdminListUsersSchema)
@handle_api_errors
@require_role(ADMIN_ROLES)
def list_users(
	page: int = 1,
	page_size: int = 20,
	search: str | None = None,
	email: str | None = None,
	phone_number: str | None = None,
	role: str | None = None,
	enabled: bool | None = None,
):
	user = frappe.qb.DocType("User")
	has_role = frappe.qb.DocType("Has Role")

	prefix = _service_prefix()
	query = frappe.qb.from_(user).where(user.name != "Guest")
	query = query.where(
		user.name.isin(
			frappe.qb.from_(has_role)
			.select(has_role.parent)
			.where((has_role.parenttype == "User") & _like_any(has_role.role, prefix))
		)
	)
	if enabled is not None:
		query = query.where(user.enabled == int(enabled))
	if role:
		query = query.where(
			user.name.isin(
				frappe.qb.from_(has_role)
				.select(has_role.parent)
				.where((has_role.parenttype == "User") & (has_role.role == role.strip()))
			)
		)
	if email:
		query = query.where(getattr(user, LOGIN_EMAIL_FIELD) == email.strip().lower())
	if phone_number:
		query = query.where(user.mobile_no == validate_mobile(phone_number))
	if search and search.strip():
		pattern = f"%{_escape_like(search.strip())}%"
		query = query.where(
			user.full_name.like(pattern)
			| user.name.like(pattern)
			| getattr(user, LOGIN_EMAIL_FIELD).like(pattern)
			| user.mobile_no.like(pattern)
		)

	total = query.select(Count("*")).run()[0][0]
	rows = (
		query.select(
			user.name,
			user.first_name,
			user.last_name,
			user.full_name,
			user.mobile_no,
			user.enabled,
			user.creation,
			getattr(user, LOGIN_EMAIL_FIELD),
			getattr(user, MUST_CHANGE_PASSWORD_FIELD),
		)
		.orderby(user.creation, order=frappe.qb.desc)
		.limit(page_size)
		.offset((page - 1) * page_size)
		.run(as_dict=True)
	)

	roles = _roles_by_user([r.name for r in rows])
	return success_response(
		data=[_user_summary(r, roles[r.name]) for r in rows], pagination=page_meta(total, page, page_size)
	)


@route(
	"/users",
	methods=("POST",),
	status=201,
	summary="Admin: onboard a user",
	description="Create an account with any roles and a temporary password the user must replace at first sign-in. No tokens are issued. A generated temporary password is returned once, in the response.",
)
@validate_request(AdminCreateUserSchema)
@handle_api_errors
@require_role(ADMIN_ROLES)
def create_user(
	full_name: str,
	email: str | None = None,
	phone_number: str | None = None,
	country_code: str | None = None,
	roles: list[str] | str | None = None,
	temporary_password: str | None = None,
	**kwargs,
):
	if not (email or phone_number):
		frappe.throw(_("Provide an email or a phone number."), frappe.ValidationError)

	requested_roles = parse_multi_value(roles)
	if not requested_roles and (default_role := frappe.conf.get("jwt_default_registration_role")):
		requested_roles = [default_role]
	if not requested_roles:
		frappe.throw(_("Provide at least one role of this service."), frappe.ValidationError)
	_validate_roles(requested_roles)

	user_doc = create_account(
		full_name=full_name,
		email=email,
		phone_number=phone_number,
		country_code=country_code,
		roles=requested_roles,
		role=requested_roles[0] if requested_roles else None,
		hook_kwargs={k: v for k, v in kwargs.items() if k not in ("cmd", "phone")},
	)

	generated = not temporary_password
	pwd = temporary_password or _generate_temporary_password()
	issue_temporary_password(user_doc.name, pwd)

	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit

	data = _user_summary(frappe.get_doc("User", user_doc.name))
	if generated:
		data["temporary_password"] = pwd
	return success_response(data=data, message=_("User created"))


@route(
	"/users/<user_id>",
	methods=("GET",),
	summary="Admin: get a user",
	description="Account details, roles and app-specific profiles of any user.",
)
@validate_request(UserRefSchema)
@handle_api_errors
@require_role(ADMIN_ROLES)
def get_user(user_id: str):
	user_doc = frappe.get_doc("User", _resolve_target(user_id))
	data = _user_summary(user_doc)
	if profiles := collect_profiles(user_doc, data["roles"]):
		data["profiles"] = profiles
	return success_response(data=data)


@route(
	"/users/<user_id>",
	methods=("PATCH",),
	summary="Admin: update a user",
	description="Change name, login email, mobile number or enabled status. Only the fields sent are changed. An email or a phone number must remain. Disabling revokes every refresh token.",
)
@validate_request(AdminUpdateUserSchema, exclude_unset=True)
@handle_api_errors
@require_role(ADMIN_ROLES)
def update_user(user_id: str, **kwargs):
	user = _resolve_target(user_id)
	_guard_privileged(user)
	user_doc = frappe.get_doc("User", user)

	if "first_name" in kwargs:
		user_doc.first_name = kwargs["first_name"].strip()
	if "last_name" in kwargs:
		user_doc.last_name = (kwargs["last_name"] or "").strip() or None

	phone_changed = False
	if "phone_number" in kwargs:
		phone = None
		if kwargs["phone_number"] and kwargs["phone_number"].strip():
			phone = validate_mobile(
				assemble_phone_number(kwargs["phone_number"], country_code=kwargs.get("country_code"))
			)
			_assert_unique("phone", phone, user, _("A user with this phone number already exists."))
		phone_changed = phone != user_doc.mobile_no
		user_doc.mobile_no = phone

	if "email" in kwargs or "phone_number" in kwargs:
		email_after = (
			(kwargs["email"] or "").strip().lower() or None
			if "email" in kwargs
			else user_doc.get(LOGIN_EMAIL_FIELD)
		)
		if not (email_after or user_doc.mobile_no):
			frappe.throw(_("Keep an email or a phone number."), frappe.ValidationError)

	disabling = False
	if "enabled" in kwargs and kwargs["enabled"] is not None and bool(user_doc.enabled) != kwargs["enabled"]:
		disabling = not kwargs["enabled"]
		if disabling:
			_guard_protected(user, "disable")
		user_doc.enabled = int(kwargs["enabled"])

	user_doc.save(ignore_permissions=True)

	# After the save: set_login_email writes the column directly, and saving the
	# stale doc afterwards would put the old address back.
	if "email" in kwargs:
		email = (kwargs["email"] or "").strip().lower() or None
		if email != user_doc.get(LOGIN_EMAIL_FIELD):
			if email:
				_assert_unique("email", email, user, _("A user with this email address already exists."))
			set_login_email(user, email)

	for contact in _contacts_of(user):
		contact_doc = frappe.get_doc("Contact", contact)  # nosemgrep: oan-get-doc-in-loop
		contact_doc.first_name = user_doc.first_name
		contact_doc.last_name = user_doc.last_name
		if phone_changed:
			contact_doc.set(
				"phone_nos",
				[{"phone": user_doc.mobile_no, "is_primary_mobile_no": 1, "is_primary_phone": 1}]
				if user_doc.mobile_no
				else [],
			)
		contact_doc.save(ignore_permissions=True)

	if disabling:
		revoke_all_for_user(user)

	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit
	return success_response(data=_user_summary(frappe.get_doc("User", user)), message=_("User updated"))


@route(
	"/users/<user_id>/temporary-password",
	methods=("POST",),
	summary="Admin: issue a temporary password",
	description="Set a temporary password the user must replace before signing in, ending every existing session. A generated password is returned once, in the response.",
)
@validate_request(AdminTemporaryPasswordSchema)
@handle_api_errors
@require_role(ADMIN_ROLES)
def reissue_temporary_password(user_id: str, temporary_password: str | None = None):
	user = _resolve_target(user_id)
	_guard_privileged(user)
	_guard_protected(user, "reset the password of")

	pwd = temporary_password or _generate_temporary_password()
	issue_temporary_password(user, pwd)

	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit
	data = {"user": user}
	if not temporary_password:
		data["temporary_password"] = pwd
	return success_response(data=data, message=_("Temporary password issued"))


@route(
	"/users/<user_id>/sessions",
	methods=("DELETE",),
	summary="Admin: revoke a user's sessions",
	description="Delete every refresh token the user holds. Access tokens already issued stay valid until they expire.",
)
@validate_request(UserRefSchema)
@handle_api_errors
@require_role(ADMIN_ROLES)
def revoke_sessions(user_id: str):
	user = _resolve_target(user_id)
	_guard_privileged(user)
	revoked = revoke_all_for_user(user)
	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit
	return success_response(data={"user": user, "revoked_sessions": revoked})


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


@route(
	"/roles",
	methods=("GET",),
	summary="Admin: list assignable roles",
	description="Every enabled role of this service, meaning the ones whose names start with a configured service prefix.",
)
@handle_api_errors
@require_role(ADMIN_ROLES)
def list_roles():
	prefix = _service_prefix()
	roles = frappe.get_all(
		"Role",
		filters={"disabled": 0},
		or_filters=[["name", "like", f"{_escape_like(p)}%"] for p in prefix],
		fields=["name", "desk_access"],
		order_by="name asc",
	)
	roles = [r for r in roles if r.name.startswith(prefix) and r.name not in _AMBIENT_ROLES]
	return success_response(data=roles)


@route(
	"/users/<user_id>/roles",
	methods=("GET",),
	summary="Admin: list a user's roles",
	description="Roles granted to the user, without the ones every user holds implicitly.",
)
@validate_request(UserRefSchema)
@handle_api_errors
@require_role(ADMIN_ROLES)
def get_roles(user_id: str):
	user = _resolve_target(user_id)
	return success_response(data={"user": user, "roles": tokens.resolve_roles(user)})


@route(
	"/users/<user_id>/roles",
	methods=("POST",),
	summary="Admin: grant roles",
	description="Add roles to a user. Roles already held are ignored. The user's refresh tokens are revoked so the next token carries the new roles.",
)
@validate_request(AdminRolesSchema)
@handle_api_errors
@require_role(ADMIN_ROLES)
def add_roles(user_id: str, roles: list[str] | str):
	user = _resolve_target(user_id)
	_guard_privileged(user)
	_guard_role_change(user)

	requested = _validate_roles(parse_multi_value(roles))
	if not requested:
		frappe.throw(_("Provide at least one role."), frappe.ValidationError)

	held = set(tokens.resolve_roles(user))
	to_add = [r for r in requested if r not in held]
	if to_add:
		user_doc = frappe.get_doc("User", user)
		user_doc.flags.ignore_permissions = True
		user_doc.add_roles(*to_add)
		revoke_all_for_user(user)
		frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit

	return success_response(
		data={"user": user, "roles": tokens.resolve_roles(user)}, message=_("Roles updated")
	)


@route(
	"/users/<user_id>/roles/<role>",
	methods=("DELETE",),
	summary="Admin: revoke a role",
	description="Remove one role from a user. The user's refresh tokens are revoked; access tokens already issued keep the old role claim until they expire.",
)
@validate_request(RoleRefSchema)
@handle_api_errors
@require_role(ADMIN_ROLES)
def remove_role(user_id: str, role: str):
	user = _resolve_target(user_id)
	_guard_privileged(user)
	_guard_role_change(user)
	if not role.startswith(_service_prefix()):
		frappe.throw(_("Role '{0}' is not managed by this service.").format(role), frappe.PermissionError)

	if role in tokens.resolve_roles(user):
		user_doc = frappe.get_doc("User", user)
		user_doc.flags.ignore_permissions = True
		user_doc.remove_roles(role)
		revoke_all_for_user(user)
		frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit

	return success_response(
		data={"user": user, "roles": tokens.resolve_roles(user)}, message=_("Roles updated")
	)


# ---------------------------------------------------------------------------
# Role permissions (service-scoped)
# ---------------------------------------------------------------------------

_PERMISSION_FIELDS = ("role", "permlevel", "if_owner", *RIGHTS)


def _scoped_role(role: str) -> str:
	"""Return `role` if it is a service role that exists, else raise."""
	role = role.strip()
	if not role.startswith(_service_prefix()) or not frappe.db.exists("Role", role):
		frappe.throw(_("Role '{0}' is not managed by this service.").format(role), frappe.PermissionError)
	return role


def _scoped_doctype(doctype: str) -> str:
	"""Return `doctype` if it is a service doctype that exists, else raise."""
	doctype = doctype.strip()
	if not doctype.startswith(_service_prefix()) or not frappe.db.exists("DocType", doctype):
		frappe.throw(
			_("DocType '{0}' is not managed by this service.").format(doctype), frappe.PermissionError
		)
	return doctype


def _permission_rows(role: str, doctype: str | None = None) -> list[dict]:
	prefix = _service_prefix()
	rows = permission_manager.get_permissions(doctype=doctype, role=role)
	return [
		{"doctype": r.parent, **{f: r.get(f) for f in _PERMISSION_FIELDS}}
		for r in rows
		if r.parent.startswith(prefix)
	]


@route(
	"/permissions",
	methods=("GET",),
	summary="Admin: list role permissions",
	description="Doctype permissions of the roles this service owns, limited to doctypes it owns. Both are the ones whose names start with a configured service prefix. Filter by `role` and `doctype`.",
)
@validate_request(PermissionQuerySchema)
@handle_api_errors
@require_role(ADMIN_ROLES)
def list_permissions(role: str | None = None, doctype: str | None = None):
	prefix = _service_prefix()
	if doctype:
		doctype = _scoped_doctype(doctype)
	if role:
		roles = [_scoped_role(role)]
	else:
		roles = frappe.get_all(
			"Role",
			filters={"disabled": 0},
			or_filters=[["name", "like", f"{_escape_like(p)}%"] for p in prefix],
			pluck="name",
			order_by="name asc",
		)
		roles = [r for r in roles if r.startswith(prefix)]
	rows = [row for r in roles for row in _permission_rows(r, doctype)]
	return success_response(data=rows)


@route(
	"/permissions",
	methods=("PUT",),
	summary="Admin: set role permissions on a doctype",
	description="Grant or revoke individual rights (`read`, `write`, `create`, ...) for a service role on a service doctype. The rule is created when missing. Rights not named are left as they are.",
)
@validate_request(SetPermissionSchema)
@handle_api_errors
@require_role(ADMIN_ROLES)
def set_permissions(
	role: str, doctype: str, permissions: dict[str, bool], permlevel: int = 0, if_owner: bool = False
):
	role = _scoped_role(role)
	doctype = _scoped_doctype(doctype)
	if unknown := [p for p in permissions if p not in RIGHTS]:
		frappe.throw(_("Unknown rights: {0}").format(", ".join(unknown)), frappe.ValidationError)

	permission_manager.add(doctype, role, permlevel)
	for ptype, granted in permissions.items():
		permission_manager.update(
			doctype, role, permlevel, ptype, str(int(granted)), if_owner=str(int(if_owner))
		)
	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit
	return success_response(data=_permission_rows(role, doctype), message=_("Permissions updated"))


@route(
	"/permissions",
	methods=("DELETE",),
	summary="Admin: remove a role permission rule",
	description="Delete one permission rule (role, doctype, permlevel, if_owner) for a service role on a service doctype.",
)
@validate_request(DeletePermissionSchema)
@handle_api_errors
@require_role(ADMIN_ROLES)
def delete_permission(role: str, doctype: str, permlevel: int = 0, if_owner: bool = False):
	role = _scoped_role(role)
	doctype = _scoped_doctype(doctype)
	permission_manager.remove(doctype, role, permlevel, if_owner=str(int(if_owner)))
	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit
	return success_response(data=_permission_rows(role, doctype), message=_("Permission removed"))
