"""Notification endpoints, under `/api/v1/notifications`. Rules: docs/NOTIFICATIONS_RULES.md."""

import frappe
from frappe import _
from pydantic import BaseModel, Field, model_validator

from oan_auth_service.api.router import prefixed
from oan_auth_service.api.utils import (
	PageParams,
	handle_api_errors,
	page_meta,
	parse_multi_value,
	success_response,
	to_tz_aware_iso,
	validate_request,
)

route = prefixed("/api/v1/notifications")

DOCTYPE = "Notification Log"

MAX_BULK_IDS = 500

_FIELDS = ["name", "subject", "email_content", "type", "document_type", "document_name", "read", "creation"]


def notify_users(users, subject, message=None, doctype=None, docname=None, notification_type="Alert"):
	"""Create a Notification Log for each user in `users`. Best-effort, never raises.

	The acting user is skipped, so no caller notifies the actor about their own action.
	"""
	actor = frappe.session.user
	for user in {u for u in (users or []) if u and u != actor}:
		try:
			frappe.get_doc(
				{
					"doctype": DOCTYPE,
					"for_user": user,
					"type": notification_type,
					"subject": subject,
					"email_content": message or subject,
					"document_type": doctype,
					"document_name": docname,
				}
			).insert(ignore_permissions=True)
		except Exception:
			frappe.log_error(
				title=f"Could not create Notification Log for user {user}",
				message=frappe.get_traceback(),
			)


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class ListNotificationsSchema(PageParams):
	status: str = Field("all", pattern="^(unread|read|all)$", description="Filter by read state")


class NotificationRefSchema(BaseModel):
	notification_id: str = Field(..., min_length=1)


class UpdateNotificationSchema(NotificationRefSchema):
	read: bool = Field(..., description="true marks read, false marks unread")


class BulkSchema(BaseModel):
	ids: list[str] | str | None = Field(default=None, description="Notification ids, list or comma-separated")
	all: bool = False

	@model_validator(mode="after")
	def _ids_xor_all(self):
		ids = parse_multi_value(self.ids)
		if bool(ids) == self.all:
			raise ValueError("Send either `ids` or `all=true`")
		if len(ids) > MAX_BULK_IDS:
			raise ValueError(f"Send at most {MAX_BULK_IDS} ids")
		return self


class BulkUpdateSchema(BulkSchema):
	read: bool = Field(True, description="true marks read, false marks unread")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serialize(row: dict) -> dict:
	return {
		"id": row["name"],
		"subject": row["subject"],
		"message": row["email_content"],
		"type": row["type"],
		"document_type": row["document_type"],
		"document_name": row["document_name"],
		"read": bool(row["read"]),
		"created_at": to_tz_aware_iso(row["creation"]),
	}


def _own_filters(bulk: BulkSchema | dict) -> dict:
	"""Filters for a bulk call: the caller's records, narrowed to `ids` unless `all`."""
	filters = {"for_user": frappe.session.user}
	if not bulk["all"]:
		filters["name"] = ["in", parse_multi_value(bulk["ids"])]
	return filters


def _get_own(notification_id: str) -> dict:
	rows = frappe.get_all(
		DOCTYPE, filters={"name": notification_id, "for_user": frappe.session.user}, fields=_FIELDS, limit=1
	)
	if not rows:
		raise frappe.DoesNotExistError(_("Notification not found"))
	return rows[0]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@route(
	"",
	methods=("GET",),
	summary="List my notifications",
	description="Newest first, for the caller only. `status` is unread, read or all. `unread_count` ignores the filter and drives the badge. `message` may contain HTML: clients must sanitize it before rendering.",
)
@validate_request(ListNotificationsSchema)
@handle_api_errors
def list_notifications(page: int = 1, page_size: int = 20, status: str = "all"):
	user = frappe.session.user
	filters = {"for_user": user}
	if status != "all":
		filters["read"] = int(status == "read")

	rows = frappe.get_all(
		DOCTYPE,
		filters=filters,
		fields=_FIELDS,
		order_by="creation desc, name desc",
		limit_start=(page - 1) * page_size,
		limit_page_length=page_size,
	)
	total = frappe.db.count(DOCTYPE, filters=filters)
	unread = frappe.db.count(DOCTYPE, filters={"for_user": user, "read": 0})

	return success_response(
		data={"unread_count": unread, "notifications": [_serialize(r) for r in rows]},
		message="Notifications retrieved successfully",
		pagination=page_meta(total, page, page_size),
	)


@route(
	"/<notification_id>",
	methods=("GET",),
	summary="Get one of my notifications",
	description="`message` may contain HTML: clients must sanitize it before rendering.",
)
@validate_request(NotificationRefSchema)
@handle_api_errors
def get_notification(notification_id: str):
	return success_response(data=_serialize(_get_own(notification_id)), message="Notification retrieved")


@route(
	"/<notification_id>",
	methods=("PATCH",),
	summary="Mark one of my notifications read or unread",
)
@validate_request(UpdateNotificationSchema)
@handle_api_errors
def update_notification(notification_id: str, read: bool):
	_get_own(notification_id)
	frappe.db.set_value(DOCTYPE, notification_id, "read", int(read), update_modified=False)
	return success_response(data=_serialize(_get_own(notification_id)), message="Notification updated")


@route(
	"",
	methods=("PATCH",),
	summary="Mark many of my notifications read or unread",
	description="Send `ids` (at most 500) or `all=true`, plus `read` (default true).",
)
@validate_request(BulkUpdateSchema)
@handle_api_errors
def bulk_update_notifications(ids=None, all: bool = False, read: bool = True):
	filters = _own_filters({"ids": ids, "all": all})
	filters["read"] = int(not read)
	updated = frappe.db.count(DOCTYPE, filters=filters)
	if updated:
		frappe.db.set_value(DOCTYPE, filters, "read", int(read), update_modified=False)
	return success_response(data={"updated": updated}, message="Notifications updated")


@route(
	"/<notification_id>",
	methods=("DELETE",),
	summary="Delete one of my notifications",
)
@validate_request(NotificationRefSchema)
@handle_api_errors
def delete_notification(notification_id: str):
	_get_own(notification_id)
	frappe.delete_doc(DOCTYPE, notification_id, ignore_permissions=True, force=True)
	return success_response(data=None, message="Notification deleted")


@route(
	"",
	methods=("DELETE",),
	summary="Delete many of my notifications",
	description="Send `ids` (at most 500) or `all=true`.",
)
@validate_request(BulkSchema)
@handle_api_errors
def bulk_delete_notifications(ids=None, all: bool = False):
	filters = _own_filters({"ids": ids, "all": all})
	deleted = frappe.db.count(DOCTYPE, filters=filters)
	if deleted:
		frappe.db.delete(DOCTYPE, filters)
	return success_response(data={"deleted": deleted}, message="Notifications deleted")
