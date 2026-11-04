import frappe
from frappe.model.document import Document
from frappe.utils import add_to_date, now_datetime

DEFAULT_RETENTION_HOURS = 24
BATCH_SIZE = 2000


class OANIdempotencyKey(Document):
	"""A request that has been answered once, kept so a retry gets the same answer.

	Written by `api.idempotency.idempotent`, in the same transaction as the endpoint's
	own writes: both are committed or both are rolled back. The `permissions` array in
	the doctype JSON is deliberately empty, so nothing else can read or write it.
	"""


def retention_hours() -> int:
	"""How long a retry is recognised. Set `oan_idempotency_retention_hours` in site_config.json."""
	return int(frappe.conf.get("oan_idempotency_retention_hours") or DEFAULT_RETENTION_HOURS)


def set_lock_wait(seconds: int | None) -> int | None:
	"""Set the session's lock wait timeout and return the value it had. MariaDB only."""
	if frappe.db.db_type != "mariadb" or seconds is None:
		return None
	previous = frappe.db.sql("select @@session.innodb_lock_wait_timeout")[0][0]
	frappe.db.sql("set session innodb_lock_wait_timeout = %s", int(seconds))
	return previous


def purge_expired() -> None:
	"""Delete rows older than the retention, a batch at a time. Runs hourly.

	One `DELETE` over millions of rows is a long transaction that holds locks and swells
	the binlog and undo log. Each batch commits on its own, so the table is never locked
	for long and replication keeps up. Rows are found through the index on `creation`.
	Deleted with `frappe.db.delete`, as these rows have no hooks.
	"""
	cutoff = add_to_date(now_datetime(), hours=-retention_hours())
	deleted = 0
	while True:
		names = frappe.get_all(
			"OAN Idempotency Key",
			filters={"creation": ("<", cutoff)},
			pluck="name",
			limit=BATCH_SIZE,
			order_by="creation asc",
		)
		if not names:
			break
		frappe.db.delete("OAN Idempotency Key", {"name": ("in", names)})
		frappe.db.commit()  # nosemgrep: frappe-manual-commit
		deleted += len(names)
		if len(names) < BATCH_SIZE:
			break
	if deleted:
		frappe.logger("oan_idempotency", allow_site=True).info({"outcome": "purged", "deleted": deleted})
