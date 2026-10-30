import frappe
from frappe.model.document import Document
from frappe.query_builder import Interval
from frappe.query_builder.functions import Now


class OANUserRefreshToken(Document):
	"""A single issued refresh token, stored as a hash.

	The `permissions` array in the doctype JSON is deliberately empty: no role
	may read or write this table through the ORM or the REST API. Every access
	goes through api/v1/auth.py with `ignore_permissions=True`, which keeps the
	set of code paths that can touch live session state small enough to audit.
	"""

	@staticmethod
	def clear_old_logs(days=0):
		"""Delete rows `days` past their expiry. Run daily by Frappe's Log Settings job.

		Housekeeping only, never a security control: `refresh()` re-checks
		`expires_at` on every exchange, so an unpruned row cannot be redeemed.

		Deleted with `frappe.db.delete` rather than the ORM. These rows have no
		child tables, no links pointing at them and no document hooks.
		"""
		table = frappe.qb.DocType("OAN User Refresh Token")
		frappe.db.delete(table, filters=(table.expires_at < (Now() - Interval(days=days))))
