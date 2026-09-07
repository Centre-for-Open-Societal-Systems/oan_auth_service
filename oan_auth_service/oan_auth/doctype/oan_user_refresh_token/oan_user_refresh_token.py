import frappe
from frappe.model.document import Document


class OANUserRefreshToken(Document):
	"""A single issued refresh token, stored as a hash.

	The `permissions` array in the doctype JSON is deliberately empty: no role
	may read or write this table through the ORM or the REST API. Every access
	goes through api/v1/auth.py with `ignore_permissions=True`, which keeps the
	set of code paths that can touch live session state small enough to audit.
	"""


def prune_expired():
	"""Delete rows past their expiry. Registered as a daily scheduler event.

	Housekeeping only, never a security control: `refresh()` re-checks
	`expires_at` on every exchange, so an unpruned row cannot be redeemed. If
	this job stops running the table grows and nothing else breaks.

	Deleted with `frappe.db.delete` rather than the ORM. These rows have no
	child tables, no links pointing at them and no document hooks; loading each
	one to call the full delete path would turn a single statement into a query
	per expired token for no gain.
	"""
	frappe.db.delete("OAN User Refresh Token", {"expires_at": ("<", frappe.utils.now_datetime())})
	frappe.db.commit()
