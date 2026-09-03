from frappe.model.document import Document


class OANUserRefreshToken(Document):
	"""A single issued refresh token, stored as a hash.

	The `permissions` array in the doctype JSON is deliberately empty: no role
	may read or write this table through the ORM or the REST API. Every access
	goes through api/v1/auth.py with `ignore_permissions=True`, which keeps the
	set of code paths that can touch live session state small enough to audit.
	"""


def prune_expired():
	"""Delete rows past their expiry. Registered as a daily scheduler event."""
	raise NotImplementedError
