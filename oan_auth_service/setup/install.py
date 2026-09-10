"""Schema this app adds to doctypes it does not own.

Deliberately called from two places. `bench install-app` marks every patch in
patches.txt as already applied *without running it*
(frappe/installer.py:357-358) and only then fires `after_install`
(installer.py:360-361). A patch on its own would therefore add this field to
existing sites and silently skip every new one — including the site CI builds
from scratch on each run, where the field's absence would surface as failing
login tests rather than as a missing migration.

So: the patch covers sites that already have the app, `after_install` covers
fresh sites, and both call the same function. `create_custom_field` no-ops when
the field is already there (custom_field.py:305), so running both is harmless.
"""

import frappe

# The canonical name of the field, defined here because this is what creates it.
# Everything that reads it imports from here rather than repeating the string.
LOGIN_EMAIL_FIELD = "oan_login_email"


def after_install():
	create_login_email_field()


def create_login_email_field():
	"""Add `User.oan_login_email` — the real address an account signs in with.

	`User.name` is a synthetic, opaque id (see `api/v1/auth.py::register_user`),
	so the address a person actually types at login cannot be the primary key.
	Keeping it out of the key is the point: `name` propagates into `owner` and
	`modified_by` on every row the user ever touches, and Frappe's only built-in
	way to change it is `rename_doc`, whose `after_rename` (user/user.py:675)
	walks every table in the site and rewrites both columns. With the address in
	its own field, changing it is a one-row UPDATE and the key never moves.

	It cannot live in `User.email` either: `User.validate()` reassigns
	`self.email = self.name` on every save (user/user.py:222), so a real address
	stored there survives only until the next save of the doc and then silently
	reverts to the synthetic hash.

	It is not stored in `Contact Email` because that is a child table with no
	unique constraint and no index — uniqueness would be enforced only by an
	application-level check that a concurrent registration can race, and every
	login would pay a join. `Contact Email` is still written as contact data; it
	is simply never consulted by the login resolver.

	Frappe's own tracker issue #26189 ("Move away from using email ID as
	username") describes upstream moving to exactly this shape: an opaque id for
	the key, with mail-sending code reading an address field off the user. That
	issue is open and labelled a breaking change, so this app provides the field
	itself rather than waiting for it.
	"""
	from frappe.custom.doctype.custom_field.custom_field import create_custom_field

	create_custom_field(
		"User",
		{
			"fieldname": LOGIN_EMAIL_FIELD,
			"label": "Login Email",
			"fieldtype": "Data",
			"options": "Email",
			# Unique gives a real index, so the resolver's lookup is a single
			# indexed read and two accounts cannot end up on one address. MariaDB
			# permits any number of NULLs under a unique index, so the phone-only
			# accounts that make up most of this platform simply leave it unset.
			"unique": 1,
			"insert_after": "email",
			# Contact data belonging to one person; copying a User would otherwise
			# carry the address onto the duplicate and collide on insert.
			"no_copy": 1,
			"description": (
				"Real address this account signs in with. User.name is a synthetic id "
				"and is never shown to the account holder."
			),
		},
	)

	frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit
