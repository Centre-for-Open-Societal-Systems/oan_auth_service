import re
from urllib.parse import urlparse

import frappe
from frappe import _
from frappe.model.document import Document

from oan_auth_service.api import iam_tokens
from oan_auth_service.api.iam_users import REFUSED_ROLES
from oan_auth_service.config import settings

KEY_PATTERN = re.compile(r"^[a-z0-9-]+$")
# iam_core builds cookie names as `<prefix><name>`; keep the prefix to cookie-safe characters.
COOKIE_PREFIX_PATTERN = re.compile(r"^[A-Za-z0-9_.-]*$")

# Fields that configure an IAM login. The `local` row is this app's own login
# and must leave all of them empty.
IAM_FIELDS = ("base_url", "provider_id", "issuer", "client_id", "application", "cookie_prefix")


class OANIAMService(Document):
	"""One login option on the login page.

	These rows are trust configuration: bearer tokens are sent to `base_url`,
	`issuer` decides which tokens are accepted, `application` and
	`default_roles` decide which roles are granted. Who may start a login (and
	where it returns to) is controlled at the gateway. DocPerm is System Manager only, and
	the admin API never exposes this doctype (see api/v1/admin.py).
	"""

	def validate(self):
		self.key = (self.key or "").strip()
		if not KEY_PATTERN.match(self.key):
			frappe.throw(_("Key may contain only lowercase letters, digits and hyphens."))

		if self.key == settings.LOCAL_LOGIN_KEY:
			self._validate_local()
			return

		self._validate_iam()
		self._validate_roles()
		self._validate_issuer_unique()

	def _validate_local(self):
		if any(self.get(f) for f in IAM_FIELDS) or self.default_roles:
			frappe.throw(
				_("The {0} row is this app's own login and takes no IAM settings.").format(
					settings.LOCAL_LOGIN_KEY
				)
			)
		self._validate_icon()

	def _validate_iam(self):
		self.base_url = (self.base_url or "").strip().rstrip("/")
		self.issuer = (self.issuer or "").strip()
		self.client_id = (self.client_id or "").strip()
		self.application = (self.application or "").strip()
		self.cookie_prefix = (self.cookie_prefix or "").strip()

		if not (self.base_url and self.provider_id and self.issuer):
			frappe.throw(_("Base URL, Provider ID and Issuer are required."))
		if self.provider_id < 1:
			frappe.throw(_("Provider ID must be a positive row id of IAM's login_providers table."))

		parsed = urlparse(self.base_url)
		if (
			parsed.scheme not in ("http", "https")
			or not parsed.hostname
			or parsed.username is not None
			or parsed.query
			or parsed.fragment
		):
			frappe.throw(_("Base URL must be the IAM API root, with no credentials, query or fragment."))
		if not iam_tokens.is_secure_url(self.base_url):
			frappe.throw(
				_(
					"Base URL must use https (plain http is allowed only for localhost): bearer tokens are sent there."
				)
			)
		for field, label in (("userinfo_url", "Userinfo URL"), ("jwks_url", "Userinfo Keys URL")):
			value = (self.get(field) or "").strip()
			self.set(field, value)
			if value and not iam_tokens.is_secure_url(value):
				frappe.throw(
					_("{0} must use https (plain http is allowed only for localhost).").format(label)
				)
		if not COOKIE_PREFIX_PATTERN.match(self.cookie_prefix):
			frappe.throw(_("Cookie Prefix may contain only letters, digits, '_', '.' and '-'."))
		self._validate_icon()

	def _validate_icon(self):
		if self.icon and self.icon.startswith("/private/"):
			frappe.throw(_("Icon must be a public file: the providers endpoint is public."))

	def _validate_roles(self):
		roles = [d.role for d in self.default_roles]
		if not (self.application or roles):
			frappe.throw(
				_(
					"Set Application or at least one Default Role, otherwise no user of this login gets a role."
				)
			)
		refused = sorted(r for r in roles if r in REFUSED_ROLES)
		if refused:
			frappe.throw(
				_(
					"These roles cannot be default roles, they would go to anyone the provider authenticates: {0}"
				).format(", ".join(refused))
			)

	def _validate_issuer_unique(self):
		if not self.enabled:
			return
		clash = frappe.db.get_value(
			"OAN IAM Service",
			{"issuer": self.issuer, "enabled": 1, "name": ("!=", self.name or "")},
			"name",
		)
		if clash:
			frappe.throw(_("Issuer is already used by the enabled row {0}.").format(frappe.bold(clash)))

	def on_update(self):
		_clear_cache()

	def on_trash(self):
		_clear_cache()


def _clear_cache():
	# Now, so this request sees the change, and again after commit, so another
	# worker cannot re-cache the old rows between this clear and the commit.
	settings.clear_iam_services_cache()
	frappe.db.after_commit.add(settings.clear_iam_services_cache)
