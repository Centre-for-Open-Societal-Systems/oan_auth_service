"""Tests for the `OAN IAM Service` DocType: one row per login option."""

import unittest

import frappe

from oan_auth_service.config import settings
from oan_auth_service.tests.utils import (
	IAM_SERVICE_DOCTYPE,
	cleanup_user,
	delete_iam_service,
	ensure_role,
	make_iam_service,
	make_user,
)

KEY = "t-svc"
OTHER = "t-svc-other"
LOCAL = settings.LOCAL_LOGIN_KEY
ROLE = "IAM Svc Test Role"


def valid(**overrides) -> dict:
	fields = {
		"base_url": "https://iam.test",
		"provider_id": 1,
		"issuer": "https://idp.test/realms/staff",
		"application": "oan-grievance",
	}
	fields.update(overrides)
	return fields


class TestIAMServiceDocType(unittest.TestCase):
	def setUp(self):
		ensure_role(ROLE)
		self._local_existed = frappe.db.exists(IAM_SERVICE_DOCTYPE, LOCAL)

	def tearDown(self):
		frappe.set_user("Administrator")
		for key in (KEY, OTHER):
			delete_iam_service(key)
		if not self._local_existed:
			delete_iam_service(LOCAL)

	def assertRefused(self, key=KEY, **fields):
		with self.assertRaises(frappe.ValidationError):
			make_iam_service(key, **fields)
		frappe.db.rollback()

	def test_valid_row_saves(self):
		make_iam_service(KEY, **valid(base_url="https://iam.test/api/"))
		doc = frappe.get_doc(IAM_SERVICE_DOCTYPE, KEY)
		self.assertEqual(doc.name, KEY)
		self.assertEqual(doc.base_url, "https://iam.test/api")

	def test_bad_key_is_refused(self):
		for key in ("Staff", "staff_portal", "staff portal", "stäff"):
			self.assertRefused(key, **valid())

	def test_iam_row_needs_base_url_provider_and_issuer(self):
		for missing in ("base_url", "provider_id", "issuer"):
			self.assertRefused(**valid(**{missing: None}))
		self.assertRefused(**valid(provider_id=-1))

	def test_iam_row_needs_application_or_default_roles(self):
		self.assertRefused(**valid(application=""))
		make_iam_service(KEY, **valid(application="", default_roles=[ROLE]))

	def test_privileged_default_roles_are_refused(self):
		for role in ("System Manager", "Administrator", "Guest", "All"):
			self.assertRefused(**valid(default_roles=[role]))

	def test_local_row_takes_no_iam_fields(self):
		delete_iam_service(LOCAL)
		for field, value in (
			("base_url", "https://iam.test"),
			("issuer", "x"),
			("application", "a"),
			("cookie_prefix", "p-"),
			("default_roles", [ROLE]),
		):
			self.assertRefused(LOCAL, **{field: value})
		make_iam_service(LOCAL, label="Sign in")

	def test_plain_http_base_url_is_refused_without_opt_out(self):
		self.assertRefused(**valid(base_url="http://iam.cluster.local"))
		self.assertRefused(**valid(base_url="https://iam.test/?x=1"))
		self.assertRefused(**valid(base_url="https://user:pw@iam.test"))
		make_iam_service(KEY, **valid(base_url="http://localhost:8020"))

	def test_issuer_can_be_shared_among_enabled_rows(self):
		shared_iss = "https://idp.test/realms/shared"
		make_iam_service(KEY, **valid(issuer=shared_iss, client_id="client-a"))
		make_iam_service(OTHER, **valid(issuer=shared_iss, client_id="client-b"))
		self.assertEqual(settings.iam_service_for_issuer(shared_iss, azp="client-a").key, KEY)
		self.assertEqual(settings.iam_service_for_issuer(shared_iss, azp="client-b").key, OTHER)

	def test_key_cannot_change(self):
		make_iam_service(KEY, **valid())
		doc = frappe.get_doc(IAM_SERVICE_DOCTYPE, KEY)
		doc.key = "t-renamed"
		# Frappe syncs an autoname field back to `name` before set_only_once runs,
		# so the change is dropped rather than refused. Either way, it never lands.
		try:
			doc.save(ignore_permissions=True)
		except frappe.ValidationError:
			frappe.db.rollback()
		self.assertEqual(frappe.db.get_value(IAM_SERVICE_DOCTYPE, KEY, "key"), KEY)
		self.assertFalse(frappe.db.exists(IAM_SERVICE_DOCTYPE, "t-renamed"))

	def test_private_icon_is_refused(self):
		self.assertRefused(**valid(icon="/private/files/staff.png"))

	def test_save_and_delete_clear_the_cache(self):
		make_iam_service(KEY, **valid())
		self.assertIn(KEY, [s.key for s in settings.iam_services()])

		doc = frappe.get_doc(IAM_SERVICE_DOCTYPE, KEY)
		doc.label = "Renamed"
		doc.save(ignore_permissions=True)
		self.assertEqual(settings.iam_service(KEY).label, "Renamed")

		doc.enabled = 0
		doc.save(ignore_permissions=True)
		self.assertIsNone(settings.iam_service(KEY))

		doc.enabled = 1
		doc.save(ignore_permissions=True)
		frappe.delete_doc(IAM_SERVICE_DOCTYPE, KEY, ignore_permissions=True)
		self.assertIsNone(settings.iam_service(KEY))
		frappe.db.commit()  # nosemgrep: frappe-manual-commit

	def test_cache_carries_child_rows(self):
		make_iam_service(KEY, **valid(default_roles=[ROLE]))
		service = settings.iam_service(KEY)
		self.assertEqual(service.default_roles, [ROLE])
		self.assertEqual(settings.iam_service_for_issuer("https://idp.test/realms/staff").key, KEY)

	def test_only_system_manager_can_write(self):
		make_iam_service(KEY, **valid())
		self.assertEqual(frappe.get_meta(IAM_SERVICE_DOCTYPE).permissions[0].role, "System Manager")
		self.assertEqual(len(frappe.get_meta(IAM_SERVICE_DOCTYPE).permissions), 1)
		user = make_user("oan_iam_svc_plain@example.com", "PlainPass123!", roles=[ROLE])
		self.addCleanup(cleanup_user, user)
		frappe.set_user(user)
		self.assertFalse(frappe.has_permission(IAM_SERVICE_DOCTYPE, "read"))
		self.assertFalse(frappe.has_permission(IAM_SERVICE_DOCTYPE, "write"))
		self.assertTrue(frappe.get_meta(IAM_SERVICE_DOCTYPE).track_changes)


class TestGrantedRolesRefusal(unittest.TestCase):
	def test_token_roles_never_grant_privileged_roles(self):
		from oan_auth_service.api import iam_users

		service = frappe._dict(application="app", default_roles=["Desk User"])
		principal = {"client_roles": {"app": ["System Manager", "Guest", "Administrator"]}}
		self.assertEqual(iam_users.granted_roles(principal, service), set())
