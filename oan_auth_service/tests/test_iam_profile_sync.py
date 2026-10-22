"""`iam_users.sync_profile`: the identity provider's claims land on the Frappe `User`."""

import random
import unittest
from datetime import date

import frappe

from oan_auth_service.api import iam_users
from oan_auth_service.tests.utils import ensure_gender

SERVICE = frappe._dict(key="t-sync")


def _random_phone() -> str:
	return f"+2519{random.randint(10000000, 99999999)}"


def _principal(**overrides) -> dict:
	principal = {
		"sub": frappe.generate_hash(length=16),
		"name": "Dawit Haile Mekonnen",
		"phone_number": _random_phone(),
		"birthdate": "1978/11/02",
		"gender": "Male",
	}
	principal.update(overrides)
	return {k: v for k, v in principal.items() if v is not ...}


class TestSyncProfile(unittest.TestCase):
	def setUp(self):
		ensure_gender("Male")
		self.principal = _principal()
		self.user = iam_users.resolve_user(self.principal, SERVICE)
		self.addCleanup(self._cleanup)

	def _cleanup(self):
		for c in frappe.get_all("Contact", filters={"user": self.user}, pluck="name"):
			frappe.delete_doc("Contact", c, force=True, ignore_permissions=True)
		frappe.delete_doc("User", self.user, force=True, ignore_permissions=True)
		frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit

	def row(self):
		return frappe.db.get_value(
			"User",
			self.user,
			["first_name", "last_name", "full_name", "mobile_no", "birth_date", "gender"],
			as_dict=True,
		)

	def test_claims_fill_names_mobile_birth_date_and_gender(self):
		self.assertTrue(iam_users.sync_profile(self.user, self.principal))

		row = self.row()
		self.assertEqual((row.first_name, row.last_name), ("Dawit", "Haile Mekonnen"))
		self.assertEqual(row.full_name, "Dawit Haile Mekonnen")
		self.assertEqual(row.mobile_no, self.principal["phone_number"])
		self.assertEqual(row.birth_date, date(1978, 11, 2))
		self.assertEqual(row.gender, "Male")

	def test_given_and_family_name_claims_win_over_a_split_name(self):
		iam_users.sync_profile(self.user, _principal(given_name="Dawit Haile", family_name="Mekonnen"))

		row = self.row()
		self.assertEqual((row.first_name, row.last_name), ("Dawit Haile", "Mekonnen"))

	def test_second_sync_with_the_same_claims_changes_nothing(self):
		iam_users.sync_profile(self.user, self.principal)

		self.assertFalse(iam_users.sync_profile(self.user, self.principal))

	def test_a_claim_the_provider_does_not_send_keeps_the_stored_value(self):
		iam_users.sync_profile(self.user, self.principal)

		iam_users.sync_profile(self.user, _principal(phone_number=..., birthdate=..., gender=...))

		row = self.row()
		self.assertEqual(row.mobile_no, self.principal["phone_number"])
		self.assertEqual(row.birth_date, date(1978, 11, 2))
		self.assertEqual(row.gender, "Male")

	def test_a_changed_claim_replaces_the_stored_value(self):
		iam_users.sync_profile(self.user, self.principal)

		new_phone = _random_phone()
		self.assertTrue(iam_users.sync_profile(self.user, _principal(phone_number=new_phone)))
		self.assertEqual(self.row().mobile_no, new_phone)

	def test_unusable_values_are_skipped(self):
		iam_users.sync_profile(
			self.user, _principal(phone_number="not a phone", birthdate="2999/01/01", gender="Robot")
		)

		row = self.row()
		self.assertFalse(row.mobile_no)
		self.assertIsNone(row.birth_date)
		self.assertIsNone(row.gender)

	def test_iso_birth_dates_are_read_too(self):
		iam_users.sync_profile(self.user, _principal(birthdate="1992-07-21"))

		self.assertEqual(self.row().birth_date, date(1992, 7, 21))
