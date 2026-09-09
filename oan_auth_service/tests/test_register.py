"""Tests for the user registration endpoint."""

import random
import unittest

import frappe

from oan_auth_service.api import tokens
from oan_auth_service.api.v1.auth import register_user
from oan_auth_service.tests.utils import configured_keys, ensure_role, override_conf


def _random_phone() -> str:
	return "98" + "".join(random.choices("0123456789", k=8))


class TestUserRegistration(unittest.TestCase):
	def setUp(self):
		self.created_users = []
		self.created_contacts = []
		ensure_role("Customer")
		ensure_role("System Manager")

	def tearDown(self):
		for user in self.created_users:
			if frappe.db.exists("User", user):
				frappe.db.delete("OAN User Refresh Token", {"user": user})
				contacts = frappe.get_all(
					"Dynamic Link", filters={"link_doctype": "User", "link_name": user}, pluck="parent"
				)
				for c in contacts:
					if frappe.db.exists("Contact", c):
						frappe.delete_doc("Contact", c, force=True, ignore_permissions=True)
				frappe.delete_doc("User", user, force=True, ignore_permissions=True)

		for c in self.created_contacts:
			if frappe.db.exists("Contact", c):
				frappe.delete_doc("Contact", c, force=True, ignore_permissions=True)

		frappe.db.commit()

	def test_register_user_creates_internal_user_and_stores_email_in_contact(self):
		with configured_keys(), override_conf(jwt_self_registerable_roles=["Customer"]):
			email = f"alice_{frappe.generate_hash(length=6)}@example.com"
			res = register_user(
				email=email,
				password="SecurePassword123!",
				full_name="Alice Smith",
				role="Customer",
			)

			self.assertEqual(res["status"], "success")
			data = res["data"]
			user_id = data["user"]
			self.created_users.append(user_id)

			# User name/email must be an internal mail id
			self.assertTrue(user_id.endswith("@id.openagrinet.internal"))
			self.assertEqual(len(user_id.split("@")[0]), 16)

			# Token verification
			claims = tokens.decode_access_token(data["access_token"])
			self.assertEqual(claims["sub"], user_id)
			self.assertEqual(claims["roles"], ["Customer"])

			# User doctype verification
			user_doc = frappe.get_doc("User", user_id)
			self.assertEqual(user_doc.first_name, "Alice")
			self.assertEqual(user_doc.last_name, "Smith")
			self.assertEqual(user_doc.email, user_id)

			# Contact doctype verification
			contact_name = frappe.db.get_value(
				"Dynamic Link", {"link_doctype": "User", "link_name": user_id}, "parent"
			)
			self.assertTrue(bool(contact_name))
			self.created_contacts.append(contact_name)

			contact_doc = frappe.get_doc("Contact", contact_name)
			self.assertEqual(contact_doc.user, user_id)
			self.assertEqual(contact_doc.first_name, "Alice")
			self.assertEqual(contact_doc.last_name, "Smith")
			self.assertEqual(contact_doc.email_id, email)
			self.assertEqual(len(contact_doc.email_ids), 1)
			self.assertEqual(contact_doc.email_ids[0].email_id, email)
			self.assertEqual(contact_doc.email_ids[0].is_primary, 1)

	def test_register_user_without_email_creates_internal_user(self):
		with configured_keys(), override_conf(jwt_self_registerable_roles=["Customer"]):
			phone = _random_phone()
			res = register_user(
				email=None,
				password="SecurePassword123!",
				full_name="Bob Jones",
				phone_number=phone,
				role="Customer",
			)

			self.assertEqual(res["status"], "success")
			data = res["data"]
			user_id = data["user"]
			self.created_users.append(user_id)

			self.assertTrue(user_id.endswith("@id.openagrinet.internal"))

			user_doc = frappe.get_doc("User", user_id)
			self.assertEqual(user_doc.first_name, "Bob")
			self.assertEqual(user_doc.last_name, "Jones")
			self.assertEqual(user_doc.mobile_no, phone)

			contact_name = frappe.db.get_value(
				"Dynamic Link", {"link_doctype": "User", "link_name": user_id}, "parent"
			)
			self.assertTrue(bool(contact_name))
			self.created_contacts.append(contact_name)

			contact_doc = frappe.get_doc("Contact", contact_name)
			self.assertEqual(contact_doc.user, user_id)
			self.assertEqual(contact_doc.mobile_no, phone)

	def test_duplicate_email_in_contact_rejected(self):
		with configured_keys(), override_conf(jwt_self_registerable_roles=["Customer"]):
			email = f"dup_{frappe.generate_hash(length=6)}@example.com"
			res1 = register_user(
				email=email,
				password="SecurePassword123!",
				full_name="User One",
				role="Customer",
			)
			self.assertEqual(res1["status"], "success")
			self.created_users.append(res1["data"]["user"])

			# Second registration with same email should fail
			res2 = register_user(
				email=email,
				password="SecurePassword123!",
				full_name="User Two",
				role="Customer",
			)
			self.assertEqual(res2["status"], "error")
			self.assertEqual(res2["code"], "VALIDATION_ERROR")
			self.assertIn("already exists", res2["message"])

	def test_duplicate_phone_number_rejected(self):
		with configured_keys(), override_conf(jwt_self_registerable_roles=["Customer"]):
			phone = _random_phone()
			res1 = register_user(
				email=None,
				password="SecurePassword123!",
				full_name="Phone User One",
				phone_number=phone,
				role="Customer",
			)
			self.assertEqual(res1["status"], "success")
			self.created_users.append(res1["data"]["user"])

			# Second registration with same phone should fail
			res2 = register_user(
				email=None,
				password="SecurePassword123!",
				full_name="Phone User Two",
				phone_number=phone,
				role="Customer",
			)
			self.assertEqual(res2["status"], "error")
			self.assertEqual(res2["code"], "VALIDATION_ERROR")
			self.assertIn("already exists", res2["message"])

	def test_missing_password_rejected(self):
		with configured_keys(), override_conf(jwt_self_registerable_roles=["Customer"]):
			res = register_user(
				email="nopass@example.com",
				password="",
				full_name="No Pass",
				role="Customer",
			)
			self.assertEqual(res["status"], "error")
			self.assertEqual(res["code"], "VALIDATION_ERROR")
			self.assertIn("password", res.get("details", {}))

	def test_missing_full_name_rejected(self):
		with configured_keys(), override_conf(jwt_self_registerable_roles=["Customer"]):
			res = register_user(
				email="noname@example.com",
				password="SecurePassword123!",
				full_name="",
				role="Customer",
			)
			self.assertEqual(res["status"], "error")
			self.assertEqual(res["code"], "VALIDATION_ERROR")
			self.assertIn("full_name", res.get("details", {}))

	def test_password_complexity_rejected(self):
		with configured_keys(), override_conf(jwt_self_registerable_roles=["Customer"]):
			# Missing special character
			res = register_user(
				email="weakpass@example.com",
				password="Password12345",
				full_name="Weak Pass",
				role="Customer",
			)
			self.assertEqual(res["status"], "error")
			self.assertEqual(res["code"], "VALIDATION_ERROR")
			self.assertIn("password", res.get("details", {}))

	def test_invalid_email_format_rejected(self):
		with configured_keys(), override_conf(jwt_self_registerable_roles=["Customer"]):
			res = register_user(
				email="not-an-email",
				password="SecurePassword123!",
				full_name="Bad Email",
				role="Customer",
			)
			self.assertEqual(res["status"], "error")
			self.assertEqual(res["code"], "VALIDATION_ERROR")
			self.assertIn("email", res.get("details", {}))
