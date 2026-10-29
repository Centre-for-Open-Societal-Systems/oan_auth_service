"""STG-478: validation errors name their field and state the rule that was broken.

The rules come from the auth rows of RefferDocs/Form-Validation-Summary.xlsx: login,
register, reset and set-initial password, and the temporary password an admin sets.
Each test pins the wording a client sees as `details[<field>]` in the 400 response.
"""

import unittest
from unittest import mock

import frappe
from pydantic import ValidationError

from oan_auth_service.api.field_errors import (
	field_label,
	friendly_code,
	friendly_message,
	validation_codes,
)
from oan_auth_service.api.v1 import admin, auth
from oan_auth_service.tests.utils import configured_keys, ensure_role, override_conf


def _errors(model, **payload):
	"""{field: message} for a payload the schema refuses; empty when it accepts."""
	try:
		model(**payload)
	except ValidationError as error:
		return {".".join(str(part) for part in e["loc"]): friendly_message(e) for e in error.errors()}
	return {}


GOOD_PASSWORD = "Secure#Pass1"


class TestLoginMessages(unittest.TestCase):
	"""Login: email/username and password are required, 1+ characters."""

	def test_required(self):
		self.assertEqual(
			_errors(auth.LoginSchema),
			{
				"usr": "Email or username is required.",
				"pwd": "Password is required.",
			},
		)

	def test_empty_values_count_as_missing(self):
		self.assertEqual(
			_errors(auth.LoginSchema, usr="", pwd=""),
			{
				"usr": "Email or username is required.",
				"pwd": "Password is required.",
			},
		)

	def test_one_character_is_enough(self):
		self.assertEqual(_errors(auth.LoginSchema, usr="a", pwd="b"), {})


class TestRegisterMessages(unittest.TestCase):
	"""Register: full name 1-140, email format, password 8-128 with letter, number, symbol."""

	Register = auth.RegisterUserSchema

	def _payload(self, **overrides):
		return {"email": "a@example.com", "password": GOOD_PASSWORD, "full_name": "Alice", **overrides}

	def test_valid(self):
		self.assertEqual(_errors(self.Register, **self._payload()), {})

	def test_full_name_boundaries(self):
		self.assertEqual(_errors(self.Register, **self._payload(full_name="n")), {})
		self.assertEqual(_errors(self.Register, **self._payload(full_name="n" * 140)), {})
		self.assertEqual(
			_errors(self.Register, **self._payload(full_name="n" * 141)),
			{"full_name": "Full name must not exceed 140 characters."},
		)
		self.assertEqual(
			_errors(self.Register, **self._payload(full_name="")), {"full_name": "Full name is required."}
		)

	def test_required_fields(self):
		self.assertEqual(
			_errors(self.Register, email="a@example.com"),
			{"password": "Password is required.", "full_name": "Full name is required."},
		)

	def test_password_length_boundaries(self):
		self.assertEqual(_errors(self.Register, **self._payload(password="aB3#" * 2)), {})
		self.assertEqual(_errors(self.Register, **self._payload(password="aB3#" * 32)), {})
		self.assertEqual(
			_errors(self.Register, **self._payload(password="aB3#aB3")),
			{"password": "Password must contain at least 8 characters."},
		)
		self.assertEqual(
			_errors(self.Register, **self._payload(password="aB3#" * 32 + "x")),
			{"password": "Password must not exceed 128 characters."},
		)

	def test_password_complexity(self):
		cases = {
			"12345678!": "Password must contain at least one letter.",
			"Password!": "Password must contain at least one number.",
			"Password12": "Password must contain at least one special character.",
		}
		for password, message in cases.items():
			with self.subTest(password=password):
				self.assertEqual(
					_errors(self.Register, **self._payload(password=password)), {"password": message}
				)

	def test_email_format(self):
		self.assertEqual(
			_errors(self.Register, **self._payload(email="not-an-email")),
			{"email": "Email address is not in a valid format."},
		)

	def test_all_errors_are_reported_together(self):
		errors = _errors(self.Register, email="bad", password="short", full_name="n" * 141)
		self.assertEqual(sorted(errors), ["email", "full_name", "password"])


class TestPasswordFlowMessages(unittest.TestCase):
	"""Reset and set-initial password: 8-128 characters with the complexity rule."""

	def test_set_initial_password(self):
		Schema = auth.SetInitialPasswordSchema
		base = {"usr": "u@example.com", "current_password": "Temp1234"}
		self.assertEqual(_errors(Schema, **base, new_password=GOOD_PASSWORD), {})
		self.assertEqual(
			_errors(Schema, **base, new_password="aB3#aB3"),
			{"new_password": "New password must contain at least 8 characters."},
		)
		self.assertEqual(
			_errors(Schema, **base, new_password="aB3#" * 32 + "x"),
			{"new_password": "New password must not exceed 128 characters."},
		)
		self.assertEqual(
			_errors(Schema, usr="u@example.com", new_password=GOOD_PASSWORD),
			{"current_password": "Current password is required."},
		)

	def test_reset_password(self):
		Schema = auth.ResetPasswordSchema
		self.assertEqual(_errors(Schema, key="k", new_password=GOOD_PASSWORD), {})
		self.assertEqual(
			_errors(Schema, key="k", new_password="short1!"),
			{"new_password": "New password must contain at least 8 characters."},
		)
		self.assertEqual(
			_errors(Schema, key="k", new_password="NoNumbers!"),
			{"new_password": "Password must contain at least one number."},
		)

	def test_forgot_password_needs_an_account_name(self):
		self.assertEqual(
			_errors(auth.ForgotPasswordSchema, usr=""), {"usr": "Email or username is required."}
		)


class TestAdminMessages(unittest.TestCase):
	"""Admin-created accounts: full name 1-140, temporary password 8-128 with a letter and a number."""

	def test_full_name(self):
		Schema = admin.AdminCreateUserSchema
		self.assertEqual(_errors(Schema, full_name="n" * 140, email="a@example.com"), {})
		self.assertEqual(
			_errors(Schema, full_name="n" * 141, email="a@example.com"),
			{"full_name": "Full name must not exceed 140 characters."},
		)
		self.assertEqual(_errors(Schema, email="a@example.com"), {"full_name": "Full name is required."})

	def test_temporary_password(self):
		Schema = admin.AdminTemporaryPasswordSchema
		self.assertEqual(_errors(Schema, user_id="u", temporary_password="abcd1234"), {})
		self.assertEqual(_errors(Schema, user_id="u", temporary_password="a1" * 64), {})
		self.assertEqual(
			_errors(Schema, user_id="u", temporary_password="abc123"),
			{"temporary_password": "Password must be at least 8 characters."},
		)
		self.assertEqual(
			_errors(Schema, user_id="u", temporary_password="a1" * 64 + "x"),
			{"temporary_password": "Temporary password must not exceed 128 characters."},
		)
		self.assertEqual(
			_errors(Schema, user_id="u", temporary_password="abcdefgh"),
			{"temporary_password": "Password must contain at least one letter and one number."},
		)


class TestRewriter(unittest.TestCase):
	"""The wording rules, independent of any one schema."""

	def test_labels(self):
		self.assertEqual(field_label(("phone_number",)), "Phone number")
		self.assertEqual(field_label(("user_id",)), "User ID")
		self.assertEqual(field_label(("pwd",)), "Password")
		self.assertEqual(field_label(()), "This value")

	def test_wording_for_each_rule(self):
		def line(kind, **ctx):
			return {"type": kind, "loc": ("code",), "msg": "original", "ctx": ctx}

		self.assertEqual(friendly_message(line("string_too_short", min_length=1)), "Code is required.")
		self.assertEqual(
			friendly_message(line("string_too_short", min_length=3)),
			"Code must contain at least 3 characters.",
		)
		self.assertEqual(
			friendly_message(line("string_too_long", max_length=1)), "Code must not exceed 1 character."
		)
		self.assertEqual(friendly_message(line("greater_than_equal", ge=1)), "Code must be at least 1.")
		self.assertEqual(friendly_message(line("less_than_equal", le=100)), "Code must not exceed 100.")
		self.assertEqual(friendly_message(line("int_parsing")), "Code must be a whole number.")

	def test_rewriting_twice_changes_nothing(self):
		once = {
			"type": "string_too_long",
			"loc": ("code",),
			"msg": "Code must not exceed 5 characters.",
			"ctx": {},
		}
		self.assertEqual(friendly_message(once), "Code must not exceed 5 characters.")

	def test_messages_with_their_own_label_pass_through(self):
		error = {
			"type": "string_too_long",
			"loc": ("reason",),
			"msg": "Justification must not exceed 1000 characters.",
			"ctx": {"label": "Justification", "max_length": 1000},
		}
		self.assertEqual(friendly_message(error), "Justification must not exceed 1000 characters.")

	def test_unknown_kinds_keep_their_text(self):
		error = {"type": "something_new", "loc": ("x",), "msg": "Kept as is", "ctx": {}}
		self.assertEqual(friendly_message(error), "Kept as is")


class TestCodes(unittest.TestCase):
	"""Stable codes and limits, for clients that show their own translation."""

	def test_code_is_the_error_type_with_its_limits(self):
		def line(kind, **ctx):
			return {"type": kind, "loc": ("code",), "msg": "original", "ctx": ctx}

		self.assertEqual(
			friendly_code(line("string_too_long", max_length=140)),
			{"code": "string_too_long", "max_length": 140},
		)
		self.assertEqual(
			friendly_code(line("string_too_short", min_length=8)),
			{"code": "string_too_short", "min_length": 8},
		)
		self.assertEqual(
			friendly_code(line("greater_than_equal", ge=1)), {"code": "greater_than_equal", "ge": 1}
		)
		self.assertEqual(friendly_code(line("missing")), {"code": "missing"})

	def test_an_empty_string_is_missing_to_the_client_too(self):
		error = {"type": "string_too_short", "loc": ("usr",), "msg": "x", "ctx": {"min_length": 1}}
		self.assertEqual(friendly_code(error), {"code": "missing", "min_length": 1})
		self.assertEqual(friendly_message(error), "Email or username is required.")

	def test_internals_are_not_exposed(self):
		pattern = {"type": "string_pattern_mismatch", "loc": ("x",), "msg": "m", "ctx": {"pattern": "^a$"}}
		value = {"type": "value_error", "loc": ("x",), "msg": "m", "ctx": {"error": ValueError("boom")}}
		self.assertEqual(friendly_code(pattern), {"code": "string_pattern_mismatch"})
		self.assertEqual(friendly_code(value), {"code": "value_error"})

	def test_a_message_with_its_own_label_still_has_a_code(self):
		error = {
			"type": "string_too_long",
			"loc": ("reason",),
			"msg": "Justification must not exceed 1000 characters.",
			"ctx": {"label": "Justification", "max_length": 1000},
		}
		self.assertEqual(friendly_code(error), {"code": "string_too_long", "max_length": 1000})

	def test_codes_are_json_ready_and_cover_every_failing_field(self):
		with self.assertRaises(ValidationError) as caught:
			auth.RegisterUserSchema(email="e", password="short", full_name="n" * 141, role="Customer")
		codes = validation_codes(caught.exception)
		self.assertEqual(codes["password"], {"code": "string_too_short", "min_length": 8})
		self.assertEqual(codes["full_name"], {"code": "string_too_long", "max_length": 140})
		frappe.parse_json(frappe.as_json(codes))


class TestTranslation(unittest.TestCase):
	"""Templates and labels go through `_()` whole, so a translator can supply each."""

	def test_template_and_label_are_translated_as_whole_phrases(self):
		seen = []

		def fake(text):
			seen.append(text)
			return text

		error = {"type": "string_too_long", "loc": ("full_name",), "msg": "m", "ctx": {"max_length": 140}}
		with mock.patch("oan_auth_service.api.field_errors._", side_effect=fake):
			friendly_message(error)
		self.assertIn("Full name", seen)
		self.assertIn("{label} must not exceed {max_length} characters.", seen)

	def test_a_translated_template_is_filled_in(self):
		translations = {
			"Full name": "Nombre completo",
			"{label} must not exceed {max_length} characters.": "{label}: máximo {max_length} caracteres.",
		}
		error = {"type": "string_too_long", "loc": ("full_name",), "msg": "m", "ctx": {"max_length": 140}}
		with mock.patch("oan_auth_service.api.field_errors._", side_effect=lambda t: translations.get(t, t)):
			self.assertEqual(friendly_message(error), "Nombre completo: máximo 140 caracteres.")

	def test_a_translation_that_loses_a_placeholder_falls_back_to_pydantic_text(self):
		error = {"type": "string_too_long", "loc": ("x",), "msg": "pydantic text", "ctx": {"max_length": 5}}
		with mock.patch(
			"oan_auth_service.api.field_errors._", side_effect=lambda t: "{nope}" if "{label}" in t else t
		):
			self.assertEqual(friendly_message(error), "pydantic text")


class TestRegisterEndpoint(unittest.TestCase):
	"""The 400 a client receives, and that a refused registration creates no account."""

	def setUp(self):
		ensure_role("Customer")

	def test_returns_field_messages_and_creates_no_user(self):
		before = frappe.db.count("User")
		with configured_keys(), override_conf(jwt_self_registerable_roles=["Customer"]):
			res = auth.register_user(
				email="not-an-email", password="short", full_name="n" * 141, role="Customer"
			)
		self.assertEqual(res["status"], "error")
		self.assertEqual(res["code"], "VALIDATION_ERROR")
		self.assertEqual(
			res["details"],
			{
				"email": "Email address is not in a valid format.",
				"password": "Password must contain at least 8 characters.",
				"full_name": "Full name must not exceed 140 characters.",
			},
		)
		self.assertEqual(
			res["field_codes"],
			{
				"email": {"code": "value_error"},
				"password": {"code": "string_too_short", "min_length": 8},
				"full_name": {"code": "string_too_long", "max_length": 140},
			},
		)
		self.assertEqual(frappe.response["http_status_code"], 400)
		self.assertEqual(frappe.db.count("User"), before)

	def test_login_names_its_fields(self):
		with configured_keys():
			res = auth.login(usr="", pwd="")
		self.assertEqual(res["code"], "VALIDATION_ERROR")
		self.assertEqual(
			res["details"], {"usr": "Email or username is required.", "pwd": "Password is required."}
		)
		self.assertEqual(frappe.response["http_status_code"], 400)
