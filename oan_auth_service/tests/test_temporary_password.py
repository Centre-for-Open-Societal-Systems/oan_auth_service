"""Tests for temporary passwords: issuing one, signing in with it, and replacing it."""

import json
import unittest
from types import SimpleNamespace

import frappe
import frappe.api

from oan_auth_service.api import tokens
from oan_auth_service.api.middleware import validate_jwt_request
from oan_auth_service.api.router import ensure_routes_registered
from oan_auth_service.api.v1.auth import _issue_token_pair, issue_temporary_password
from oan_auth_service.setup.install import MUST_CHANGE_PASSWORD_FIELD
from oan_auth_service.tests.test_router import make_test_request
from oan_auth_service.tests.utils import cleanup_user, configured_keys, make_user

TEMPORARY = "Temp1234"
OWN = "MyOwnPassword1!"


def _call(path: str, data: dict, headers: dict | None = None) -> tuple[int, dict]:
	req = make_test_request(path, method="POST", data=data, headers=headers)
	res = frappe.api.handle(req)
	return res.status_code, json.loads(res.get_data(as_text=True))


def _flagged(user: str) -> bool:
	return bool(frappe.db.get_value("User", user, MUST_CHANGE_PASSWORD_FIELD))


class TestTemporaryPassword(unittest.TestCase):
	def setUp(self):
		ensure_routes_registered()
		self.users = []
		# The endpoints are rate limited per caller address; start each test with a clean budget.
		for key in ("oan_auth:set_initial_pwd:127.0.0.1",):
			frappe.cache.delete_value(key)

	def tearDown(self):
		for user in self.users:
			cleanup_user(user)
		frappe.set_user("Administrator")

	def _officer(self, temporary: bool = True) -> str:
		email = f"temp_{frappe.generate_hash(length=8)}@example.com"
		user = make_user(email, "Original1!")
		self.users.append(user)
		if temporary:
			issue_temporary_password(user, TEMPORARY)
			frappe.db.commit()  # nosemgrep: frappe-manual-commit
		return user

	# -- signing in ---------------------------------------------------------

	def test_temporary_password_cannot_open_a_session(self):
		user = self._officer()

		with configured_keys():
			status, body = _call("/api/v1/auth/login", {"usr": user, "pwd": TEMPORARY})

		self.assertEqual(status, 403)
		self.assertEqual(body["code"], "PASSWORD_CHANGE_REQUIRED")
		self.assertNotIn("access_token", json.dumps(body))
		self.assertNotIn("refresh_token", json.dumps(body))

	def test_wrong_password_is_still_a_plain_401(self):
		"""A flagged account must not answer differently to a wrong password, or login becomes an oracle."""
		user = self._officer()

		with configured_keys():
			status, body = _call("/api/v1/auth/login", {"usr": user, "pwd": "Not-the-password-1"})

		self.assertEqual(status, 401)
		self.assertEqual(body["code"], "AUTHENTICATION_ERROR")

	def test_ordinary_account_signs_in_normally(self):
		user = self._officer(temporary=False)

		with configured_keys():
			status, body = _call("/api/v1/auth/login", {"usr": user, "pwd": "Original1!"})

		self.assertEqual(status, 200)
		self.assertIn("access_token", body["data"])

	# -- replacing it -------------------------------------------------------

	def test_set_initial_password_replaces_the_temporary_one(self):
		user = self._officer()

		with configured_keys():
			status, body = _call(
				"/api/v1/auth/password/initial",
				{"usr": user, "current_password": TEMPORARY, "new_password": OWN},
			)
			self.assertEqual(status, 200, msg=body)
			self.assertFalse(_flagged(user))

			status, _body = _call("/api/v1/auth/login", {"usr": user, "pwd": OWN})
			self.assertEqual(status, 200)

			status, _body = _call("/api/v1/auth/login", {"usr": user, "pwd": TEMPORARY})
			self.assertEqual(status, 401)

	def test_set_initial_password_refuses_what_it_should(self):
		flagged = self._officer()
		ordinary = self._officer(temporary=False)

		cases = {
			"wrong current password": (
				{"usr": flagged, "current_password": "Wrong-password-1", "new_password": OWN},
				401,
			),
			"account is not holding a temporary password": (
				{"usr": ordinary, "current_password": "Original1!", "new_password": OWN},
				401,
			),
			"unknown account": (
				{"usr": "nobody@example.com", "current_password": TEMPORARY, "new_password": OWN},
				401,
			),
			"new password equals the temporary one": (
				{"usr": flagged, "current_password": TEMPORARY, "new_password": TEMPORARY},
				400,
			),
			"new password too weak": (
				{"usr": flagged, "current_password": TEMPORARY, "new_password": "password1"},
				400,
			),
		}

		with configured_keys():
			for label, (payload, expected) in cases.items():
				status, body = _call("/api/v1/auth/password/initial", payload)
				self.assertEqual(status, expected, msg=(label, body))

		# None of that may have changed either account.
		self.assertTrue(_flagged(flagged))
		self.assertFalse(_flagged(ordinary))
		with configured_keys():
			status, _body = _call("/api/v1/auth/login", {"usr": ordinary, "pwd": "Original1!"})
			self.assertEqual(status, 200)

	# -- ending sessions the old password opened -----------------------------

	def test_issuing_ends_existing_sessions(self):
		user = self._officer(temporary=False)

		with configured_keys():
			pair = _issue_token_pair(user, remember_me=False)
			frappe.db.commit()  # nosemgrep: frappe-manual-commit

			issue_temporary_password(user, TEMPORARY)
			frappe.db.commit()  # nosemgrep: frappe-manual-commit

			# The refresh token is gone ...
			status, _body = _call("/api/v1/auth/refresh", {"refresh_token": pair["refresh_token"]})
			self.assertEqual(status, 401)

			# ... and so is the access token, which cannot be revoked and is cut off by the flag.
			req = make_test_request(
				"/api/v1/auth/health",
				method="GET",
				headers={"Authorization": f"Bearer {pair['access_token']}"},
			)
			frappe.set_user("Guest")
			frappe.local.session = frappe._dict({"user": "Guest"})
			with self.assertRaises(frappe.AuthenticationError):
				validate_jwt_request(req)

	def test_refresh_refuses_a_token_minted_after_the_flag(self):
		user = self._officer(temporary=False)

		with configured_keys():
			pair = _issue_token_pair(user, remember_me=False)
			frappe.db.set_value("User", user, MUST_CHANGE_PASSWORD_FIELD, 1)
			frappe.db.commit()  # nosemgrep: frappe-manual-commit

			status, body = _call("/api/v1/auth/refresh", {"refresh_token": pair["refresh_token"]})

		self.assertEqual(status, 403)
		self.assertEqual(body["code"], "PASSWORD_CHANGE_REQUIRED")

	def test_valid_access_token_is_accepted_for_an_ordinary_account(self):
		user = self._officer(temporary=False)

		with configured_keys():
			token, _ttl = tokens.issue_access_token(user, [])
			req = make_test_request(
				"/api/v1/auth/health", method="GET", headers={"Authorization": f"Bearer {token}"}
			)
			frappe.set_user("Guest")
			frappe.local.session = frappe._dict({"user": "Guest"})
			validate_jwt_request(req)

		self.assertEqual(frappe.session.user, user)

	# -- reissuing ----------------------------------------------------------

	def test_reissuing_flags_the_account_again_and_kills_the_old_password(self):
		user = self._officer()

		with configured_keys():
			status, _body = _call(
				"/api/v1/auth/password/initial",
				{"usr": user, "current_password": TEMPORARY, "new_password": OWN},
			)
			self.assertEqual(status, 200)
			self.assertFalse(_flagged(user))

			issue_temporary_password(user, "Another1234")
			frappe.db.commit()  # nosemgrep: frappe-manual-commit

			self.assertTrue(_flagged(user))
			status, _body = _call("/api/v1/auth/login", {"usr": user, "pwd": OWN})
			self.assertEqual(status, 401)
			status, body = _call("/api/v1/auth/login", {"usr": user, "pwd": "Another1234"})
			self.assertEqual((status, body["code"]), (403, "PASSWORD_CHANGE_REQUIRED"))

	def test_a_weak_temporary_password_is_refused_and_changes_nothing(self):
		user = self._officer(temporary=False)

		for weak in ("short1", "lettersonly", "12345678"):
			with self.assertRaises(ValueError, msg=weak):
				issue_temporary_password(user, weak)

		self.assertFalse(_flagged(user))
		with configured_keys():
			status, _body = _call("/api/v1/auth/login", {"usr": user, "pwd": "Original1!"})
		self.assertEqual(status, 200)

	# -- forgotten password ---------------------------------------------------

	def test_resetting_by_key_clears_the_flag(self):
		"""The reset key went to the account holder, so the password they set with it is their own."""
		user = self._officer()
		link = frappe.get_doc("User", user)._reset_password(send_email=False)
		key = link.split("key=")[1]

		# Frappe's update_password signs the user in through the request's login manager,
		# which exists only inside a real web request.
		frappe.local.login_manager = SimpleNamespace(login_as=lambda _user: None)

		try:
			with configured_keys():
				status, body = _call("/api/v1/auth/reset-password", {"key": key, "new_password": OWN})
				self.assertEqual(status, 200, msg=body)
				self.assertFalse(_flagged(user))

				status, _body = _call("/api/v1/auth/login", {"usr": user, "pwd": OWN})
				self.assertEqual(status, 200)
		finally:
			del frappe.local.login_manager
