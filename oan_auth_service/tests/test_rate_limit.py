"""Tests for the request rate limiter and the endpoints that use it."""

import unittest
from types import SimpleNamespace

import frappe

from oan_auth_service.api.utils import check_rate_limit
from oan_auth_service.api.v1.auth import forgot_password
from oan_auth_service.tests.utils import clear_rate_limits

KEY = "oan_auth:test_rate_limit"


class TestCheckRateLimit(unittest.TestCase):
	def setUp(self):
		clear_rate_limits()
		self.addCleanup(clear_rate_limits)

	def test_allows_the_limit_then_refuses_with_429(self):
		for _call in range(3):
			check_rate_limit(KEY, limit=3, window=60)
		with self.assertRaises(frappe.TooManyRequestsError) as caught:
			check_rate_limit(KEY, limit=3, window=60)
		self.assertEqual(caught.exception.http_status_code, 429)

	def test_keeps_refusing_until_the_window_ends(self):
		check_rate_limit(KEY, limit=1, window=60)
		for _call in range(3):
			with self.assertRaises(frappe.TooManyRequestsError):
				check_rate_limit(KEY, limit=1, window=60)

	def test_callers_are_counted_separately(self):
		check_rate_limit(f"{KEY}:a", limit=1, window=60)
		check_rate_limit(f"{KEY}:b", limit=1, window=60)
		with self.assertRaises(frappe.TooManyRequestsError):
			check_rate_limit(f"{KEY}:a", limit=1, window=60)

	def test_the_counter_expires_with_the_window(self):
		check_rate_limit(KEY, limit=5, window=60)
		ttl = frappe.cache.ttl(frappe.cache.make_key(KEY))
		self.assertTrue(0 < ttl <= 60, ttl)

	def test_a_counter_without_an_expiry_is_given_one(self):
		redis_key = frappe.cache.make_key(KEY)
		frappe.cache.set(redis_key, 1)  # what a crash between INCR and EXPIRE would leave
		self.assertEqual(frappe.cache.ttl(redis_key), -1)
		check_rate_limit(KEY, limit=5, window=60)
		self.assertTrue(0 < frappe.cache.ttl(redis_key) <= 60)

	def test_clearing_the_counters_restores_the_budget(self):
		check_rate_limit(KEY, limit=1, window=60)
		clear_rate_limits()
		check_rate_limit(KEY, limit=1, window=60)


class TestForgotPasswordIsRateLimited(unittest.TestCase):
	"""Forgot password: 10 requests an hour from one address and 3 an hour for one account (Form Validation Summary)."""

	def setUp(self):
		clear_rate_limits()
		self.addCleanup(clear_rate_limits)
		previous = getattr(frappe.local, "request_ip", None)
		frappe.local.request_ip = "203.0.113.7"
		self.addCleanup(setattr, frappe.local, "request_ip", previous)
		# Frappe's `@rate_limit` does nothing outside a request.
		previous_request = getattr(frappe.local, "request", None)
		frappe.local.request = SimpleNamespace(method="POST")
		self.addCleanup(setattr, frappe.local, "request", previous_request)

	def request(self, usr):
		"""Call the endpoint as a request would: the per-account limit reads `usr` from the form."""
		frappe.local.form_dict = frappe._dict(cmd="forgot_password", usr=usr)
		return forgot_password(usr=usr)

	def test_the_fourth_request_for_one_account_in_an_hour_is_refused(self):
		for attempt in range(3):
			res = self.request("nobody-here@example.com")
			self.assertEqual(res["status"], "success", msg=(attempt, res))
		res = self.request("nobody-here@example.com")
		self.assertEqual(res["status"], "error")
		self.assertEqual(res["code"], "RATE_LIMIT_EXCEEDED")
		self.assertEqual(frappe.response["http_status_code"], 429)

	def test_the_eleventh_request_from_one_address_in_an_hour_is_refused(self):
		for attempt in range(10):
			res = self.request(f"nobody-{attempt}@example.com")
			self.assertEqual(res["status"], "success", msg=(attempt, res))
		res = self.request("nobody-10@example.com")
		self.assertEqual(res["status"], "error")
		self.assertEqual(res["code"], "RATE_LIMIT_EXCEEDED")
		self.assertEqual(frappe.response["http_status_code"], 429)

	def test_another_address_is_not_affected(self):
		for attempt in range(11):
			self.request(f"nobody-{attempt}@example.com")
		frappe.local.request_ip = "203.0.113.8"
		self.assertEqual(self.request("nobody-11@example.com")["status"], "success")
