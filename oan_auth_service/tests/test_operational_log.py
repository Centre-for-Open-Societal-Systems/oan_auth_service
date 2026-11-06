"""Operational logging: the correlation id, the request log, masking and scrubbing, error rows,
and the guarantee that no credential or personal data reaches a log line."""

import io
import json
import logging
import uuid
from unittest import mock

import frappe
from frappe.tests.utils import FrappeTestCase
from werkzeug.wrappers import Response

from oan_auth_service.api import operational_log as oplog
from oan_auth_service.api import request_log as rl
from oan_auth_service.api.middleware import validate_jwt_request
from oan_auth_service.api.router import ensure_routes_registered
from oan_auth_service.api.utils import handle_api_errors
from oan_auth_service.tests.test_router import make_test_request
from oan_auth_service.tests.utils import configured_keys

JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJqYW5lIn0.c2lnbmF0dXJlLXBhcnQ"
REFRESH = "refresh-abcdef-1234567890"
PASSWORD = "hunter2-Pa55word"
EMAIL = "jane.doe@example.com"
PHONE = "0911223344"
FAYDA = "1234567890123456"
NAME = "Abebe Kebede"
SENSITIVE = (JWT, REFRESH, PASSWORD, EMAIL, PHONE, FAYDA, NAME, "c2lnbmF0dXJlLXBhcnQ")


class CapturedLog:
	"""Stands in for the operational logger and keeps what it was asked to write."""

	def __init__(self, level=logging.DEBUG):
		self.stream = io.StringIO()
		handler = logging.StreamHandler(self.stream)
		handler.setFormatter(oplog.JsonFormatter())
		self.logger = logging.getLogger(f"oan-test-{uuid.uuid4().hex}")
		self.logger.setLevel(level)
		self.logger.propagate = False
		self.logger.addHandler(handler)
		self._patch = mock.patch.object(oplog, "get_logger", return_value=self.logger)

	def __enter__(self):
		self._patch.start()
		return self

	def __exit__(self, *exc):
		self._patch.stop()

	@property
	def text(self) -> str:
		return self.stream.getvalue()

	@property
	def events(self) -> list[dict]:
		return [json.loads(line) for line in self.text.splitlines() if line]

	def named(self, event: str) -> list[dict]:
		return [e for e in self.events if e["event"] == event]


class LogCase(FrappeTestCase):
	def setUp(self):
		super().setUp()
		self._reset_request_state()
		self.addCleanup(self._reset_request_state)

	@staticmethod
	def _reset_request_state():
		frappe.local.request_id = None
		frappe.local.oan_request_started = None

	def assertNoLeak(self, text: str):
		for secret in SENSITIVE:
			self.assertNotIn(secret, text, msg=f"{secret!r} reached the log")


class TestMasking(FrappeTestCase):
	def test_contact_details_are_masked(self):
		self.assertEqual(oplog.mask_email(EMAIL), "j***@example.com")
		self.assertEqual(oplog.mask_phone(PHONE), "***44")
		self.assertEqual(oplog.mask_phone("+251911234567"), "***67")
		self.assertEqual(oplog.mask_name(NAME), "A*** K***")
		self.assertEqual(oplog.mask_identifier(FAYDA), "***56")
		self.assertEqual(oplog.mask_ip("196.188.12.34"), "196.188.12.0")
		self.assertEqual(oplog.mask_ip("2001:db8:85a3:8d3:1319:8a2e:370:7348"), "2001:db8:85a3::")

	def test_a_user_id_is_masked_whatever_it_looks_like(self):
		self.assertEqual(oplog.mask_user(EMAIL), "j***@example.com")
		self.assertEqual(oplog.mask_user("+251911234567"), "***67")
		self.assertEqual(oplog.mask_user("abebe"), "a***")
		self.assertEqual(oplog.mask_user("Administrator"), "Administrator")
		self.assertIsNone(oplog.mask_user(None))

	def test_short_values_are_hidden_rather_than_partly_shown(self):
		self.assertEqual(oplog.mask_phone("123"), oplog.MASKED)
		self.assertEqual(oplog.mask_identifier("1234"), oplog.MASKED)
		self.assertEqual(oplog.mask_email("not-an-email"), oplog.MASKED)

	def test_free_text_loses_credentials_and_personal_data(self):
		text = (
			f"login failed for {EMAIL} password={PASSWORD} Authorization: Bearer {JWT} "
			f'{{"refresh_token": "{REFRESH}"}} phone {PHONE} fayda {FAYDA}'
		)
		clean = oplog.scrub_text(text)
		self.assertNoLeakIn(clean)
		self.assertIn("login failed for j***@example.com", clean)

	def assertNoLeakIn(self, text: str):
		for secret in (JWT, REFRESH, PASSWORD, EMAIL, PHONE, FAYDA):
			self.assertNotIn(secret, text)

	def test_ordinary_words_are_not_taken_for_credentials(self):
		for text in (
			"Invalid token provided",
			"Basic settings are missing for this category",
			"The bearer of this notice must attend",
			"token expired - please sign in again",
			"Missing bearer credentials in request",
		):
			with self.subTest(text=text):
				self.assertEqual(oplog.scrub_text(text), text)

	def test_credentials_are_found_by_their_shape(self):
		opaque = "AbCdEf0123456789xyzXYZ-_.~+/=abc"
		for text, secret in (
			(f"Authorization: Bearer {opaque}", opaque),
			(f"authorization=Bearer {opaque}", opaque),
			(f"'Authorization': 'Bearer {opaque}'", opaque),
			('{"Authorization": "token key123:secret456"}', "secret456"),
			("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"),
			(f"sent Bearer {opaque} to the gateway", opaque),
			(f"jwt {JWT}", "c2lnbmF0dXJlLXBhcnQ"),
		):
			with self.subTest(text=text):
				clean = oplog.scrub_text(text)
				self.assertNotIn(secret, clean)
				self.assertIn(oplog.REDACTED, clean)

	def test_phone_numbers_are_found_whatever_their_spacing(self):
		for number in (
			"+251 911 234 567",
			"+251-911-234-567",
			"+251911234567",
			"0911 223 344",
			"0911-223-344",
			"0911223344",
			"251911223344",
			"+1 415 555 0132",
			"+44 20 7946 0958",
		):
			with self.subTest(number=number):
				clean = oplog.scrub_text(f"call {number} now")
				self.assertEqual(clean[:5], "call ")
				self.assertRegex(clean, r"^call \*\*\*\d\d now$")

	def test_a_fayda_id_is_masked_but_other_long_numbers_are_not(self):
		self.assertEqual(oplog.scrub_text(f"id {FAYDA}"), "id ***56")
		for text in (
			"epoch 1730000000",
			"epoch ms 1730000000000",
			"order 123456789012",
			"ticket 012345678 and 300100200",
			"took 1234567890 ns",
			"at 2026-11-06 10:15:00",
			"v1.2.3 build 20261106",
			"range 0-9999999999 allowed",
		):
			with self.subTest(text=text):
				self.assertEqual(oplog.scrub_text(text), text)

	def test_scrubbing_stays_fast_on_long_unbroken_input(self):
		"""A traceback lists every local variable, so a log call can be handed a huge string.

		These patterns were quadratic in the length of a run of letters (`x` * 32,000 took
		seconds, `token_` * 5,000 longer); a log line must never cost that.
		"""
		import time

		size = 300_000
		hostile = {
			"letters": "x" * size,
			"digits": "7" * size,
			"token_": "token_" * (size // 6),
			"email_": "email_" * (size // 6),
			"address-ish": "a.b-c" * (size // 5),
			"eyJ": "eyJabcde." * (size // 9),
			"plus": "+1 " * (size // 3),
			"quotes": "'password' " * (size // 11),
		}
		for label, text in hostile.items():
			for name, call in (
				("scrub_text", lambda t: oplog.scrub_text(t)),
				("scrub_text tail", lambda t: oplog.scrub_text(t, keep="tail")),
				("scrub_traceback", lambda t: oplog.scrub_traceback("      local = '" + t + "'")),
				("email", lambda t: oplog._EMAIL.sub("", t)),
				("secret pair", lambda t: oplog._SECRET_PAIR.sub("", t)),
				("pii pair", lambda t: oplog._PII_PAIR.sub("", t)),
			):
				with self.subTest(input=label, scrubber=name):
					started = time.perf_counter()
					call(text)
					# Linear takes a few hundredths of a second; the quadratic form took minutes.
					self.assertLess(time.perf_counter() - started, 3.0)

	def test_only_a_bounded_amount_is_scanned_and_the_end_is_what_is_kept(self):
		text = "noise\n" * 500_000 + "ValueError: the real message"
		clean = oplog.scrub_traceback(text)
		self.assertTrue(clean.endswith("ValueError: the real message"))
		self.assertLessEqual(len(clean), oplog.ERROR_LOG_LIMIT)
		head = oplog.scrub_text("start " + "y" * 1_000_000, 100)
		self.assertTrue(head.startswith("start yyy"))
		self.assertEqual(len(head), 100)

	def test_emails_are_still_masked_after_the_anchoring(self):
		for text, expected in (
			("jane.doe@example.com", "j***@example.com"),
			("mail <jane.doe@example.com>", "mail <j***@example.com>"),
			("user=jane@x.org;", "user=j***@x.org;"),
			('{"email": "a.b+tag@sub.example.co.uk"}', '{"email": "a***@sub.example.co.uk"}'),
			("a@b.co and c@d.io", "a***@b.co and c***@d.io"),
			("(x_y-z@mail.example.org)", "(x***@mail.example.org)"),
		):
			with self.subTest(text=text):
				self.assertEqual(oplog.scrub_text(text), expected)

	def test_secret_names_are_still_found_with_prefixes_and_quotes(self):
		for text in (
			"new_password=hunter2xx",
			"old_password: hunter2xx",
			'"refresh_token": "hunter2xx"',
			"{'api_key': 'hunter2xx'}",
			"user_token=hunter2xx&x=1",
			"client_secret = hunter2xx",
			"pwd=hunter2xx",
			"otp: hunter2xx",
		):
			with self.subTest(text=text):
				clean = oplog.scrub_text(text)
				self.assertNotIn("hunter2xx", clean)
				self.assertIn(oplog.REDACTED, clean)

	def test_personal_keys_are_still_found_in_a_dict_dump(self):
		line = "      case = {'contact_email': 'jane@x.org', 'submitter_name': 'Abebe', 'mobile_no': '0911', 'id': 7}"
		clean = oplog.scrub_traceback(line)
		self.assertNotIn("Abebe", clean)
		self.assertNotIn("jane@x.org", clean)
		self.assertIn("'id': 7", clean)

	def test_a_ticket_number_is_not_mistaken_for_a_phone_number(self):
		self.assertEqual(oplog.scrub_text("ticket 300100200 and 3001002A0"), "ticket 300100200 and 3001002A0")

	def test_timestamps_and_short_numbers_survive(self):
		text = "2026-11-06 10:15:00 line 1234 took 250 ms"
		self.assertEqual(oplog.scrub_text(text), text)

	def test_long_text_is_cut(self):
		clean = oplog.scrub_text("x" * 5000)
		# The marker counts toward the limit, so a column of that width is never overrun.
		self.assertEqual(len(clean), 2000)
		self.assertTrue(clean.endswith(oplog.TRUNCATED_END))
		self.assertTrue(clean.startswith("xxx"))

	def test_a_cut_can_keep_the_end_instead(self):
		clean = oplog.scrub_text("a" * 100 + "THE END", 50, keep="tail")
		self.assertEqual(len(clean), 50)
		self.assertTrue(clean.startswith(oplog.TRUNCATED_START))
		self.assertTrue(clean.endswith("THE END"))

	def test_a_limit_smaller_than_the_marker_still_holds(self):
		self.assertLessEqual(len(oplog.scrub_text("x" * 100, 5)), 5)
		self.assertLessEqual(len(oplog.scrub_text("x" * 100, 5, keep="tail")), 5)

	def test_redact_by_key_covers_credentials_and_personal_fields(self):
		out = oplog.redact(
			{
				"password": PASSWORD,
				"new_password": PASSWORD,
				"access_token": JWT,
				"refresh_token": REFRESH,
				"Authorization": f"Bearer {JWT}",
				"cookie": f"sid={REFRESH}",
				"api_secret": "s3cr3t",
				"otp": "123456",
				"submitter_name": NAME,
				"contact_mobile": PHONE,
				"contact_email": EMAIL,
				"fayda_id": FAYDA,
				"description": "my neighbour took my land",
				"address": "Bole, Addis Ababa",
				"assigned_to": EMAIL,
				"record": "3001002A0",
				"status": "Assigned",
				"count": 3,
			}
		)
		self.assertEqual(out["password"], oplog.REDACTED)
		self.assertEqual(out["new_password"], oplog.REDACTED)
		self.assertEqual(out["access_token"], oplog.REDACTED)
		self.assertEqual(out["refresh_token"], oplog.REDACTED)
		self.assertEqual(out["Authorization"], oplog.REDACTED)
		self.assertEqual(out["cookie"], oplog.REDACTED)
		self.assertEqual(out["api_secret"], oplog.REDACTED)
		self.assertEqual(out["otp"], oplog.REDACTED)
		self.assertEqual(out["submitter_name"], "A*** K***")
		self.assertEqual(out["contact_mobile"], "***44")
		self.assertEqual(out["contact_email"], "j***@example.com")
		self.assertEqual(out["fayda_id"], "***56")
		self.assertEqual(out["description"], oplog.MASKED)
		self.assertEqual(out["address"], oplog.MASKED)
		self.assertEqual(out["assigned_to"], "j***@example.com")
		# What an operator needs is left alone.
		self.assertEqual(out["record"], "3001002A0")
		self.assertEqual(out["status"], "Assigned")
		self.assertEqual(out["count"], 3)

	def test_redact_walks_nested_values_and_scrubs_strings(self):
		out = oplog.redact({"detail": {"items": [{"password": PASSWORD}, f"mail {EMAIL}"]}})
		self.assertEqual(out["detail"]["items"][0]["password"], oplog.REDACTED)
		self.assertNotIn(EMAIL, json.dumps(out))

	def test_redact_does_not_loop_on_a_deep_structure(self):
		deep: dict = {}
		cursor = deep
		for _ in range(50):
			cursor["a"] = {}
			cursor = cursor["a"]
		self.assertIn(oplog.MASKED, json.dumps(oplog.redact(deep)))

	def test_bytes_are_never_logged(self):
		self.assertEqual(oplog.redact({"blob": b"secret bytes"})["blob"], "<12 bytes>")


class TestCorrelationId(LogCase):
	def test_a_plain_inbound_id_is_adopted(self):
		request = make_test_request("/api/v1/widgets/health", headers={"X-Request-Id": "trace-abc-12345"})
		rl.begin()
		self.assertEqual(frappe.local.request_id, "trace-abc-12345")
		self.assertIsNotNone(request)

	def test_a_missing_id_is_generated(self):
		make_test_request("/api/v1/widgets/health")
		rl.begin()
		self.assertTrue(uuid.UUID(frappe.local.request_id))

	def test_an_id_that_could_forge_a_log_line_is_replaced(self):
		for hostile in ("short", "a" * 200, "has space in it", "<script>12345678", 'quote"12345678'):
			with self.subTest(hostile=hostile):
				self._reset_request_state()
				make_test_request("/api/v1/widgets/health", headers={"X-Request-Id": hostile})
				rl.begin()
				self.assertNotEqual(frappe.local.request_id, hostile)
				self.assertTrue(uuid.UUID(frappe.local.request_id))

	def test_an_id_with_a_line_break_is_never_valid(self):
		# A WSGI server will hand one over even though the test client refuses to build it.
		for hostile in ('abc"}\n{"event":"fake"', "abcdefgh\r\nX: y", "abcdefgh\n"):
			with self.subTest(hostile=hostile):
				self.assertIsNone(oplog.valid_correlation_id(hostile))
		trace_id = "0af7651916cd43dd8448eb211c80319c"
		self.assertEqual(oplog.valid_correlation_id(trace_id), trace_id)
		self.assertEqual(oplog.valid_correlation_id("req_01HZX:7-a.b"), "req_01HZX:7-a.b")

	def test_an_id_already_set_is_kept(self):
		frappe.local.request_id = "already-set-12345"
		self.assertEqual(oplog.ensure_correlation_id("other-id-123456"), "already-set-12345")

	def test_other_paths_are_left_alone(self):
		make_test_request("/app/home")
		rl.begin()
		self.assertIsNone(frappe.local.request_id)

	def test_the_api_envelope_carries_the_same_id(self):
		@handle_api_errors
		def handler():
			return {"data": {"ok": True}}

		make_test_request("/api/v1/auth/health", headers={"X-Request-Id": "trace-abc-12345"})
		rl.begin()
		self.assertEqual(handler()["request_id"], "trace-abc-12345")

	def test_a_handler_reached_without_the_hook_validates_the_id_too(self):
		"""`handle_api_errors` used to adopt any inbound id; it now takes the validated route."""

		@handle_api_errors
		def handler():
			return {"data": {"ok": True}}

		make_test_request("/api/v1/auth/health", headers={"X-Request-Id": "has space in it"})
		self.assertNotEqual(handler()["request_id"], "has space in it")
		self._reset_request_state()
		make_test_request("/api/v1/auth/health", headers={"X-Request-Id": "trace-abc-12345"})
		self.assertEqual(handler()["request_id"], "trace-abc-12345")

	def test_every_line_in_a_request_carries_the_id(self):
		make_test_request("/api/v1/widgets/health", headers={"X-Request-Id": "trace-abc-12345"})
		with CapturedLog() as captured:
			rl.begin()
			oplog.emit("custom.event", logging.INFO, detail="x")
			rl.end(Response("{}", status=200, content_type="application/json"), frappe.local.request)
		self.assertTrue(captured.events)
		self.assertEqual({e["correlation_id"] for e in captured.events}, {"trace-abc-12345"})


class TestRequestLogging(LogCase):
	def _run(self, path, status=200, body=None, headers=None, data=None, method="GET", content_type=None):
		request = make_test_request(path, method=method, headers=headers, data=data)
		# Frappe's form_dict holds the query string as well as the body.
		frappe.local.form_dict.update(request.args.to_dict())
		with CapturedLog() as captured:
			rl.begin()
			response = Response(
				json.dumps(body) if body is not None else "{}",
				status=status,
				content_type=content_type or "application/json",
			)
			rl.end(response, request)
		return captured, response

	def test_a_request_is_logged_with_status_duration_and_user(self):
		captured, response = self._run("/api/v1/widgets", status=200)
		self.assertEqual(response.headers["X-Request-Id"], frappe.local.request_id)

		(line,) = captured.named("http.request")
		self.assertEqual(line["level"], "INFO")
		self.assertEqual(line["method"], "GET")
		self.assertEqual(line["path"], "/api/v1/widgets")
		self.assertEqual(line["status"], 200)
		self.assertIsInstance(line["duration_ms"], int | float)
		self.assertGreaterEqual(line["duration_ms"], 0)
		self.assertEqual(line["correlation_id"], frappe.local.request_id)
		self.assertEqual(line["user"], "Administrator")
		self.assertEqual(line["client_ip"], "127.0.0.0")
		self.assertEqual(line["site"], frappe.local.site)
		self.assertIn("ts", line)

	def test_the_response_keeps_a_correlation_header_the_handler_already_set(self):
		request = make_test_request("/api/v1/widgets/health")
		with CapturedLog():
			rl.begin()
			response = Response("{}", status=200, content_type="application/json")
			response.headers["X-Request-Id"] = "from-handler-123"
			rl.end(response, request)
		self.assertEqual(response.headers["X-Request-Id"], "from-handler-123")

	def test_the_level_follows_the_status(self):
		for status, level in (
			(200, "INFO"),
			(302, "INFO"),
			(404, "WARNING"),
			(409, "WARNING"),
			(500, "ERROR"),
		):
			with self.subTest(status=status):
				self._reset_request_state()
				captured, _ = self._run("/api/v1/widgets", status=status)
				self.assertEqual(captured.named("http.request")[0]["level"], level)

	def test_an_error_response_logs_its_code_and_nothing_else_from_the_body(self):
		body = {
			"status": "error",
			"code": "NOT_FOUND",
			"message": f"No grievance for {EMAIL}",
			"details": {"phone": PHONE},
		}
		captured, _ = self._run("/api/v1/widgets/3001002A0/timeline", status=404, body=body)
		(line,) = captured.named("http.request")
		self.assertEqual(line["error_code"], "NOT_FOUND")
		self.assertNoLeak(captured.text)

	def test_a_frappe_error_page_reports_its_exception_type(self):
		captured, _ = self._run(
			"/api/v1/widgets", status=500, body={"exc_type": "OperationalError", "exc": "Traceback"}
		)
		self.assertEqual(captured.named("http.request")[0]["error_code"], "OperationalError")

	def test_a_download_is_not_read(self):
		request = make_test_request("/api/v1/attachments/x/download")
		response = Response(b"%PDF", status=404, content_type="application/pdf")
		with CapturedLog() as captured:
			rl.begin()
			rl.end(response, request)
		self.assertIsNone(captured.named("http.request")[0].get("error_code"))

	def test_a_slow_request_is_flagged_and_raised_to_a_warning(self):
		request = make_test_request("/api/v1/widgets")
		with CapturedLog() as captured, mock.patch.dict(frappe.local.conf, {"oan_slow_request_ms": 1}):
			rl.begin()
			frappe.local.oan_request_started -= 0.5
			rl.end(Response("{}", status=200, content_type="application/json"), request)
		(line,) = captured.named("http.request")
		self.assertTrue(line["slow"])
		self.assertEqual(line["level"], "WARNING")
		self.assertGreaterEqual(line["duration_ms"], 500)

	def test_health_checks_are_debug_lines(self):
		request = make_test_request("/api/v1/auth/ping")
		with CapturedLog(level=logging.INFO) as captured:
			rl.begin()
			rl.end(Response("{}", status=200, content_type="application/json"), request)
		self.assertEqual(captured.named("http.request"), [])

	def test_no_value_from_the_request_reaches_the_log(self):
		captured, _ = self._run(
			f"/api/v1/officers/{EMAIL}?phone={PHONE}&password={PASSWORD}",
			method="POST",
			headers={
				"Authorization": f"Bearer {JWT}",
				"Cookie": f"oan_refresh={REFRESH}",
				"User-Agent": f"curl/8 (contact {EMAIL})",
			},
			data={"submitter_name": NAME, "contact_mobile": PHONE, "fayda_id": FAYDA, "pwd": PASSWORD},
			body={"status": "error", "code": "VALIDATION_ERROR", "message": f"{NAME} {PHONE}"},
			status=400,
		)
		self.assertNoLeak(captured.text)
		(line,) = captured.named("http.request")
		# The path keeps its shape; the officer's address is masked in it.
		self.assertEqual(line["path"], "/api/v1/officers/j***@example.com")
		# Only the names of what was sent are recorded.
		self.assertEqual(
			line["param_names"], ["contact_mobile", "fayda_id", "password", "phone", "pwd", "submitter_name"]
		)

	def test_an_unrelated_request_is_not_logged(self):
		request = make_test_request("/assets/frappe/js/x.js")
		with CapturedLog() as captured:
			rl.begin()
			rl.end(Response("", status=200), request)
		self.assertEqual(captured.events, [])

	def test_a_request_that_failed_before_begin_is_still_logged_and_given_an_id(self):
		"""CSRF, session and maintenance-mode failures happen before before_request hooks."""
		request = make_test_request("/api/v1/widgets", headers={"X-Request-Id": "trace-early-123"})
		self._reset_request_state()  # `begin` never ran
		response = Response(
			json.dumps({"exc_type": "CSRFTokenError"}), status=400, content_type="application/json"
		)
		with CapturedLog() as captured:
			rl.end(response, request)

		self.assertEqual(response.headers["X-Request-Id"], "trace-early-123")
		(line,) = captured.named("http.request")
		self.assertEqual(line["correlation_id"], "trace-early-123")
		self.assertEqual(line["status"], 400)
		self.assertEqual(line["error_code"], "CSRFTokenError")
		self.assertNotIn("duration_ms", line)
		self.assertNotIn("slow", line)

	def test_a_request_that_failed_before_a_session_existed_is_logged(self):
		request = make_test_request("/api/v1/widgets")
		self._reset_request_state()
		response = Response("{}", status=503, content_type="application/json")
		saved = (frappe.local.session, frappe.local.request_ip)
		frappe.local.session = frappe.local.request_ip = None
		try:
			with CapturedLog() as captured:
				rl.end(response, request)
		finally:
			frappe.local.session, frappe.local.request_ip = saved
		(line,) = captured.named("http.request")
		self.assertEqual(line["status"], 503)
		self.assertNotIn("user", line)
		self.assertTrue(uuid.UUID(response.headers["X-Request-Id"]))

	def test_a_logging_fault_does_not_break_the_request(self):
		request = make_test_request("/api/v1/widgets")
		with mock.patch.object(oplog, "get_logger", side_effect=RuntimeError("disk full")):
			rl.begin()
			response = Response("{}", status=200, content_type="application/json")
			rl.end(response, request)
		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.headers["X-Request-Id"], frappe.local.request_id)

	def test_a_request_below_the_configured_level_builds_no_log_fields(self):
		request = make_test_request("/api/v1/widgets")
		with CapturedLog(level=logging.ERROR) as captured, mock.patch.object(oplog, "scrub_path") as scrub:
			rl.begin()
			response = Response("{}", status=200, content_type="application/json")
			rl.end(response, request)
		scrub.assert_not_called()
		self.assertEqual(captured.events, [])
		# The caller still gets its id back.
		self.assertEqual(response.headers["X-Request-Id"], frappe.local.request_id)

	def test_a_disabled_level_costs_nothing(self):
		with CapturedLog(level=logging.ERROR), mock.patch.object(oplog, "redact") as redact:
			oplog.emit("area.something", logging.INFO, record="R-1")
		redact.assert_not_called()


class TestAuthenticationFailures(LogCase):
	def setUp(self):
		super().setUp()
		ensure_routes_registered()

	def _refused(self, status, **request_kwargs):
		request = make_test_request("/api/v1/auth/me", **request_kwargs)
		with CapturedLog() as captured:
			rl.begin()
			rl.end(
				Response(
					json.dumps({"code": "AUTHENTICATION_ERROR"}),
					status=status,
					content_type="application/json",
				),
				request,
			)
		return captured

	def test_a_request_refused_by_the_auth_layer_is_logged_with_its_correlation_id(self):
		"""The auth hook raises after `before_request`, so the refusal has an id to be traced by."""
		frappe.set_user("Guest")
		frappe.local.session = frappe._dict({"user": "Guest"})
		headers = {"Authorization": f"Bearer {JWT}", "X-Request-Id": "trace-abc-12345"}
		request = make_test_request("/api/v1/auth/me", headers=headers)
		rl.begin()
		with configured_keys(), CapturedLog() as captured:
			with self.assertRaises(frappe.AuthenticationError):
				validate_jwt_request(request)
			rl.end(
				Response(
					json.dumps({"code": "AUTHENTICATION_ERROR"}), status=401, content_type="application/json"
				),
				request,
			)
		frappe.set_user("Administrator")

		(failure,) = captured.named("security.auth_failure")
		self.assertEqual(failure["correlation_id"], "trace-abc-12345")
		self.assertEqual(failure["status"], 401)
		self.assertEqual(failure["path"], "/api/v1/auth/me")
		self.assertEqual(failure["error_code"], "AUTHENTICATION_ERROR")
		self.assertEqual(failure["auth_scheme"], "bearer")
		self.assertEqual(failure["level"], "WARNING")
		self.assertNoLeak(captured.text)

	def test_a_failed_sign_in_names_the_account_only_masked(self):
		captured = self._refused(
			401, method="POST", data={"usr": EMAIL, "pwd": PASSWORD}, headers={"User-Agent": "okhttp/4"}
		)
		(failure,) = captured.named("security.auth_failure")
		self.assertEqual(failure["attempted_user"], "j***@example.com")
		self.assertEqual(failure["auth_scheme"], "none")
		self.assertEqual(failure["user_agent"], "okhttp/4")
		self.assertNoLeak(captured.text)

	def test_the_scheme_is_recorded_without_the_credential(self):
		cases = (
			({"Authorization": f"Bearer {JWT}"}, "bearer"),
			({"Authorization": "token key:secret-value"}, "token"),
			({"Authorization": "Basic dXNlcjpwYXNz"}, "basic"),
			({"Authorization": "Negotiate abcdef"}, "other"),
			({"Cookie": f"oan_access={JWT}"}, "cookie"),
			({}, "none"),
		)
		for headers, scheme in cases:
			with self.subTest(scheme=scheme):
				captured = self._refused(401, headers=headers)
				self.assertEqual(captured.named("security.auth_failure")[0]["auth_scheme"], scheme)
				self.assertNoLeak(captured.text)
				self.assertNotIn("secret-value", captured.text)
				self.assertNotIn("dXNlcjpwYXNz", captured.text)

	def test_permission_denied_and_rate_limiting_are_security_events(self):
		self.assertEqual(len(self._refused(403).named("security.permission_denied")), 1)
		self.assertEqual(len(self._refused(429).named("security.rate_limited")), 1)

	def test_other_statuses_raise_no_security_event(self):
		for status in (200, 400, 404, 500):
			with self.subTest(status=status):
				captured = self._refused(status)
				self.assertFalse([e for e in captured.events if e["event"].startswith("security.")])

	def test_a_signed_in_user_denied_is_not_named_in_the_line(self):
		with mock.patch.dict(frappe.local.session, {"user": EMAIL}):
			captured = self._refused(403)
		self.assertNoLeak(captured.text)
		self.assertNotIn("user", captured.named("security.permission_denied")[0])

	def test_an_event_carries_no_credential_even_if_a_caller_passes_one(self):
		with CapturedLog() as captured:
			oplog.emit(
				"security.temporary_password_reissued",
				logging.WARNING,
				user="admin@example.com",
				target_user=EMAIL,
				new_password=PASSWORD,
				temporary_password=PASSWORD,
			)
		(event,) = captured.named("security.temporary_password_reissued")
		self.assertEqual(event["target_user"], "j***@example.com")
		self.assertEqual(event["new_password"], oplog.REDACTED)
		self.assertEqual(event["temporary_password"], oplog.REDACTED)
		self.assertNoLeak(captured.text)


class TestErrorLogging(LogCase):
	def _fail(self, **kwargs):
		try:
			raise ValueError(f"bad input for {EMAIL}: password={PASSWORD} fayda {FAYDA} Bearer {JWT}")
		except ValueError:
			with mock.patch.object(frappe, "log_error") as stored, CapturedLog() as captured:
				oplog.log_error(title="Something failed", **kwargs)
		return stored, captured

	def test_an_error_is_logged_with_its_type_and_correlation_id(self):
		frappe.local.request_id = "trace-abc-12345"
		_, captured = self._fail()
		(line,) = captured.named("error")
		self.assertEqual(line["level"], "ERROR")
		self.assertEqual(line["correlation_id"], "trace-abc-12345")
		self.assertEqual(line["title"], "Something failed")
		self.assertEqual(line["exception"], "ValueError")
		self.assertIn("ValueError", line["detail"])

	def test_the_error_log_row_is_scrubbed_and_traceable(self):
		frappe.local.request_id = "trace-abc-12345"
		stored, captured = self._fail()
		stored.assert_called_once()
		self.assertEqual(stored.call_args.kwargs["title"], "Something failed")
		message = stored.call_args.kwargs["message"]
		self.assertTrue(message.startswith("correlation_id: trace-abc-12345\n"))
		self.assertIn("ValueError", message)
		self.assertNoLeak(message)
		self.assertNoLeak(captured.text)

	def test_the_exception_message_survives_a_long_traceback(self):
		"""A traceback ends with its message, so a cut must drop the start, not the end."""
		frappe.local.request_id = "trace-abc-12345"
		long_tb = ("  File x, line 1, in frame\n      local = 1\n" * 4000) + "ValueError: the real message"
		with (
			mock.patch.object(frappe, "get_traceback", side_effect=lambda with_context=False: long_tb),
			mock.patch.object(frappe, "log_error") as stored,
			CapturedLog() as captured,
		):
			oplog.log_error(title="t")

		message = stored.call_args.kwargs["message"]
		self.assertTrue(message.startswith("correlation_id: trace-abc-12345\n"))
		self.assertTrue(message.endswith("ValueError: the real message"))
		self.assertLessEqual(len(message), oplog.ERROR_LOG_LIMIT + 100)

		(line,) = captured.named("error")
		self.assertEqual(line["summary"], "ValueError: the real message")
		self.assertTrue(line["detail"].endswith("ValueError: the real message"))
		self.assertGreater(len(line["detail"]), oplog.MAX_FIELD_TEXT)
		self.assertLessEqual(len(line["detail"]), oplog.ERROR_DETAIL_LIMIT)

	def test_a_long_explicit_message_also_keeps_its_end(self):
		with mock.patch.object(frappe, "log_error") as stored, CapturedLog() as captured:
			oplog.log_error(title="t", message="start\n" + "x" * 50_000 + "\nFINAL LINE")
		self.assertTrue(stored.call_args.kwargs["message"].endswith("FINAL LINE"))
		self.assertEqual(captured.named("error")[0]["summary"], "FINAL LINE")

	def test_the_title_always_fits_the_error_log_column(self):
		for title in ("x" * 140, "x" * 141, "x" * 500, "Failed for " + "ticket-" * 40):
			with self.subTest(length=len(title)):
				with mock.patch.object(frappe, "log_error") as stored, CapturedLog() as captured:
					oplog.log_error(title=title, message="m")
				stored_title = stored.call_args.kwargs["title"]
				self.assertLessEqual(len(stored_title), 140)
				self.assertLessEqual(len(captured.named("error")[0]["title"]), 140)
		self.assertEqual(stored_title.count("truncated"), 1)

	def test_a_title_with_a_line_break_is_one_line(self):
		"""`frappe.log_error` takes a title containing one to be a swapped traceback."""
		with mock.patch.object(frappe, "log_error") as stored, CapturedLog():
			oplog.log_error(title="first\nsecond", message="m")
		self.assertEqual(stored.call_args.kwargs["title"], "first second")

	def test_a_title_overflow_cannot_hide_the_original_error(self):
		"""The real Error Log raises on a 141-character title; ours is never that long."""
		try:
			raise ValueError("the original failure")
		except ValueError:
			with CapturedLog() as captured:
				oplog.log_error(title="y" * 600)
		self.assertEqual(captured.named("error")[0]["exception"], "ValueError")

	@staticmethod
	def _failed_filing():
		"""Raise from a frame that holds credentials and personal data in its variables."""

		def handler(submitter_name, contact_email, description, password, count, case):
			ticket = "3001002A0"
			raise RuntimeError(f"cannot file {ticket}")

		handler(
			NAME,
			EMAIL,
			"my neighbour took my land",
			PASSWORD,
			3,
			{"contact_mobile": PHONE, "fayda_id": FAYDA, "status": "Open"},
		)

	def test_the_variables_of_each_frame_are_kept_and_scrubbed(self):
		"""With no message `frappe.log_error` stores the traceback with each frame's variables.

		Whether Frappe includes them is its decision: from 16.55 `get_traceback(with_context=True)`
		leaves them out unless the site is in developer mode, and CI's fresh site is not. The test
		turns developer mode on so it exercises the scrubbing on every Frappe version.
		"""
		try:
			self._failed_filing()
		except RuntimeError:
			with (
				mock.patch.dict(frappe.local.conf, {"developer_mode": 1}),
				mock.patch.object(frappe, "log_error") as stored,
				CapturedLog() as captured,
			):
				oplog.log_error(title="Filing failed")

		message = stored.call_args.kwargs["message"]
		# The context an operator relied on is there ...
		self.assertIn("count = 3", message)
		self.assertIn("ticket = '3001002A0'", message)
		self.assertIn("RuntimeError: cannot file 3001002A0", message)
		self.assertIn("'status': 'Open'", message)
		# ... and nothing personal or secret with it.
		self.assertIn("submitter_name = [MASKED]", message)
		self.assertIn("description = [MASKED]", message)
		self.assertIn("password = ", message)
		for secret in (NAME, "my neighbour took my land", PASSWORD, PHONE, FAYDA, EMAIL):
			self.assertNotIn(secret, message)
		self.assertNoLeak(captured.text)

	def test_the_row_is_complete_when_frappe_leaves_the_variables_out(self):
		"""Frappe 16.55+ outside developer mode: no variables, but the same row otherwise."""
		real = frappe.get_traceback
		try:
			self._failed_filing()
		except RuntimeError:
			with (
				mock.patch.object(
					frappe, "get_traceback", side_effect=lambda with_context=False: real(False)
				),
				mock.patch.object(frappe, "log_error") as stored,
				CapturedLog() as captured,
			):
				frappe.local.request_id = "trace-abc-12345"
				oplog.log_error(title="Filing failed")

		message = stored.call_args.kwargs["message"]
		self.assertTrue(message.startswith("correlation_id: trace-abc-12345\n"))
		self.assertIn("RuntimeError: cannot file 3001002A0", message)
		self.assertNotIn("count = ", message)
		for secret in (NAME, "my neighbour took my land", PASSWORD, PHONE, FAYDA, EMAIL):
			self.assertNotIn(secret, message)
		(line,) = captured.named("error")
		self.assertEqual(line["summary"], "RuntimeError: cannot file 3001002A0")
		self.assertNoLeak(captured.text)

	def test_with_no_message_the_traceback_is_asked_for_with_its_variables(self):
		with (
			mock.patch.object(frappe, "get_traceback", return_value="Traceback\nValueError: x") as tb,
			mock.patch.object(frappe, "log_error"),
			CapturedLog(),
		):
			oplog.log_error(title="t")
		self.assertIn(mock.call(with_context=True), tb.call_args_list)

	def test_an_explicit_message_is_scrubbed_too(self):
		with mock.patch.object(frappe, "log_error") as stored, CapturedLog() as captured:
			oplog.log_error(title="t", message=f"user {EMAIL} token={JWT}", defer_insert=True)
		self.assertNotIn(EMAIL, stored.call_args.kwargs["message"])
		self.assertTrue(stored.call_args.kwargs["defer_insert"])
		self.assertNoLeak(captured.text)

	def test_a_failing_error_log_still_writes_the_line(self):
		# It is called from `except` blocks: a failing Error Log insert must not replace the
		# error being handled, so it is noted on the line instead of raised.
		with (
			mock.patch.object(frappe, "log_error", side_effect=RuntimeError("db down")),
			CapturedLog() as captured,
		):
			oplog.log_error(title="t", message="m")
		(line,) = captured.named("error")
		self.assertTrue(line["error_log_failed"])

	def test_api_errors_use_the_correlation_id_set_before_authentication(self):
		from oan_auth_service.api.utils import handle_api_errors

		@handle_api_errors
		def boom():
			raise ValueError(f"cannot find {EMAIL}")

		make_test_request("/api/v1/auth/me", headers={"X-Request-Id": "trace-abc-12345"})
		rl.begin()
		with mock.patch.object(frappe, "log_error"):
			envelope = boom()
		self.assertEqual(envelope["request_id"], "trace-abc-12345")


class TestLoggerConfiguration(FrappeTestCase):
	def _fresh_logger(self):
		"""Forget the configured logger, and put everything back afterwards."""
		key = oplog._LOGGER_KEY
		logger = logging.getLogger(key)
		saved = (
			list(logger.handlers),
			logger.level,
			logger.__dict__.get("_oan_configured"),
			frappe.log_level,
		)
		saved_registry = frappe.loggers.pop(key, None)
		for handler in saved[0]:
			logger.removeHandler(handler)
		logger._oan_configured = False

		def restore():
			for handler in list(logger.handlers):
				logger.removeHandler(handler)
				handler.close()
			for handler in saved[0]:
				logger.addHandler(handler)
			logger.setLevel(saved[1])
			logger._oan_configured = saved[2]
			frappe.log_level = saved[3]
			if saved_registry is not None:
				frappe.loggers[key] = saved_registry
			else:
				frappe.loggers.pop(key, None)

		self.addCleanup(restore)
		return logger

	def test_it_writes_json_lines_at_info_when_frappe_has_no_level_set(self):
		logger = self._fresh_logger()
		frappe.log_level = None
		fresh = oplog.get_logger()
		self.assertIs(fresh, logger)
		# Frappe would otherwise leave a production bench at ERROR and drop every INFO event.
		self.assertEqual(fresh.level, logging.INFO)
		self.assertTrue(fresh.handlers)
		for handler in fresh.handlers:
			self.assertIsInstance(handler.formatter, oplog.JsonFormatter)
		# Asking again does not stack a second set of handlers.
		count = len(fresh.handlers)
		self.assertEqual(len(oplog.get_logger().handlers), count)

	def test_a_level_an_operator_set_through_frappe_is_kept(self):
		self._fresh_logger()
		frappe.log_level = logging.WARNING
		self.assertEqual(oplog.get_logger().level, logging.WARNING)
		self.assertEqual(frappe.log_level, logging.WARNING)

	def test_rotation_is_frappes_own(self):
		"""No size or count setting of ours: the handler is whatever `frappe.logger` made."""
		self._fresh_logger()
		frappe.log_level = None
		for handler in oplog.get_logger().handlers:
			if hasattr(handler, "maxBytes"):
				self.assertEqual(handler.maxBytes, 100_000)
				self.assertEqual(handler.backupCount, 20)

	def test_two_threads_configure_one_set_of_handlers(self):
		import threading

		logger = self._fresh_logger()
		frappe.log_level = None
		barrier = threading.Barrier(8)

		def configure():
			barrier.wait()
			oplog.get_logger()

		threads = [threading.Thread(target=configure) for _ in range(8)]
		for thread in threads:
			thread.start()
		for thread in threads:
			thread.join()
		# `allow_site=False` gives one handler per logger.
		self.assertEqual(len(logger.handlers), 1)

	def test_a_line_is_one_json_object(self):
		formatter = oplog.JsonFormatter()
		record = logging.LogRecord("x", logging.INFO, __file__, 1, "evt", None, None)
		record.oan_fields = {"a": 1, "b": "\u00e9"}
		line = formatter.format(record)
		self.assertNotIn("\n", line)
		self.assertEqual(json.loads(line)["a"], 1)
		self.assertEqual(json.loads(line)["event"], "evt")

	def test_the_slow_threshold_defaults_and_survives_a_bad_value(self):
		request = make_test_request("/api/v1/auth/me")
		for value, slow in ((None, False), ("soon", False), (-1, False), (0, False), (1, True)):
			with self.subTest(value=value), CapturedLog() as captured:
				self._reset()
				conf = {} if value is None else {"oan_slow_request_ms": value}
				with mock.patch.dict(frappe.local.conf, conf):
					rl.begin()
					frappe.local.oan_request_started -= 0.05
					rl.end(Response("{}", status=200, content_type="application/json"), request)
				line = captured.named("http.request")[0]
				self.assertEqual(bool(line.get("slow")), slow)

	@staticmethod
	def _reset():
		frappe.local.request_id = None
		frappe.local.oan_request_started = None


class TestScope(FrappeTestCase):
	def test_the_shared_namespace_and_registered_namespaces_are_in_scope(self):
		from oan_auth_service.api.middleware import register_namespace

		register_namespace("/api/method/oan_test_app.", [])
		for path in (
			"/api/v1/widgets",
			"/api/v1/auth/login",
			"/api/method/oan_test_app.api.thing",
		):
			with self.subTest(path=path):
				self.assertTrue(rl.in_scope(path))

	def test_everything_else_is_left_alone(self):
		for path in (
			"/app/home",
			"/assets/frappe/js/x.js",
			"/api/method/frappe.client.get_list",
			"/api/method/ping",
			"/api/resource/User",
		):
			with self.subTest(path=path):
				self.assertFalse(rl.in_scope(path))

	def test_a_registered_frappe_method_is_still_left_alone(self):
		"""An app registers the socket server's user lookup so a bearer token resolves; it is not
		an API call worth a line."""
		from oan_auth_service.api.middleware import register_namespace

		register_namespace("/api/method/frappe.realtime.get_user_info", [])
		self.assertFalse(rl.in_scope("/api/method/frappe.realtime.get_user_info"))
