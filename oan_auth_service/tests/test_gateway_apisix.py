"""Tests for the realtime routes built by gateway_apisix.socket_service."""

import unittest
from typing import ClassVar

from oan_auth_service import gateway_apisix as gw


def build():
	return gw.socket_service(
		app="demo",
		upstream=gw.upstream(host_env="X", host_default="node", port_env="Y", port_default=9000),
		session_cookies=[
			{"name": "local", "cookie": "auth_token", "require": ["last_activity"]},
			{"name": "iam", "cookie": "X-Access-Token"},
		],
		browser_origins=["https://app.example.org"],
		frappe_web_origin="http://site.example:8000",
		site_name="site.example",
		limit={"rules": []},
	)


class TestSocketService(unittest.TestCase):
	def setUp(self):
		self.routes = {r["name"].rsplit("-", 1)[-1]: r for r in build()["routes"]}

	def test_origin_and_host_are_fixed_not_client_values(self):
		for route in self.routes.values():
			rewrite = route["plugins"]["proxy-rewrite"]
			self.assertEqual(rewrite["headers"]["set"]["Origin"], "http://site.example:8000")
			self.assertEqual(rewrite["host"], "site.example")
			self.assertIn("Cookie", rewrite["headers"]["remove"])

	def test_cookie_routes_require_an_allowed_origin(self):
		for name in ("local", "iam"):
			self.assertIn(["http_origin", "in", ["https://app.example.org"]], self.routes[name]["vars"])

	def test_cookie_becomes_bearer_header(self):
		auth = {
			n: r["plugins"]["proxy-rewrite"]["headers"]["set"].get("Authorization")
			for n, r in self.routes.items()
		}
		self.assertIsNone(auth["bearer"])
		self.assertEqual(auth["local"], "Bearer $cookie_auth_token")
		# `-` needs the braced form, which ADC does not expand.
		self.assertEqual(auth["iam"], "Bearer ${cookie_X-Access-Token}")

	def test_earlier_cookie_wins(self):
		self.assertIn(["cookie_last_activity", "~~", ".+"], self.routes["local"]["vars"])
		self.assertIn(["cookie_auth_token", "!", "~~", ".+"], self.routes["iam"]["vars"])

	def test_header_beats_cookie(self):
		self.assertGreater(self.routes["bearer"]["priority"], self.routes["local"]["priority"])


class TestLimitCount(unittest.TestCase):
	TIER: ClassVar[dict] = {"limit_by": "consumer", "minute": 5, "hour": 30}

	def key(self, **kw):
		return gw.limit_count(self.TIER, **kw)["rules"][0]["key"]

	def test_keys_by_address_without_gateway_jwt(self):
		self.assertEqual(self.key(gateway_jwt=False), "$remote_addr:min")

	def test_keys_by_token_only_on_bearer_routes(self):
		self.assertEqual(self.key(gateway_jwt=True, auth="bearer"), "$http_authorization:min")
		self.assertEqual(self.key(gateway_jwt=True, auth="public"), "$remote_addr:min")

	def test_fails_closed_only_when_tier_says_so(self):
		self.assertTrue(gw.limit_count(self.TIER, False)["allow_degradation"])
		self.assertFalse(gw.limit_count({**self.TIER, "fail_open": False}, False)["allow_degradation"])


class TestHelmExternal(unittest.TestCase):
	def test_helm_external_renders_multinode_and_healthcheck(self):
		template = (
			"  backends:\n"
			"  - serviceName: demo-svc\n"
			"    servicePort: 8080\n"
			"  externalNodes:\n"
			"  - type: Domain\n"
			"    name: demo.example.com\n"
			"    port: 8080\n"
		)
		backends = [("demo-svc", "8080", "demo.example.com")]
		values = {
			"demo.example.com": ".Values.demo.externalHosts",
			"8080": "Values.demo.port",
		}
		rendered = gw.helm_external(template, backends, values)
		self.assertIn("{{- if .Values.demo.externalHosts }}", rendered)
		self.assertIn("{{- range .Values.demo.externalHosts }}", rendered)
		self.assertIn("port: {{ $Values.demo.port }}", rendered)
		self.assertIn("{{- with .Values.demo.healthCheck }}", rendered)
		self.assertIn("{{- toYaml . | nindent 4 }}", rendered)
