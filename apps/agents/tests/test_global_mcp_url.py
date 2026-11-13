"""global_mcp_url from DASHBOARD_PUBLIC_URL (personal MCP status)."""

from __future__ import annotations

from django.test import SimpleTestCase, override_settings

from apps.agents.mcp_resources import global_mcp_url


class GlobalMcpUrlTests(SimpleTestCase):
    @override_settings(DASHBOARD_PUBLIC_URL='')
    def test_unset_returns_none(self):
        self.assertIsNone(global_mcp_url())

    @override_settings(DASHBOARD_PUBLIC_URL='https://app.shellui.com')
    def test_https_origin_appends_mcp(self):
        self.assertEqual(global_mcp_url(), 'https://app.shellui.com/mcp')

    @override_settings(DASHBOARD_PUBLIC_URL='https://app.shellui.com/')
    def test_trailing_slash_normalized(self):
        self.assertEqual(global_mcp_url(), 'https://app.shellui.com/mcp')

    @override_settings(DASHBOARD_PUBLIC_URL='http://127.0.0.1:8000')
    def test_loopback_http_allowed(self):
        self.assertEqual(global_mcp_url(), 'http://127.0.0.1:8000/mcp')

    @override_settings(DASHBOARD_PUBLIC_URL='http://evil.com')
    def test_non_loopback_http_rejected(self):
        self.assertIsNone(global_mcp_url())

    @override_settings(DASHBOARD_PUBLIC_URL='http://100.127.19.94:5174')
    def test_private_ip_http_allowed(self):
        self.assertEqual(global_mcp_url(), 'http://100.127.19.94:5174/mcp')

    @override_settings(DASHBOARD_PUBLIC_URL='https://app.shellui.com/nested')
    def test_path_with_segments_rejected(self):
        self.assertIsNone(global_mcp_url())
