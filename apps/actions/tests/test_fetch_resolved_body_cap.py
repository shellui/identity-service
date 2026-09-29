"""fetch_resolved_endpoint must enforce response body size while reading in chunks."""

from __future__ import annotations

import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import TestCase
from unittest.mock import patch

from apps.actions.ssrf import ResolvedWebhookEndpoint, SSRFError
from apps.actions.webhook_transport import fetch_resolved_endpoint
from apps.authapi.tests.oauth_test_crypto import OAuthMockHttpsServer


class FetchResolvedBodyCapTests(TestCase):
    def test_oversized_body_raises_before_full_read(self) -> None:
        hostname = 'body-cap.test'
        oversized = b'x' * (512 * 1024 + 1)

        def _handler(http: BaseHTTPRequestHandler) -> None:
            http.send_response(200)
            http.send_header('Content-Type', 'application/octet-stream')
            http.end_headers()
            http.wfile.write(oversized)

        server = OAuthMockHttpsServer.start(
            hostnames=[hostname],
            routes={(hostname, 'GET', '/big'): _handler},
        )
        endpoint = ResolvedWebhookEndpoint(
            original_url=f'https://{hostname}:{server.port}/big',
            scheme='https',
            connect_host='127.0.0.1',
            port=server.port,
            host_header=f'{hostname}:{server.port}',
            path='/big',
        )
        try:
            with patch(
                'apps.actions.webhook_transport.ssl.create_default_context',
                return_value=server.ssl_client_context(),
            ):
                with self.assertRaises(SSRFError):
                    fetch_resolved_endpoint(endpoint, max_bytes=512 * 1024)
        finally:
            server.shutdown()
