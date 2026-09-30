"""OAuth pinned HTTP must preserve TLS SNI and re-pin redirects (H1)."""

from __future__ import annotations

import json
from unittest import TestCase
from unittest.mock import patch
from apps.authapi.oauth_pinned_http import pinned_get_json
from apps.authapi.tests.oauth_ssrf_test_utils import pin_oauth_http_to_localhost
from apps.authapi.tests.oauth_test_crypto import OAuthMockHttpsServer, json_response_handler


class OAuthPinnedHttpTests(TestCase):
    def test_tls_uses_original_hostname_for_sni_while_connecting_to_pinned_ip(self) -> None:
        hostname = 'oauth-pin.test'
        seen: dict[str, str] = {}

        def _handler(http) -> None:
            seen['host'] = http.headers.get('Host', '')
            seen['path'] = http.path
            body = json.dumps({'ok': True}).encode()
            http.send_response(200)
            http.send_header('Content-Type', 'application/json')
            http.end_headers()
            http.wfile.write(body)

        server = OAuthMockHttpsServer.start(
            hostnames=[hostname],
            routes={(hostname, 'GET', '/discovery'): _handler},
        )
        url = f'https://{hostname}:{server.port}/discovery'
        try:
            with pin_oauth_http_to_localhost((hostname, server.port)):
                with patch(
                    'apps.actions.webhook_transport.ssl.create_default_context',
                    return_value=server.ssl_client_context(),
                ):
                    data = pinned_get_json(url)
            self.assertEqual(data, {'ok': True})
            self.assertEqual(seen['host'], f'{hostname}:{server.port}')
        finally:
            server.shutdown()

    def test_redirect_re_resolves_and_repins(self) -> None:
        hostname_a = 'oauth-a.test'
        hostname_b = 'oauth-b.test'

        def _redirect(http) -> None:
            target = f'https://{hostname_b}:{server_b.port}/final'
            http.send_response(302)
            http.send_header('Location', target)
            http.end_headers()

        hits: list[str] = []

        def _final(http) -> None:
            hits.append('b')
            body = json.dumps({'stage': 'b'}).encode()
            http.send_response(200)
            http.send_header('Content-Type', 'application/json')
            http.end_headers()
            http.wfile.write(body)

        server_b = OAuthMockHttpsServer.start(
            hostnames=[hostname_b],
            routes={(hostname_b, 'GET', '/final'): _final},
        )

        def _start(http) -> None:
            hits.append('a')
            _redirect(http)

        server_a = OAuthMockHttpsServer.start(
            hostnames=[hostname_a],
            routes={(hostname_a, 'GET', '/start'): _start},
        )
        start_url = f'https://{hostname_a}:{server_a.port}/start'

        try:
            with pin_oauth_http_to_localhost(
                (hostname_a, server_a.port),
                (hostname_b, server_b.port),
            ):
                ctx = server_a.ssl_client_context()
                ctx.load_verify_locations(cadata=(server_a.cert_pem + server_b.cert_pem).decode('ascii'))
                with patch(
                    'apps.actions.webhook_transport.ssl.create_default_context',
                    return_value=ctx,
                ):
                    data = pinned_get_json(start_url)
            self.assertEqual(data, {'stage': 'b'})
            self.assertEqual(hits, ['a', 'b'])
        finally:
            server_a.shutdown()
            server_b.shutdown()
