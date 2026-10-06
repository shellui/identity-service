"""The gunicorn access log and app request logs never include query strings or the Referer."""

import re
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from django.conf import settings
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings

from config.request_context import RequestIdMiddleware, url_without_query

_ENTRYPOINT = Path(settings.BASE_DIR) / 'tools' / 'docker-entrypoint.sh'
_SECRET = 'S3cretMagicToken_abc123'


def _access_log_format() -> str:
    text = _ENTRYPOINT.read_text(encoding='utf-8')
    match = re.search(r"--access-logformat '([^']+)'", text)
    assert match, 'access log format not found in tools/docker-entrypoint.sh'
    return match.group(1)


class GunicornAccessLogFormatTests(SimpleTestCase):
    def test_format_has_no_full_request_line_query_or_referer(self):
        fmt = _access_log_format()
        for atom in ('%(r)s', '%(q)s', '%(f)s', '{referer}i', '{x-setup-token}i', '{authorization}i', '{cookie}i'):
            self.assertNotIn(atom, fmt.lower() if atom.startswith('{') else fmt)
        for atom in ('%(m)s', '%(U)s', '%(s)s', '%(M)s', '%({x-request-id}o)s'):
            self.assertIn(atom, fmt)

    def test_rendered_line_drops_query_string_and_referer(self):
        from gunicorn.config import Config
        from gunicorn.glogging import Logger

        fmt = _access_log_format()
        log = Logger(Config())
        environ = {
            'REQUEST_METHOD': 'GET',
            'RAW_URI': f'/api/v1/magic-link/verify?token={_SECRET}&company_id=1',
            'PATH_INFO': '/api/v1/magic-link/verify',
            'QUERY_STRING': f'token={_SECRET}&company_id=1',
            'SERVER_PROTOCOL': 'HTTP/1.1',
            'HTTP_REFERER': f'https://mail.example.com/read?token={_SECRET}',
            'HTTP_USER_AGENT': 'Mozilla/5.0',
            'REMOTE_ADDR': '203.0.113.9',
        }
        resp = SimpleNamespace(status='200 OK', sent=512, headers=[('X-Request-ID', 'req-abc')])
        req = SimpleNamespace(headers=[('REFERER', environ['HTTP_REFERER'])])
        atoms = log.atoms_wrapper_class(log.atoms(resp, req, environ, timedelta(milliseconds=42)))
        line = fmt % atoms
        self.assertNotIn(_SECRET, line)
        self.assertNotIn('?', line)
        self.assertNotIn('mail.example.com', line)
        self.assertIn('"GET /api/v1/magic-link/verify HTTP/1.1" 200 512', line)
        self.assertIn('"Mozilla/5.0"', line)
        self.assertIn('42ms req=req-abc', line)


class UrlWithoutQueryTests(SimpleTestCase):
    def test_strips_query_and_fragment(self):
        self.assertEqual(
            url_without_query(f'https://app.example.com/cb?shellui_auth_code={_SECRET}#x'),
            'https://app.example.com/cb',
        )
        self.assertEqual(url_without_query('/oauth/callback?code=a&state=b'), '/oauth/callback')
        self.assertEqual(url_without_query(None), '')
        self.assertEqual(url_without_query('/plain'), '/plain')


class SlowRequestLogTests(SimpleTestCase):
    @override_settings(SLOW_REQUEST_THRESHOLD_SECONDS=0.000001)
    def test_slow_request_warning_logs_path_without_query(self):
        middleware = RequestIdMiddleware(lambda request: HttpResponse('ok'))
        request = RequestFactory().get(
            f'/api/v1/magic-link/verify?token={_SECRET}&company_id=1',
            HTTP_REFERER=f'https://x.example.com/?token={_SECRET}',
        )
        with self.assertLogs('config.request', level='WARNING') as logs:
            middleware(request)
        output = '\n'.join(logs.output)
        self.assertIn('/api/v1/magic-link/verify', output)
        self.assertNotIn(_SECRET, output)
