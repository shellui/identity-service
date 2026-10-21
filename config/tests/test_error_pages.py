import json
from html import unescape

from django.test import Client, RequestFactory, SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from config import errors

BROWSER_ACCEPT = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'


class ApiErrorsStayJsonTests(TestCase):
    def test_api_error_is_json_when_browser_asks_for_html(self):
        response = self.client.get(reverse('shellui-user'), HTTP_ACCEPT=BROWSER_ACCEPT)
        self.assertIn(response.status_code, (401, 403))
        self.assertTrue(response['Content-Type'].startswith('application/json'))
        body = json.loads(response.content)
        self.assertIn('detail', body)
        self.assertNotIn(b'<html', response.content.lower())
        self.assertNotIn(b'Django REST framework', response.content)

    def test_api_error_json_body_unchanged_for_api_clients(self):
        html = self.client.get(reverse('shellui-user'), HTTP_ACCEPT=BROWSER_ACCEPT)
        api = self.client.get(reverse('shellui-user'), HTTP_ACCEPT='application/json')
        self.assertEqual(html.status_code, api.status_code)
        self.assertEqual(json.loads(html.content), json.loads(api.content))

    def test_unknown_api_url_returns_json_404(self):
        response = self.client.get('/api/v1/does-not-exist/', HTTP_ACCEPT=BROWSER_ACCEPT)
        self.assertEqual(response.status_code, 404)
        self.assertTrue(response['Content-Type'].startswith('application/json'))
        self.assertEqual(json.loads(response.content), {'error': 'Not found.', 'error_code': 'not_found'})


class BrowserErrorPageTests(TestCase):
    def test_unknown_page_returns_branded_html_404(self):
        response = self.client.get('/no-such-page/', HTTP_ACCEPT=BROWSER_ACCEPT)
        self.assertEqual(response.status_code, 404)
        self.assertTrue(response['Content-Type'].startswith('text/html'))
        content = unescape(response.content.decode())
        self.assertIn("This page doesn't exist", content)
        self.assertIn('href="/"', content)
        self.assertIn('css/site.css', content)
        self.assertNotIn('/no-such-page/', content)

    def test_404_page_in_french(self):
        response = self.client.get('/no-such-page/', HTTP_ACCEPT=BROWSER_ACCEPT, HTTP_ACCEPT_LANGUAGE='fr-CH,fr;q=0.9')
        self.assertEqual(response.status_code, 404)
        self.assertIn('lang="fr"', unescape(response.content.decode()))
        self.assertIn("Cette page n'existe pas", unescape(response.content.decode()))


class ServerErrorTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_500_page_renders_without_details(self):
        request = self.factory.get('/boom/?secret=abc')
        response = errors.server_error(request)
        self.assertEqual(response.status_code, 500)
        content = unescape(response.content.decode())
        self.assertIn('Something went wrong', content)
        for leaked in ('Traceback', 'secret', 'abc', '/boom/', 'Exception'):
            self.assertNotIn(leaked, content)

    def test_500_under_api_is_json(self):
        response = errors.server_error(self.factory.get('/api/v1/boom'))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(json.loads(response.content), {'error': 'Server error.', 'error_code': 'server_error'})

    def test_400_and_403_handlers(self):
        self.assertEqual(errors.bad_request(self.factory.get('/x')).status_code, 400)
        self.assertIn("You can't open this page", unescape(errors.permission_denied(self.factory.get('/x')).content.decode()))

    def test_handlers_are_registered(self):
        from config import urls

        self.assertEqual(urls.handler404, 'config.errors.page_not_found')
        self.assertEqual(urls.handler500, 'config.errors.server_error')


class CsrfFailureTests(TestCase):
    def test_csrf_failure_renders_branded_page(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post('/', {'username': 'x'}, HTTP_ACCEPT=BROWSER_ACCEPT)
        self.assertEqual(response.status_code, 403)
        content = unescape(response.content.decode())
        self.assertIn('This form has expired', content)
        self.assertNotIn('CSRF verification failed', content)

    @override_settings(CSRF_FAILURE_VIEW='config.errors.csrf_failure')
    def test_csrf_failure_under_api_is_json(self):
        response = errors.csrf_failure(RequestFactory().post('/api/v1/x'), reason='CSRF cookie not set.')
        self.assertEqual(response.status_code, 403)
        body = json.loads(response.content)
        self.assertEqual(body['error_code'], 'csrf_failed')
        self.assertNotIn('cookie', body['error'].lower())
