"""Per-company MCP OAuth: identity sign-in page, consent, and anti-phishing rules."""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlencode, urlsplit

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings

from apps.agents.mcp_resources import resolve_mcp_resource, resource_company_id
from apps.agents.mcp_signin import AUTHORIZE_SESSION_KEY, safe_authorize_path, signin_complete_url
from apps.agents.models import Agent, AgentRefreshSession, McpCallLog, McpOAuthClient
from apps.agents.oauth_redirect import validate_mcp_redirect_uri
from apps.agents.tokens import encode_access_token, refresh_agent_access
from apps.authapi.client_pkce import s256_challenge
from apps.companies.access import set_company_access
from apps.companies.models import Company

User = get_user_model()

SETTINGS = dict(
    JWT_ISSUER='https://identity.test',
    JWT_AUDIENCE='shellui-test',
    AI_SERVICE_URL='https://ai.test',
    MCP_DYNAMIC_CLIENT_REGISTRATION=True,
    AUTH_RATE_LIMIT_ENABLED=False,
)
REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect'
INSPECTOR = 'http://127.0.0.1:6274/oauth/callback'


class RedirectUriRuleTests(TestCase):
    def test_allows_https_and_loopback_http(self):
        for uri in (REDIRECT, INSPECTOR, 'http://localhost:3000/cb', 'http://[::1]:8080/cb'):
            self.assertEqual(validate_mcp_redirect_uri(None, uri), (uri, None), uri)

    def test_rejects_other_schemes_fragments_and_userinfo(self):
        for uri in (
            'javascript:alert(1)',
            'data:text/html,hi',
            'cursor://anysphere/cb',
            'ftp://example.com/cb',
            'http://example.com/cb',
            'https://example.com/cb#frag',
            'https://user:pw@example.com/cb',
            'https://evil.com@example.com/cb',
            '/relative/cb',
            '//example.com/cb',
            'https://example.com/a b',
            '',
        ):
            url, err = validate_mcp_redirect_uri(None, uri)
            self.assertIsNone(url, uri)
            self.assertTrue(err, uri)


class SafeNextTests(TestCase):
    def test_only_relative_authorize_paths(self):
        self.assertEqual(safe_authorize_path('/oauth/mcp/authorize?a=1'), '/oauth/mcp/authorize?a=1')
        for bad in (
            'https://evil.com/oauth/mcp/authorize?a=1',
            '//evil.com/oauth/mcp/authorize?a=1',
            '/oauth/mcp/authorize',
            '/admin/?a=1',
            '/oauth/mcp/authorize?a=1\r\nX: y',
            '/oauth/mcp/authorize?a=1#x',
            '/oauth/mcp/authorize/../x?a=1',
        ):
            self.assertIsNone(safe_authorize_path(bad), bad)


@override_settings(**SETTINGS)
class CompanyResourceTests(TestCase):
    def test_per_company_gateway_resource_resolves(self):
        self.assertEqual(resolve_mcp_resource('https://ai.test/c/7/mcp'), ('https://ai.test/c/7/mcp', 'ai'))
        self.assertEqual(resource_company_id('https://ai.test/c/7/mcp'), 7)

    def test_rejects_foreign_origin_and_bad_ids(self):
        for raw in (
            'https://evil.test/c/7/mcp',
            'https://ai.test/c/0/mcp',
            'https://ai.test/c/07/mcp',
            'https://ai.test/c/x/mcp',
            'https://ai.test/c/7/mcp?x=1',
            'https://ai.test/c/7/mcp#x',
            'http://ai.test/c/7/mcp',
        ):
            url, _code = resolve_mcp_resource(raw)
            self.assertIsNone(url, raw)


@override_settings(**SETTINGS)
class CompanySigninFlowTests(TestCase):
    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Acme', slug='acme-signin', enable_magic_link=True)
        self.other = Company.objects.create(name='Other', slug='other-signin')
        self.user = User.objects.create_user(username='ella', email='ella@acme.com', password='unused')
        set_company_access(self.company, self.user, enabled=True)
        self.client_row = McpOAuthClient.objects.create(
            client_id='client-1', client_name='Totally Claude', redirect_uris=[REDIRECT, INSPECTOR]
        )
        self.verifier = 'v' * 43
        self.challenge = s256_challenge(self.verifier)
        self.resource = f'https://ai.test/c/{self.company.id}/mcp'

    def _query(self, **overrides):
        params = {
            'response_type': 'code',
            'client_id': 'client-1',
            'redirect_uri': REDIRECT,
            'code_challenge': self.challenge,
            'code_challenge_method': 'S256',
            'resource': self.resource,
            'state': 'st4te',
        }
        params.update(overrides)
        return '/oauth/mcp/authorize?' + urlencode(params)

    def _assert_error_page(self, response, code, status=400):
        self.assertEqual(response.status_code, status)
        self.assertNotIn('Location', response)
        self.assertContains(response, f'data-error-code="{code}"', status_code=status)
        self.assertEqual(response['X-Frame-Options'], 'DENY')
        self.assertIn("frame-ancestors 'none'", response['Content-Security-Policy'])

    def test_invalid_client_redirect_and_resource_never_redirect(self):
        self._assert_error_page(self.client.get(self._query(client_id='nope')), 'invalid_client')
        self._assert_error_page(
            self.client.get(self._query(redirect_uri='https://evil.com/cb')), 'invalid_redirect_uri'
        )
        self._assert_error_page(
            self.client.get(self._query(redirect_uri=REDIRECT + '/extra')), 'invalid_redirect_uri'
        )
        self._assert_error_page(
            self.client.get(self._query(resource='https://evil.test/c/1/mcp')), 'invalid_resource'
        )
        self._assert_error_page(self.client.get(self._query(resource='https://ai.test/mcp')), 'company_required')
        self._assert_error_page(self.client.get(self._query(resource='')), 'company_required')

    def test_unknown_company_is_404_only_after_signin(self):
        self.client.force_login(self.user)
        self._assert_error_page(
            self.client.get(self._query(resource='https://ai.test/c/999999/mcp')), 'unknown_company', 404
        )

    def test_signed_out_goes_to_identity_signin_with_anti_phishing_info(self):
        response = self.client.get(self._query())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/oauth/mcp/signin')
        page = self.client.get('/oauth/mcp/signin')
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page['X-Frame-Options'], 'DENY')
        self.assertIn("frame-ancestors 'none'", page['Content-Security-Policy'])
        body = page.content.decode()
        self.assertIn('Totally Claude wants to use MCP for your company.', body)
        self.assertNotIn('Acme', body)
        self.assertIn('Access requested', body)
        self.assertIn('identity.test', body)
        self.assertIn('Only continue if you started this from Totally Claude.', body)
        self.assertIn('Cancel', body)
        self.assertIn('name="email"', body)
        self.assertIn('csrfmiddlewaretoken', body)
        self.assertNotIn('/admin/login', body)

    def test_signin_page_in_french(self):
        self.client.get(self._query())
        page = self.client.get('/oauth/mcp/signin', HTTP_ACCEPT_LANGUAGE='fr')
        self.assertContains(page, 'veut utiliser MCP pour votre entreprise')
        self.assertNotContains(page, 'Acme')

    def test_signin_page_without_saved_request_is_an_error(self):
        self._assert_error_page(self.client.get('/oauth/mcp/signin'), 'invalid_request')

    def test_signin_post_requires_csrf(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.get(self._query())
        response = csrf_client.post('/oauth/mcp/signin', {'email': 'ella@acme.com'})
        self.assertEqual(response.status_code, 403)

    @staticmethod
    def _csrf_from_page(response) -> str:
        match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', response.content.decode())
        assert match, 'csrf token missing from page'
        return match.group(1)

    def test_signin_post_https_after_authorize_redirect_accepts_same_origin_referer(self):
        """MCP Inspector: authorize -> sign-in GET -> sign-in POST (HTTPS, same-origin Referer)."""
        from unittest import mock

        client = Client(enforce_csrf_checks=True)
        client.get(self._query(), secure=True)
        page = client.get('/oauth/mcp/signin', secure=True)
        self.assertEqual(page['Referrer-Policy'], 'same-origin')
        self.assertNotIn('name="referrer"', page.content.decode())
        token = self._csrf_from_page(page)
        referer = 'https://testserver/oauth/mcp/signin'
        with mock.patch('apps.authapi.magic_link_views.deliver_magic_link_email'):
            ok = client.post(
                '/oauth/mcp/signin',
                {'email': 'ella@acme.com', 'csrfmiddlewaretoken': token},
                secure=True,
                HTTP_REFERER=referer,
            )
        self.assertEqual(ok.status_code, 200)
        rejected = client.post(
            '/oauth/mcp/signin',
            {'email': 'ella@acme.com', 'csrfmiddlewaretoken': token},
            secure=True,
            HTTP_ORIGIN='null',
            HTTP_REFERER=referer,
        )
        self.assertEqual(rejected.status_code, 403)

    def test_consent_post_https_accepts_same_origin_referer_rejects_null_origin(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        page = client.get(self._query(), secure=True)
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page['Referrer-Policy'], 'same-origin')
        token = self._csrf_from_page(page)
        referer = f'https://testserver{self._query()}'
        approved = client.post(
            self._query(),
            {**self._form(), 'decision': 'approve', 'csrfmiddlewaretoken': token},
            secure=True,
            HTTP_REFERER=referer,
        )
        self.assertEqual(approved.status_code, 302)
        client.force_login(self.user)
        page2 = client.get(self._query(), secure=True)
        token2 = self._csrf_from_page(page2)
        rejected = client.post(
            self._query(),
            {**self._form(), 'decision': 'approve', 'csrfmiddlewaretoken': token2},
            secure=True,
            HTTP_ORIGIN='null',
            HTTP_REFERER=referer,
        )
        self.assertEqual(rejected.status_code, 403)

    def test_magic_link_disabled_company_looks_the_same_and_sends_nothing(self):
        from unittest import mock

        self.company.enable_magic_link = False
        self.company.save(update_fields=['enable_magic_link'])
        self.client.get(self._query())
        page = self.client.get('/oauth/mcp/signin')
        self.assertContains(page, 'name="email"')
        with mock.patch('apps.authapi.magic_link_views.deliver_magic_link_email') as deliver:
            response = self.client.post('/oauth/mcp/signin', {'email': 'ella@acme.com'})
        self.assertEqual(response.status_code, 200)
        deliver.assert_not_called()

    def _signin_pages(self, resource):
        from unittest import mock

        client = Client()
        first = client.get(self._query(resource=resource))
        page = client.get('/oauth/mcp/signin')
        with mock.patch('apps.authapi.magic_link_views.deliver_magic_link_email'):
            posted = client.post('/oauth/mcp/signin', {'email': 'someone@example.com'})
        strip = lambda r: re.sub(r'name="csrfmiddlewaretoken" value="[^"]+"', '', r.content.decode())  # noqa: E731
        return first, page, posted, strip

    def test_unknown_and_known_company_identical_before_signin(self):
        known = self._signin_pages(self.resource)
        unknown = self._signin_pages('https://ai.test/c/999999/mcp')
        strip = known[3]
        for a, b in zip(known[:3], unknown[:3]):
            self.assertEqual(a.status_code, b.status_code)
            self.assertEqual(a.get('Location'), b.get('Location'))
            self.assertEqual(strip(a), strip(b))
        self.assertEqual(known[0].status_code, 302)
        self.assertEqual(known[1].status_code, 200)
        for response in known[:3]:
            self.assertNotIn('Acme', response.content.decode())

    def test_signin_page_rate_limited_per_ip(self):
        self.client.get(self._query())
        with override_settings(AUTH_RATE_LIMIT_ENABLED=True):
            codes = [self.client.get('/oauth/mcp/signin').status_code for _ in range(32)]
        self.assertIn(429, codes)

    def test_magic_link_request_and_verify_signs_in_and_returns_to_consent(self):
        from unittest import mock

        authorize = self._query()
        self.client.get(authorize)
        sent = {}

        def fake_deliver(**kwargs):
            sent['token'] = kwargs['raw_token']
            sent['redirect_to'] = kwargs['row'].redirect_to

        with mock.patch('apps.authapi.magic_link_views.deliver_magic_link_email', side_effect=fake_deliver):
            response = self.client.post('/oauth/mcp/signin', {'email': 'ella@acme.com'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'a sign-in link is on its way')
        self.assertEqual(sent['redirect_to'], signin_complete_url())
        verify = self.client.post(
            '/api/v1/magic-link/verify',
            {'token': sent['token'], 'company_id': str(self.company.id)},
            HTTP_ACCEPT='text/html',
        )
        self.assertEqual(verify.status_code, 302)
        self.assertEqual(verify['Location'], authorize)
        consent = self.client.get(authorize)
        self.assertEqual(consent.status_code, 200)
        self.assertContains(consent, 'Allow Totally Claude?')
        self.assertContains(consent, 'Settings → MCP / AI agents')
        self.assertContains(consent, 'Allow')
        self.assertContains(consent, 'Deny')

    def test_staff_magic_link_sends_nothing(self):
        from unittest import mock

        User.objects.create_user(username='staffer', email='staff@acme.com', password='unused', is_staff=True)
        self.client.get(self._query())
        with mock.patch('apps.authapi.magic_link_views.deliver_magic_link_email') as deliver:
            response = self.client.post('/oauth/mcp/signin', {'email': 'staff@acme.com'})
        self.assertEqual(response.status_code, 200)
        deliver.assert_not_called()

    def test_magic_link_is_rate_limited(self):
        from unittest import mock

        self.client.get(self._query())
        with override_settings(AUTH_RATE_LIMIT_ENABLED=True), mock.patch(
            'apps.authapi.magic_link_views.deliver_magic_link_email'
        ):
            codes = [self.client.post('/oauth/mcp/signin', {'email': 'x@acme.com'}).status_code for _ in range(12)]
        self.assertIn(429, codes)

    def test_consent_needs_explicit_approval_and_logs_it(self):
        self.client.force_login(self.user)
        page = self.client.get(self._query())
        self.assertEqual(page.status_code, 200)
        self.assertEqual(Agent.objects.count(), 0)
        no_decision = self.client.post(self._query(), {**self._form()})
        self.assertEqual(no_decision.status_code, 400)
        self.assertEqual(Agent.objects.count(), 0)
        approved = self.client.post(self._query(), {**self._form(), 'decision': 'approve'})
        self.assertEqual(approved.status_code, 302)
        location = approved['Location']
        self.assertTrue(location.startswith(REDIRECT + '?'))
        params = parse_qs(urlsplit(location).query)
        self.assertEqual(params['state'], ['st4te'])
        agent = Agent.objects.get()
        self.assertEqual(agent.company_id, self.company.id)
        self.assertIn('ai', agent.services_allowed)
        log = McpCallLog.objects.get(agent=agent)
        self.assertEqual(log.tool, 'oauth.authorize.approved')
        self.assertEqual(log.arguments_redacted['redirect_host'], 'chatgpt.com')
        self.assertNotIn('code', json.dumps(log.arguments_redacted).replace('code_', ''))

        token = self.client.post(
            '/oauth/mcp/token',
            data=json.dumps(
                {
                    'grant_type': 'authorization_code',
                    'code': params['code'][0],
                    'redirect_uri': REDIRECT,
                    'client_id': 'client-1',
                    'code_verifier': self.verifier,
                    'resource': self.resource,
                }
            ),
            content_type='application/json',
        )
        self.assertEqual(token.status_code, 200, token.content)
        import jwt

        claims = jwt.decode(token.json()['access_token'], options={'verify_signature': False})
        self.assertEqual(claims['aud'], self.resource)
        self.assertEqual(claims['company_id'], self.company.id)
        self.assertEqual(claims['company_name'], self.company.name)
        refreshed = self.client.post(
            '/oauth/mcp/token',
            data=json.dumps(
                {'grant_type': 'refresh_token', 'refresh_token': token.json()['refresh_token'], 'resource': self.resource}
            ),
            content_type='application/json',
        )
        self.assertEqual(refreshed.status_code, 200)
        refreshed_claims = jwt.decode(refreshed.json()['access_token'], options={'verify_signature': False})
        self.assertEqual(refreshed_claims['company_name'], self.company.name)

    def test_deny_returns_access_denied(self):
        self.client.force_login(self.user)
        denied = self.client.post(self._query(), {**self._form(), 'decision': 'deny'})
        self.assertEqual(denied.status_code, 302)
        self.assertIn('error=access_denied', denied['Location'])
        self.assertEqual(Agent.objects.count(), 0)

    def test_consent_requires_csrf(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        response = csrf_client.post(self._query(), {**self._form(), 'decision': 'approve'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Agent.objects.count(), 0)

    def test_non_member_and_staff_refused(self):
        outsider = User.objects.create_user(username='out', email='out@x.com', password='unused')
        self.client.force_login(outsider)
        self.assertEqual(self.client.get(self._query()).status_code, 403)
        staff = User.objects.create_user(username='st', email='st@acme.com', password='unused', is_staff=True)
        set_company_access(self.company, staff, enabled=True)
        self.client.force_login(staff)
        self.assertEqual(self.client.get(self._query()).status_code, 403)

    def test_token_for_other_company_resource_refused(self):
        agent = Agent.objects.create(company=self.company, name='a', created_by=self.user, services_allowed=['ai'])
        with self.assertRaises(ValueError):
            encode_access_token(agent, resource=f'https://ai.test/c/{self.other.id}/mcp')

    def test_refresh_bound_to_other_company_refused(self):
        from rest_framework_simplejwt.tokens import RefreshToken

        agent = Agent.objects.create(company=self.company, name='a', created_by=self.user, services_allowed=['ai'])
        other_resource = f'https://ai.test/c/{self.other.id}/mcp'
        refresh = RefreshToken()
        refresh['agent_id'] = str(agent.id)
        refresh['resource'] = other_resource
        AgentRefreshSession.objects.create(
            agent=agent, jti=str(refresh['jti']), resource=other_resource, expires_at=agent.created_at.replace(year=2099)
        )
        self.assertIsNone(refresh_agent_access(str(refresh), resource=other_resource))

    def _form(self):
        return {
            'response_type': 'code',
            'client_id': 'client-1',
            'redirect_uri': REDIRECT,
            'code_challenge': self.challenge,
            'code_challenge_method': 'S256',
            'resource': self.resource,
            'state': 'st4te',
            'services': ['identity', 'storage'],
        }


@override_settings(**SETTINGS)
class RegistrationRuleTests(TestCase):
    def setUp(self):
        cache.clear()

    def _register(self, uris):
        return self.client.post(
            '/oauth/mcp/register',
            data=json.dumps({'redirect_uris': uris, 'client_name': 'Inspector'}),
            content_type='application/json',
        )

    def test_rejects_bad_redirect_uris(self):
        for uri in ('javascript:alert(1)', 'https://x.com/cb#f', 'http://x.com/cb', 'cursor://x/cb'):
            self.assertEqual(self._register([uri]).status_code, 400, uri)
        self.assertEqual(self._register([INSPECTOR]).status_code, 201)

    def test_registration_is_rate_limited(self):
        with override_settings(AUTH_RATE_LIMIT_ENABLED=True):
            codes = [self._register([INSPECTOR]).status_code for _ in range(12)]
        self.assertEqual(codes[:10], [201] * 10)
        self.assertEqual(codes[10], 429)

    def test_rejects_non_object_body(self):
        response = self.client.post('/oauth/mcp/register', data='[]', content_type='application/json')
        self.assertEqual(response.status_code, 400)


@override_settings(**SETTINGS)
class ProviderFinishTests(TestCase):
    """OAuth/SSO providers land on the MCP sign-in URL and reuse the same finish step."""

    def test_finalize_with_mcp_landing_starts_session_and_returns_to_authorize(self):
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.test import RequestFactory

        from apps.agents.mcp_signin import remember_authorize
        from apps.authapi.views import _finalize_shellui_oauth_login

        company = Company.objects.create(name='Acme', slug='acme-provider')
        user = User.objects.create_user(username='p', email='p@acme.com', password='unused')
        set_company_access(company, user, enabled=True)
        McpOAuthClient.objects.create(client_id='c2', client_name='Grok', redirect_uris=[REDIRECT])
        path = '/oauth/mcp/authorize?' + urlencode(
            {
                'response_type': 'code',
                'client_id': 'c2',
                'redirect_uri': REDIRECT,
                'code_challenge': s256_challenge('w' * 43),
                'code_challenge_method': 'S256',
                'resource': f'https://ai.test/c/{company.id}/mcp',
            }
        )
        request = RequestFactory().get('/oauth/callback')
        SessionMiddleware(lambda r: None).process_request(request)
        remember_authorize(request, path, company.id)
        response = _finalize_shellui_oauth_login(
            request, user=user, company=company, provider='google', redirect_to=signin_complete_url(), avatar_url=None
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], path)
        self.assertEqual(str(request.session.get('_auth_user_id')), str(user.pk))
        self.assertEqual(request.session.get(AUTHORIZE_SESSION_KEY), path)

    def test_signin_landing_is_on_every_company_allowlist(self):
        from django.test import RequestFactory

        from apps.companies.redirect_allowlist import redirect_url_allowed_for_company

        company = Company.objects.create(name='Acme', slug='acme-allow')
        self.assertTrue(redirect_url_allowed_for_company(company, signin_complete_url(), RequestFactory().get('/')))
        self.assertFalse(
            redirect_url_allowed_for_company(company, 'https://identity.test/oauth/mcp/signin/other', RequestFactory().get('/'))
        )
