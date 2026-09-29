import threading

from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site
from django.test import RequestFactory, TestCase

from apps.authapi.oauth_request_context import oauth_allauth_request
from apps.authapi.social_account_adapter import ShellUISocialAccountAdapter


class OAuthCompanyContextTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.site = Site.objects.get_current()
        self.app_a = SocialApp.objects.create(
            provider='microsoft',
            name='ms-a',
            client_id='client-a',
            secret='secret-a',
            settings={'tenant': 'tenant-a'},
        )
        self.app_b = SocialApp.objects.create(
            provider='microsoft',
            name='ms-b',
            client_id='client-b',
            secret='secret-b',
            settings={'tenant': 'tenant-b'},
        )
        for app in (self.app_a, self.app_b):
            app.sites.add(self.site)
        self.adapter = ShellUISocialAccountAdapter()

    def test_get_app_isolated_per_thread(self):
        errors: list[str] = []
        barrier = threading.Barrier(2)

        def worker(app: SocialApp):
            try:
                request = self.factory.get('/')
                barrier.wait(timeout=5)
                with oauth_allauth_request(request, social_app=app):
                    resolved = self.adapter.get_app(request, 'microsoft', client_id=app.client_id)
                    if resolved.client_id != app.client_id:
                        errors.append(f'expected {app.client_id}, got {resolved.client_id}')
                    if str(resolved.settings.get('tenant')) != str(app.settings.get('tenant')):
                        errors.append('tenant mismatch')
            except Exception as exc:
                errors.append(str(exc))

        t1 = threading.Thread(target=worker, args=(self.app_a,))
        t2 = threading.Thread(target=worker, args=(self.app_b,))
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)
        self.assertEqual(errors, [])
