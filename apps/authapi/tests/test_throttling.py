from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from apps.authapi.middleware import AdminLoginRateLimitMiddleware
from apps.authapi.throttling import check_rate_limit


class RateLimitTests(TestCase):
    def setUp(self):
        cache.clear()
        self.factory = RequestFactory()

    @override_settings(
        AUTH_RATE_LIMIT_ENABLED=True,
        AUTH_RATE_LIMITS={'oauth': {'limit': 2, 'window': 60}},
    )
    def test_check_rate_limit_allows_under_limit(self):
        request = self.factory.get('/api/v1/authorize')
        self.assertIsNone(check_rate_limit(request, scope='oauth', identity='1.2.3.4'))
        self.assertIsNone(check_rate_limit(request, scope='oauth', identity='1.2.3.4'))

    @override_settings(
        AUTH_RATE_LIMIT_ENABLED=True,
        AUTH_RATE_LIMITS={'oauth': {'limit': 2, 'window': 60}},
    )
    def test_check_rate_limit_blocks_over_limit(self):
        request = self.factory.get('/api/v1/authorize')
        check_rate_limit(request, scope='oauth', identity='1.2.3.4')
        check_rate_limit(request, scope='oauth', identity='1.2.3.4')
        limited = check_rate_limit(request, scope='oauth', identity='1.2.3.4')
        self.assertIsNotNone(limited)
        self.assertEqual(limited.status_code, 429)

    @override_settings(
        AUTH_RATE_LIMIT_ENABLED=True,
        AUTH_RATE_LIMITS={'admin_login': {'limit': 1, 'window': 300}},
    )
    def test_admin_login_middleware_blocks_repeated_posts(self):
        middleware = AdminLoginRateLimitMiddleware(lambda request: HttpResponse('ok'))

        first = self.factory.post('/admin/login/', {'username': 'a', 'password': 'b'})
        response = middleware(first)
        self.assertNotEqual(response.status_code, 429)

        second = self.factory.post('/admin/login/', {'username': 'a', 'password': 'b'})
        response = middleware(second)
        self.assertEqual(response.status_code, 429)
