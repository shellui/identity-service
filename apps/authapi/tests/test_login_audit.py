from django.test import RequestFactory, TestCase, override_settings

from apps.authapi.login_audit import get_client_ip


class ClientIpTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_ignores_xff_without_trusted_proxy(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '203.0.113.10'
        request.META['HTTP_X_FORWARDED_FOR'] = '198.51.100.5, 203.0.113.1'
        self.assertEqual(get_client_ip(request), '203.0.113.10')

    @override_settings(TRUSTED_PROXY_IPS=('203.0.113.1',))
    def test_uses_xff_first_hop_from_trusted_proxy(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '203.0.113.1'
        request.META['HTTP_X_FORWARDED_FOR'] = '198.51.100.5, 203.0.113.99'
        self.assertEqual(get_client_ip(request), '198.51.100.5')

    @override_settings(TRUSTED_PROXY_IPS=('10.0.0.0/8',))
    def test_trusted_proxy_cidr(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '10.1.2.3'
        request.META['HTTP_X_FORWARDED_FOR'] = '198.51.100.8'
        self.assertEqual(get_client_ip(request), '198.51.100.8')
