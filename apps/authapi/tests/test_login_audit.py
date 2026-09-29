from django.test import RequestFactory, TestCase, override_settings

from apps.authapi.login_audit import client_ip_rate_limit_key, get_client_ip


class ClientIpTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_ignores_xff_without_trusted_proxy(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '203.0.113.10'
        request.META['HTTP_X_FORWARDED_FOR'] = '198.51.100.5, 203.0.113.1'
        self.assertEqual(get_client_ip(request), '203.0.113.10')

    @override_settings(TRUSTED_PROXY_IPS=('203.0.113.1', '203.0.113.99'))
    def test_uses_rightmost_untrusted_hop_from_trusted_proxy(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '203.0.113.1'
        request.META['HTTP_X_FORWARDED_FOR'] = '198.51.100.5, 203.0.113.99'
        self.assertEqual(get_client_ip(request), '198.51.100.5')

    @override_settings(TRUSTED_PROXY_IPS=('203.0.113.1', '203.0.113.99'))
    def test_ignores_spoofed_leftmost_xff_entry(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '203.0.113.1'
        request.META['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 198.51.100.5, 203.0.113.99'
        self.assertEqual(get_client_ip(request), '198.51.100.5')

    @override_settings(TRUSTED_PROXY_IPS=('10.0.0.0/8',))
    def test_trusted_proxy_cidr(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '10.1.2.3'
        request.META['HTTP_X_FORWARDED_FOR'] = '198.51.100.8'
        self.assertEqual(get_client_ip(request), '198.51.100.8')

    @override_settings(TRUSTED_PROXY_IPS=('203.0.113.1',))
    def test_single_hop_xff_when_peer_is_trusted(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '203.0.113.1'
        request.META['HTTP_X_FORWARDED_FOR'] = '198.51.100.8'
        self.assertEqual(get_client_ip(request), '198.51.100.8')

    @override_settings(TRUSTED_PROXY_IPS=('10.0.0.0/8',))
    def test_trusted_proxy_matches_ipv4_mapped_remote(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '::ffff:10.0.0.5'
        request.META['HTTP_X_FORWARDED_FOR'] = '198.51.100.9'
        self.assertEqual(get_client_ip(request), '198.51.100.9')

    @override_settings(TRUSTED_PROXY_IPS=('203.0.113.1',))
    def test_xff_strips_ipv4_port_and_bracketed_ipv6(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '203.0.113.1'
        request.META['HTTP_X_FORWARDED_FOR'] = (
            '9.9.9.9:4431, [2001:db8::1]:8080, 198.51.100.11, 203.0.113.1'
        )
        self.assertEqual(get_client_ip(request), '198.51.100.11')

    @override_settings(TRUSTED_PROXY_IPS=('203.0.113.1',))
    def test_xff_skips_invalid_hops(self):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '203.0.113.1'
        request.META['HTTP_X_FORWARDED_FOR'] = 'not-an-ip, 198.51.100.12, 203.0.113.1'
        self.assertEqual(get_client_ip(request), '198.51.100.12')

    def test_ipv6_rate_limit_key_buckets_by_slash_64(self):
        full = '2001:db8:abcd:1234:5678:9abc:def0:1111'
        other = '2001:db8:abcd:1234:ffff:ffff:ffff:ffff'
        self.assertEqual(client_ip_rate_limit_key(full), '2001:db8:abcd:1234::/64')
        self.assertEqual(client_ip_rate_limit_key(other), client_ip_rate_limit_key(full))

    def test_ipv4_rate_limit_key_unchanged(self):
        self.assertEqual(client_ip_rate_limit_key('198.51.100.5'), '198.51.100.5')
