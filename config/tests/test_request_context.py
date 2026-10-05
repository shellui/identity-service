from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings

from config.request_context import RequestIdMiddleware, request_id_var


class RequestIdMiddlewareTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_generates_request_id_and_returns_header(self):
        middleware = RequestIdMiddleware(lambda request: HttpResponse('ok'))
        response = middleware(self.factory.get('/api/v1/settings'))
        self.assertRegex(response['X-Request-ID'], r'^[0-9a-f]{32}$')

    def test_honors_inbound_request_id(self):
        captured = {}

        def get_response(request):
            captured['var'] = request_id_var.get()
            captured['attr'] = request.request_id
            return HttpResponse('ok')

        middleware = RequestIdMiddleware(get_response)
        request = self.factory.get('/api/v1/settings', HTTP_X_REQUEST_ID='from-proxy-123')
        response = middleware(request)
        self.assertEqual(response['X-Request-ID'], 'from-proxy-123')
        self.assertEqual(captured, {'var': 'from-proxy-123', 'attr': 'from-proxy-123'})

    def test_replaces_unsafe_inbound_request_id(self):
        middleware = RequestIdMiddleware(lambda request: HttpResponse('ok'))
        request = self.factory.get('/', HTTP_X_REQUEST_ID='bad id with spaces')
        response = middleware(request)
        self.assertNotEqual(response['X-Request-ID'], 'bad id with spaces')
        self.assertRegex(response['X-Request-ID'], r'^[0-9a-f]{32}$')

    def test_resets_context_after_request(self):
        middleware = RequestIdMiddleware(lambda request: HttpResponse('ok'))
        middleware(self.factory.get('/', HTTP_X_REQUEST_ID='abc'))
        self.assertEqual(request_id_var.get(), '-')

    def test_request_id_in_log_records(self):
        import logging

        from config.request_context import RequestIdFilter

        records = []

        class _Collect(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = _Collect()
        handler.addFilter(RequestIdFilter())
        test_logger = logging.getLogger('config.tests.request_id')
        test_logger.addHandler(handler)
        test_logger.propagate = False
        try:

            def get_response(request):
                test_logger.warning('inside request')
                return HttpResponse('ok')

            RequestIdMiddleware(get_response)(self.factory.get('/', HTTP_X_REQUEST_ID='trace-42'))
        finally:
            test_logger.removeHandler(handler)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].request_id, 'trace-42')

    def test_filter_reads_request_id_from_django_request_record(self):
        import logging

        from config.request_context import RequestIdFilter

        request = self.factory.get('/')
        request.request_id = 'from-record'
        record = logging.LogRecord('django.request', logging.WARNING, __file__, 1, 'Forbidden', None, None)
        record.request = request
        RequestIdFilter().filter(record)
        self.assertEqual(record.request_id, 'from-record')

    def test_health_live_returns_request_id(self):
        response = self.client.get('/health/live', HTTP_X_REQUEST_ID='lb-probe')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['X-Request-ID'], 'lb-probe')


class SlowRequestLoggingTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @override_settings(SLOW_REQUEST_THRESHOLD_SECONDS=0.001)
    def test_logs_warning_when_slow(self):
        import time

        def get_response(request):
            time.sleep(0.01)
            return HttpResponse('ok')

        middleware = RequestIdMiddleware(get_response)
        with self.assertLogs('config.request', level='WARNING') as logs:
            middleware(self.factory.get('/api/v1/authorize'))
        self.assertIn('Slow request: GET /api/v1/authorize status=200', logs.output[0])

    @override_settings(SLOW_REQUEST_THRESHOLD_SECONDS=0)
    def test_zero_threshold_turns_it_off(self):
        middleware = RequestIdMiddleware(lambda request: HttpResponse('ok'))
        with self.assertNoLogs('config.request', level='WARNING'):
            middleware(self.factory.get('/'))

    @override_settings(SLOW_REQUEST_THRESHOLD_SECONDS=60)
    def test_fast_request_not_logged(self):
        middleware = RequestIdMiddleware(lambda request: HttpResponse('ok'))
        with self.assertNoLogs('config.request', level='WARNING'):
            middleware(self.factory.get('/'))
