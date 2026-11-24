"""Request spans, resource role, and traceparent on token exchange and MCP notify."""

from __future__ import annotations

import os
from threading import Thread
from unittest import mock

from django.test import Client, TestCase, override_settings
from opentelemetry import trace
from opentelemetry.propagate import inject
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from shellui_django.telemetry import _reset_for_tests, setup_telemetry

from apps.agents.approval_notify import notify_ai_approval_decided
from apps.federation.relying import _exchange


class TelemetryTests(TestCase):
    def tearDown(self):
        _reset_for_tests()
        for key in (
            'OTEL_RESOURCE_ATTRIBUTES',
            'OTEL_SERVICE_NAME',
            'OTEL_EXPORTER_OTLP_ENDPOINT',
            'SHELLUI_INSTANCE_ROLE',
            'SHELLUI_REGION',
        ):
            os.environ.pop(key, None)

    def _enable(self) -> InMemorySpanExporter:
        exporter = InMemorySpanExporter()
        self.assertTrue(
            setup_telemetry(
                'identity-service',
                service_version='test',
                environment='test',
                region='eu',
                span_exporter=exporter,
            )
        )
        return exporter

    def test_request_span_and_removed_metrics_routes(self):
        exporter = self._enable()
        client = Client()
        self.assertEqual(client.get('/health/live').status_code, 200)
        self.assertEqual(exporter.get_finished_spans(), ())
        response = client.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(exporter.get_finished_spans())
        self.assertEqual(client.get('/api/v1/metrics').status_code, 404)
        self.assertEqual(client.get('/api/v1/metrics/all').status_code, 404)

    def test_token_exchange_and_downstream_continue_traceparent(self):
        exporter = self._enable()
        tracer = trace.get_tracer('identity.test')
        client = Client()
        with tracer.start_as_current_span('caller') as span:
            parent = span.get_span_context().trace_id
            carrier: dict[str, str] = {}
            inject(carrier)
            token = client.post(
                '/oauth/token',
                data='{}',
                content_type='application/json',
                HTTP_TRACEPARENT=carrier['traceparent'],
            )
            downstream = client.post(
                '/api/v1/mcp/internal/mcp-downstream-access-token',
                data='{}',
                content_type='application/json',
                HTTP_TRACEPARENT=carrier['traceparent'],
            )
        self.assertIn(token.status_code, {400, 401, 404, 415})
        self.assertIn(downstream.status_code, {400, 401, 404, 415})
        traced = [item for item in exporter.get_finished_spans() if item.context.trace_id == parent]
        self.assertGreaterEqual(len(traced), 2)

    def test_instance_role_resource_attribute(self):
        os.environ['SHELLUI_INSTANCE_ROLE'] = 'global'
        os.environ['SHELLUI_REGION'] = 'eu'
        os.environ.pop('OTEL_RESOURCE_ATTRIBUTES', None)
        os.environ.pop('OTEL_SERVICE_NAME', None)
        from config.telemetry import _ensure_instance_role, _region, instance_role

        _ensure_instance_role(instance_role())
        exporter = InMemorySpanExporter()
        self.assertTrue(
            setup_telemetry(
                'identity-service',
                service_version='test',
                region=_region() or None,
                span_exporter=exporter,
            )
        )
        attributes = dict(trace.get_tracer_provider().resource.attributes)
        self.assertEqual(attributes['service.name'], 'identity-service')
        self.assertEqual(attributes['shellui.instance_role'], 'global')
        self.assertEqual(attributes['cloud.region'], 'eu')

    @override_settings(
        GLOBAL_ISSUER_URL='https://id.example',
        GLOBAL_CLIENT_ID='client',
        GLOBAL_CLIENT_SECRET='secret',
    )
    def test_upstream_token_exchange_sends_traceparent(self):
        self._enable()
        tracer = trace.get_tracer('identity.test')
        with tracer.start_as_current_span('caller') as span:
            parent = format(span.get_span_context().trace_id, '032x')
            with mock.patch('apps.federation.relying.requests.post') as post:
                post.return_value.status_code = 200
                post.return_value.json.return_value = {'id_token': 'header.payload.sig'}
                token = _exchange('code', {'redirect_uri': 'https://region.example/cb', 'verifier': 'verifier'})
        self.assertEqual(token, 'header.payload.sig')
        headers = post.call_args.kwargs['headers']
        self.assertEqual(headers['traceparent'].split('-')[1], parent)

    @override_settings(AI_SERVICE_URL='https://ai.example')
    def test_mcp_downstream_notify_sends_traceparent_from_a_worker_thread(self):
        self._enable()
        tracer = trace.get_tracer('identity.test')
        captured: dict[str, str] = {}

        def _post(*_args, **kwargs):
            captured['traceparent'] = kwargs['headers']['traceparent']
            response = mock.Mock()
            response.status_code = 204
            return response

        with tracer.start_as_current_span('caller') as span:
            parent = format(span.get_span_context().trace_id, '032x')
            from config.telemetry import bind_trace_context, current_trace_context

            context = current_trace_context()

            def _run():
                with bind_trace_context(context), mock.patch(
                    'apps.agents.approval_notify.requests.post', side_effect=_post
                ):
                    self.assertTrue(
                        notify_ai_approval_decided(
                            approval_id='approval-1',
                            status='approved',
                            company_id=1,
                            agent_id='agent-1',
                        )
                    )

            worker = Thread(target=_run)
            worker.start()
            worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(captured['traceparent'].split('-')[1], parent)
