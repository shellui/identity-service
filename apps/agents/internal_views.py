"""Internal service-to-identity APIs (signed assertions, no user tokens)."""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from shellui_mcp.internal import (
    APPROVAL_AUDIENCE,
    APPROVAL_SCOPE,
    CALL_LOG_AUDIENCE,
    CALL_LOG_SCOPE,
    REVOCATION_AUDIENCE,
    REVOCATION_SCOPE,
    InternalAssertionError,
    verify_mcp_internal_assertion,
)
from shellui_mcp.masking import redact_mapping

from apps.actions.event_log import record_event
from apps.actions.registry import get_event_type
from apps.agents.models import Agent, McpApprovalRequest, McpCallLog
from apps.agents.revocation import REVOCATION_CACHE_SECONDS, blocked_agent_ids


def _identity_origin() -> str:
    return (getattr(settings, 'JWT_ISSUER', '') or '').rstrip('/')


def _assertion_from_request(request) -> str:
    auth = request.headers.get('Authorization') or ''
    if auth.lower().startswith('bearer '):
        return auth[7:].strip()
    return str(request.data.get('assertion') or '').strip()


def _approval_assertion_claims(request) -> tuple[dict | None, Response | None]:
    try:
        claims = verify_mcp_internal_assertion(
            _assertion_from_request(request),
            expected_audience=APPROVAL_AUDIENCE,
            expected_scope=APPROVAL_SCOPE,
            expected_target=_identity_origin(),
        )
    except InternalAssertionError as exc:
        return None, Response({'error': exc.message}, status=exc.status)
    agent_id = str(claims.get('agent_id') or '')
    company_id = claims.get('company_id')
    service = str(claims.get('service') or '')
    action = str(claims.get('action') or '')
    arguments_hash = str(claims.get('arguments_hash') or '')
    if not agent_id or company_id is None or not service or not action or not arguments_hash:
        return None, Response({'error': 'Invalid assertion claims.'}, status=status.HTTP_400_BAD_REQUEST)
    return claims, None


def _approval_binding_from_request(request, claims: dict) -> tuple[dict | None, Response | None]:
    """Merge assertion claims with optional body/query fields; reject mismatches."""
    if request.method == 'GET':
        source = request.query_params
    else:
        body = request.data if isinstance(request.data, dict) else {}
        source = body
    agent_id = str(claims.get('agent_id') or '')
    company_id = claims.get('company_id')
    service = str(claims.get('service') or '')
    action = str(claims.get('action') or '')
    arguments_hash = str(claims.get('arguments_hash') or '')
    for key, expected in (
        ('agent_id', agent_id),
        ('company_id', company_id),
        ('service', service),
        ('action', action),
        ('arguments_hash', arguments_hash),
    ):
        if key not in source or source.get(key) in (None, ''):
            continue
        provided = source.get(key)
        if key == 'company_id':
            try:
                provided_norm = int(provided)
                expected_norm = int(expected)
            except (TypeError, ValueError):
                return None, Response({'error': 'Invalid company_id.'}, status=status.HTTP_400_BAD_REQUEST)
            if provided_norm != expected_norm:
                return None, Response({'error': 'Request does not match assertion.'}, status=status.HTTP_400_BAD_REQUEST)
            continue
        if str(provided) != str(expected):
            return None, Response({'error': 'Request does not match assertion.'}, status=status.HTTP_400_BAD_REQUEST)
    return {
        'agent_id': agent_id,
        'company_id': company_id,
        'service': service,
        'action': action,
        'arguments_hash': arguments_hash,
    }, None


def _public_approval_status(row: McpApprovalRequest, *, now) -> str:
    if row.status == McpApprovalRequest.STATUS_REJECTED:
        return 'denied'
    if row.status == McpApprovalRequest.STATUS_EXECUTED:
        return 'expired'
    if row.status == McpApprovalRequest.STATUS_EXPIRED or row.expires_at <= now:
        return 'expired'
    if row.status == McpApprovalRequest.STATUS_APPROVED:
        return 'approved'
    if row.status == McpApprovalRequest.STATUS_PENDING:
        return 'pending'
    return 'expired'


def _lookup_approval_row(binding: dict) -> McpApprovalRequest | None:
    return (
        McpApprovalRequest.objects.filter(
            agent_id=binding['agent_id'],
            company_id=binding['company_id'],
            service=binding['service'],
            action=binding['action'],
            arguments_hash=binding['arguments_hash'],
        )
        .order_by('-created_at')
        .first()
    )


class McpRevocationListView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        try:
            verify_mcp_internal_assertion(
                _assertion_from_request(request),
                expected_audience=REVOCATION_AUDIENCE,
                expected_scope=REVOCATION_SCOPE,
                expected_target=_identity_origin(),
            )
        except InternalAssertionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        company_id = request.query_params.get('company_id')
        cid = int(company_id) if company_id and str(company_id).isdigit() else None
        payload = {
            'revoked_agent_ids': blocked_agent_ids(company_id=cid),
            'cache_seconds': REVOCATION_CACHE_SECONDS,
        }
        response = Response(payload)
        response['Cache-Control'] = f'private, max-age={REVOCATION_CACHE_SECONDS}'
        return response


class McpInternalApprovalCreateView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        try:
            claims = verify_mcp_internal_assertion(
                _assertion_from_request(request),
                expected_audience=APPROVAL_AUDIENCE,
                expected_scope=APPROVAL_SCOPE,
                expected_target=_identity_origin(),
            )
        except InternalAssertionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        agent_id = str(claims.get('agent_id') or '')
        company_id = claims.get('company_id')
        service = str(claims.get('service') or '')
        action = str(claims.get('action') or '')
        arguments_hash = str(claims.get('arguments_hash') or '')
        if not agent_id or not company_id or not service or not action or not arguments_hash:
            return Response({'error': 'Invalid assertion claims.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            agent = Agent.objects.get(pk=agent_id, company_id=company_id)
        except Agent.DoesNotExist:
            return Response({'error': 'Agent not found.'}, status=status.HTTP_404_NOT_FOUND)
        if not agent.is_active:
            return Response({'error': 'Agent inactive.'}, status=status.HTTP_403_FORBIDDEN)
        body = request.data if isinstance(request.data, dict) else {}
        args = body.get('arguments') if isinstance(body.get('arguments'), dict) else {}
        redacted = redact_mapping(args, read_sensitive=False)
        expires_at = timezone.now() + timedelta(minutes=10)
        row, created = McpApprovalRequest.objects.get_or_create(
            agent=agent,
            arguments_hash=arguments_hash,
            status=McpApprovalRequest.STATUS_PENDING,
            defaults={
                'company_id': company_id,
                'service': service,
                'action': action,
                'arguments_redacted': redacted,
                'expires_at': expires_at,
            },
        )
        if not created and row.expires_at <= timezone.now():
            row.expires_at = expires_at
            row.arguments_redacted = redacted
            row.save(update_fields=['expires_at', 'arguments_redacted'])
        return Response({'id': str(row.id), 'status': row.status, 'expires_at': row.expires_at.isoformat()})


class McpInternalApprovalStateView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        return self._state(request)

    def post(self, request):
        return self._state(request)

    def _state(self, request):
        claims, err = _approval_assertion_claims(request)
        if err:
            return err
        binding, err = _approval_binding_from_request(request, claims)
        if err:
            return err
        row = _lookup_approval_row(binding)
        if row is None:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        now = timezone.now()
        public_status = _public_approval_status(row, now=now)
        payload = {'status': public_status}
        if public_status == 'approved':
            payload['id'] = str(row.id)
        return Response(payload)


class McpInternalApprovalConsumeView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request, approval_id=None):
        try:
            verify_mcp_internal_assertion(
                _assertion_from_request(request),
                expected_audience=CALL_LOG_AUDIENCE,
                expected_scope=CALL_LOG_SCOPE,
                expected_target=_identity_origin(),
            )
        except InternalAssertionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        body = request.data if isinstance(request.data, dict) else {}
        raw_id = approval_id or body.get('approval_id') or body.get('id')
        approval_id_str = str(raw_id or '').strip()
        if not approval_id_str:
            return Response({'error': 'approval_id required.'}, status=status.HTTP_400_BAD_REQUEST)
        now = timezone.now()
        with transaction.atomic():
            try:
                row = McpApprovalRequest.objects.select_for_update().get(pk=approval_id_str)
            except McpApprovalRequest.DoesNotExist:
                return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
            if row.status == McpApprovalRequest.STATUS_EXECUTED:
                return Response(
                    {'error': 'Approval already consumed.', 'consumed': False},
                    status=status.HTTP_409_CONFLICT,
                )
            if row.status != McpApprovalRequest.STATUS_APPROVED or row.expires_at <= now:
                return Response(
                    {'error': 'Approval is not consumable.', 'consumed': False},
                    status=status.HTTP_409_CONFLICT,
                )
            row.status = McpApprovalRequest.STATUS_EXECUTED
            row.executed_at = now
            row.save(update_fields=['status', 'executed_at'])
        return Response({'consumed': True})


class McpInternalCallLogView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        try:
            verify_mcp_internal_assertion(
                _assertion_from_request(request),
                expected_audience=CALL_LOG_AUDIENCE,
                expected_scope=CALL_LOG_SCOPE,
                expected_target=_identity_origin(),
            )
        except InternalAssertionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        body = request.data if isinstance(request.data, dict) else {}
        agent_id = str(body.get('agent_id') or '')
        company_id = body.get('company_id')
        if not agent_id or company_id is None:
            return Response({'error': 'agent_id and company_id required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            agent = Agent.objects.get(pk=agent_id, company_id=company_id)
        except Agent.DoesNotExist:
            return Response({'error': 'Agent not found.'}, status=status.HTTP_404_NOT_FOUND)
        args = body.get('arguments') if isinstance(body.get('arguments'), dict) else {}
        row = McpCallLog.objects.create(
            agent=agent,
            company_id=company_id,
            service=str(body.get('service') or '')[:32],
            tool=str(body.get('tool') or '')[:255],
            http_method=str(body.get('method') or '')[:10],
            path=str(body.get('path') or '')[:500],
            status_code=int(body.get('status') or 0),
            duration_ms=int(body.get('duration_ms') or 0),
            arguments_redacted=redact_mapping(args, read_sensitive=False),
        )
        event = get_event_type('identity.mcp.call')
        if event:
            record_event(
                event,
                agent.company,
                {
                    'agent_id': str(agent.id),
                    'service': row.service,
                    'tool': row.tool,
                    'status_code': row.status_code,
                },
            )
        return Response({'id': row.id}, status=status.HTTP_201_CREATED)
