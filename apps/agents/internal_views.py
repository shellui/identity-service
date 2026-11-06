"""Internal service-to-identity APIs (signed assertions, no user tokens)."""

from __future__ import annotations

from datetime import timedelta
import uuid

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from shellui_django.mcp.internal import (
    APPROVAL_AUDIENCE,
    APPROVAL_SCOPE,
    CALL_LOG_AUDIENCE,
    CALL_LOG_SCOPE,
    REVOCATION_AUDIENCE,
    REVOCATION_SCOPE,
    InternalAssertionError,
)
from apps.actions.event_log import record_event
from apps.actions.registry import get_event_type
from apps.agents.approval_audit import record_approval_expired_once
from apps.agents.approval_decisions import (
    ApprovalDecisionError,
    client_allow,
    client_allow_session,
    client_deny,
)
from apps.agents.approval_internal import (
    approval_binding_from_claims,
    approval_lookup_filter,
    lookup_approval_row,
    public_approval_status,
)
from apps.agents.approval_links import sign_approval_fallback_token
from apps.agents.approval_session import (
    active_session_grant,
    revoke_session_grant,
    session_allows_non_destructive_write,
)
from apps.agents.approval_authority import (
    agent_matches_approval_authority,
    approval_row_stale_for_agent,
    approval_row_stale_for_authority_only,
    parse_approval_authority_claims,
)
from apps.agents.approval_global import (
    ensure_global_approval_claims,
    global_agent_revoked,
    global_approval_live_binding_ok,
    is_global_placeholder_company_id,
    provisioned_company_for_global_uuid,
    global_user_sub_is_company_owner,
)
from apps.agents.internal_callers import verify_caller_assertion, verify_delegated_authority_assertion
from apps.agents.call_log_internal import fixed_resource_label_for_service, safe_operation_title
from apps.agents.call_log_outcome import (
    OUTCOME_ALLOWED,
    OUTCOME_DENIED,
    OUTCOME_FAILED,
    OUTCOME_SESSION_USED,
    OUTCOME_WAITING_APPROVAL,
    canonical_outcome_ingest,
)
from apps.agents.json_strict import strict_json_int_for_company_id, strict_non_negative_int
from apps.agents.mcp_claims import strict_bool_claim
from apps.agents.mcp_audit_codes import sanitize_error_code
from apps.agents.models import Agent, GlobalAgentRevocation, McpApprovalRequest, McpCallLog
from apps.agents.tokens import company_name_for_agent
from apps.agents.revocation import (
    REVOCATION_CACHE_SECONDS,
    active_max_grant_version,
    blocked_agent_ids,
    blocked_agent_snapshots,
)
from apps.agents.revocation_jwt import compute_revocation_policy_version, sign_revocation_list_response
from apps.federation.signing import TokenError


def _identity_origin() -> str:
    return (getattr(settings, 'JWT_ISSUER', '') or '').rstrip('/')


def _assertion_from_request(request) -> str:
    auth = request.headers.get('Authorization') or ''
    if auth.lower().startswith('bearer '):
        return auth[7:].strip()
    return str(request.data.get('assertion') or '').strip()


def _approval_assertion_claims(request):
    try:
        verified = verify_caller_assertion(
            _assertion_from_request(request),
            audience=APPROVAL_AUDIENCE,
            scope=APPROVAL_SCOPE,
            target=_identity_origin(),
        )
    except InternalAssertionError as exc:
        return None, None, Response({'error': exc.message}, status=exc.status)
    binding = approval_binding_from_claims(verified.claims)
    if binding is None:
        return None, None, Response({'error': 'Invalid assertion claims.'}, status=status.HTTP_400_BAD_REQUEST)
    return verified.claims, verified.caller, None


def _approval_live_authority(claims: dict, binding: dict) -> Response | None:
    auth, err = parse_approval_authority_claims(claims)
    if err:
        return Response({'error': err}, status=status.HTTP_400_BAD_REQUEST)
    assert auth is not None
    if binding.get('is_global'):
        meta = binding.get('global_meta') or {}
        meta2 = ensure_global_approval_claims(claims)
        if meta2 is None:
            return Response({'error': 'Invalid global approval claims.'}, status=status.HTTP_400_BAD_REQUEST)
        if (
            meta.get('global_agent_id') != meta2.get('global_agent_id')
            or meta.get('global_company_id') != meta2.get('global_company_id')
            or meta.get('company_binding_version') != meta2.get('company_binding_version')
            or meta.get('global_user_sub') != meta2.get('global_user_sub')
        ):
            return Response({'error': 'Global approval metadata mismatch.'}, status=status.HTTP_400_BAD_REQUEST)
        if global_agent_revoked(meta2['global_agent_id']):
            return Response({'error': 'Global agent is revoked.'}, status=status.HTTP_403_FORBIDDEN)
        gv = int(auth['grant_version'])
        if not global_approval_live_binding_ok(meta2, authority_grant_version=gv):
            return Response({'error': 'Global approval authority mismatch.'}, status=status.HTTP_409_CONFLICT)
        pc = provisioned_company_for_global_uuid(meta2['global_company_id'])
        assert pc is not None
        if not global_user_sub_is_company_owner(global_user_sub=meta2['global_user_sub'], company=pc.company):
            return Response({'error': 'Actor is not a verified company owner.'}, status=status.HTTP_403_FORBIDDEN)
        return None

    cid = binding['company_id']
    if is_global_placeholder_company_id(cid):
        return Response({'error': 'Invalid binding.'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        agent = Agent.objects.only(
            'id',
            'grant_version',
            'global_company_id',
            'company_binding_version',
            'company_id',
        ).get(pk=binding['agent_id'], company_id=cid)
    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found.'}, status=status.HTTP_404_NOT_FOUND)
    if not agent_matches_approval_authority(agent, auth):
        return Response({'error': 'Approval authority mismatch.'}, status=status.HTTP_409_CONFLICT)
    return None


def _delegated_approval_caller_conflict(
    *,
    agent: Agent,
    caller_name: str,
) -> Response | None:
    """Regional services may host approvals for personal agents; delegated rows need ai-service."""
    if agent.global_agent_id is None:
        return None
    if caller_name == 'ai':
        return None
    return Response(
        {
            'error': (
                'This agent was created by delegated global token exchange. Route MCP approvals '
                'through the regional AI gateway for this company, or reconcile out-of-band.'
            ),
            'error_code': 'out_of_sync',
        },
        status=status.HTTP_409_CONFLICT,
    )


class McpRevocationListView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        try:
            verify_caller_assertion(
                _assertion_from_request(request),
                audience=REVOCATION_AUDIENCE,
                scope=REVOCATION_SCOPE,
                target=_identity_origin(),
            )
        except InternalAssertionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        company_id = request.query_params.get('company_id')
        cid = int(company_id) if company_id and str(company_id).isdigit() else None
        revoked_ids = blocked_agent_ids(company_id=cid)
        agents = blocked_agent_snapshots(company_id=cid)
        max_gv = active_max_grant_version(company_id=cid)
        policy_ver = compute_revocation_policy_version(
            revoked_ids=revoked_ids,
            agents=agents,
            cache_seconds=REVOCATION_CACHE_SECONDS,
            max_active_grant_version=max_gv,
        )
        try:
            revocation_assertion = sign_revocation_list_response(
                revoked_agent_ids=revoked_ids,
                agents=agents,
                cache_seconds=REVOCATION_CACHE_SECONDS,
                revocation_policy_version=policy_ver,
                max_active_grant_version=max_gv,
            )
        except TokenError:
            return Response(
                {'error': 'Revocation list signing is not configured.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        payload = {
            'revoked_agent_ids': revoked_ids,
            'agents': agents,
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_policy_version': policy_ver,
            'revocation_assertion': revocation_assertion,
        }
        response = Response(payload)
        response['Cache-Control'] = f'private, max-age={REVOCATION_CACHE_SECONDS}'
        return response


_ALLOWED_DELEGATED_AUTHORITY_CALLERS = frozenset({'storage', 'hosting', 'email', 'ai'})

_DELEGATED_AUTHORITY_BODY_KEYS = frozenset(
    {
        'agent_id',
        'company_id',
        'global_company_id',
        'grant_version',
        'company_binding_version',
    }
)


def _delegated_authority_assertion_error_response(exc: InternalAssertionError) -> Response:
    if getattr(exc, 'message', None) == 'Missing assertion.':
        return Response({'error': 'Missing assertion.'}, status=status.HTTP_404_NOT_FOUND)
    return Response({'error': exc.message}, status=exc.status)


def _delegated_authority_revoked_at(agent: Agent) -> int | None:
    ga = agent.global_agent_id
    if ga is None:
        return None
    row_revoked = agent.revoked_at is not None
    global_row_revoked = GlobalAgentRevocation.objects.filter(global_agent_id=ga).exists()
    if row_revoked and agent.revoked_at is not None:
        return int(agent.revoked_at.timestamp())
    if global_row_revoked:
        grev = (
            GlobalAgentRevocation.objects.filter(global_agent_id=ga)
            .order_by('-revoked_at')
            .values_list('revoked_at', flat=True)
            .first()
        )
        if grev is not None:
            return int(grev.timestamp())
    return None


def _delegated_authority_fixed_payload(
    agent: Agent,
    *,
    authorized: bool,
    active: bool,
    global_company_id: str,
    grant_version: int,
    company_binding_version: int,
) -> dict:
    """Fixed JSON keys for every delegated-authority **200** response (no extras)."""
    ga = agent.global_agent_id
    assert ga is not None
    paused = agent.paused_at is not None
    row_revoked = agent.revoked_at is not None
    global_row_revoked = GlobalAgentRevocation.objects.filter(global_agent_id=ga).exists()
    revoked = bool(row_revoked or global_row_revoked)
    services = sorted(str(s) for s in (agent.services_allowed or []))
    # Delegated exchange agents never get destructive without asking on the regional JWT.
    allow_dest = False
    out = {
        'authorized': authorized,
        'active': active,
        'revoked': revoked,
        'paused': paused,
        'agent_id': str(agent.id),
        'company_id': int(agent.company_id),
        'global_agent_id': str(ga),
        'global_company_id': global_company_id,
        'grant_version': int(grant_version),
        'company_binding_version': int(company_binding_version),
        'access_mode': str(agent.access_mode),
        'read_level': str(agent.read_level),
        'allow_destructive': allow_dest,
        'services_allowed': services,
        'revoked_at': _delegated_authority_revoked_at(agent),
    }
    return out


def _delegated_authority_mismatch_response(*, agent: Agent, body_gc: uuid.UUID, gv: int, cb: int) -> Response:
    """Binding triple does not match live row: fail closed (never authorized)."""
    payload = _delegated_authority_fixed_payload(
        agent,
        authorized=False,
        active=False,
        global_company_id=str(body_gc),
        grant_version=gv,
        company_binding_version=cb,
    )
    return Response(payload)


def _delegated_authority_live_payload(agent: Agent) -> dict:
    """Authoritative state when body binding matches the delegated agent row."""
    row_gc = agent.global_company_id
    row_cb = agent.company_binding_version
    ga = agent.global_agent_id
    assert ga is not None and row_gc is not None and row_cb is not None
    gv = int(agent.grant_version or 0)
    paused = agent.paused_at is not None
    row_revoked = agent.revoked_at is not None
    global_row_revoked = GlobalAgentRevocation.objects.filter(global_agent_id=ga).exists()
    revoked = bool(row_revoked or global_row_revoked)
    active = bool(agent.is_active and not revoked)
    authorized = bool(active and not paused)
    return _delegated_authority_fixed_payload(
        agent,
        authorized=authorized,
        active=active,
        global_company_id=str(row_gc),
        grant_version=gv,
        company_binding_version=int(row_cb),
    )


class McpInternalDelegatedAgentAuthorityView(APIView):
    """Storage, hosting, email, and ai-service: verify live delegated agent binding (not revocation-only)."""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        try:
            verified = verify_delegated_authority_assertion(
                _assertion_from_request(request),
                target=_identity_origin(),
            )
        except InternalAssertionError as exc:
            return _delegated_authority_assertion_error_response(exc)
        if verified.caller.name not in _ALLOWED_DELEGATED_AUTHORITY_CALLERS:
            return Response({'error': 'Caller not allowed for delegated authority checks.'}, status=status.HTTP_403_FORBIDDEN)
        body = request.data if isinstance(request.data, dict) else {}
        unknown = set(body.keys()) - _DELEGATED_AUTHORITY_BODY_KEYS
        if unknown:
            return Response({'error': 'Unexpected request fields.'}, status=status.HTTP_400_BAD_REQUEST)
        raw_aid = body.get('agent_id')
        try:
            agent_uuid = uuid.UUID(str(raw_aid).strip())
        except (TypeError, ValueError, AttributeError):
            return Response({'error': 'agent_id must be a uuid string.'}, status=status.HTTP_400_BAD_REQUEST)
        cid = strict_json_int_for_company_id(body.get('company_id'))
        if cid is None or cid <= 0:
            return Response({'error': 'company_id must be a positive JSON integer.'}, status=status.HTTP_400_BAD_REQUEST)
        raw_gc = body.get('global_company_id')
        if type(raw_gc) is not str or not raw_gc.strip():
            return Response({'error': 'global_company_id must be a uuid string.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            body_gc = uuid.UUID(raw_gc.strip())
        except (ValueError, TypeError):
            return Response({'error': 'Invalid global_company_id.'}, status=status.HTTP_400_BAD_REQUEST)
        gv = strict_non_negative_int(body.get('grant_version'))
        if gv is None:
            return Response({'error': 'grant_version must be a JSON non-negative integer.'}, status=status.HTTP_400_BAD_REQUEST)
        cb = strict_non_negative_int(body.get('company_binding_version'))
        if cb is None:
            return Response(
                {'error': 'company_binding_version must be a JSON non-negative integer.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            agent = Agent.objects.get(pk=agent_uuid, company_id=cid)
        except Agent.DoesNotExist:
            return Response({'error': 'Agent not found.'}, status=status.HTTP_404_NOT_FOUND)

        if agent.global_agent_id is None:
            return Response({'error': 'Agent is not a delegated exchange agent.'}, status=status.HTTP_404_NOT_FOUND)
        row_gc = getattr(agent, 'global_company_id', None)
        row_cb = getattr(agent, 'company_binding_version', None)
        if row_gc is None or row_cb is None:
            return Response({'error': 'Agent has no SaaS company binding.'}, status=status.HTTP_404_NOT_FOUND)
        if row_gc != body_gc or int(agent.grant_version or 0) != int(gv) or int(row_cb) != int(cb):
            return _delegated_authority_mismatch_response(agent=agent, body_gc=body_gc, gv=gv, cb=cb)

        return Response(_delegated_authority_live_payload(agent))


class McpInternalApprovalCreateView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        try:
            verified = verify_caller_assertion(
                _assertion_from_request(request),
                audience=APPROVAL_AUDIENCE,
                scope=APPROVAL_SCOPE,
                target=_identity_origin(),
            )
        except InternalAssertionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        claims = verified.claims
        binding = approval_binding_from_claims(claims)
        if binding is None:
            return Response({'error': 'Invalid assertion claims.'}, status=status.HTTP_400_BAD_REQUEST)
        agent_probe: Agent | None = None
        if binding.get('is_global'):
            if verified.caller.name != 'dashboard':
                return Response(
                    {'error': 'Global MCP approvals require a dashboard-signed assertion.'},
                    status=status.HTTP_403_FORBIDDEN,
                )
        else:
            try:
                agent_probe = Agent.objects.get(pk=binding['agent_id'], company_id=binding['company_id'])
            except Agent.DoesNotExist:
                return Response({'error': 'Agent not found.'}, status=status.HTTP_404_NOT_FOUND)
            if not agent_probe.is_active:
                return Response({'error': 'Agent inactive.'}, status=status.HTTP_403_FORBIDDEN)
            delegated_err = _delegated_approval_caller_conflict(agent=agent_probe, caller_name=verified.caller.name)
            if delegated_err is not None:
                return delegated_err
        live_err = _approval_live_authority(claims, binding)
        if live_err is not None:
            return live_err
        body = request.data if isinstance(request.data, dict) else {}
        if 'arguments' in body:
            return Response({'error': 'arguments not accepted.'}, status=status.HTTP_400_BAD_REQUEST)
        if 'arguments_redacted' in body:
            return Response({'error': 'arguments_redacted not accepted.'}, status=status.HTTP_400_BAD_REQUEST)
        if body.get('target') not in (None, '') or body.get('short_action_summary') not in (None, ''):
            return Response(
                {'error': 'target and short_action_summary are server-derived.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        service_id = (binding['service'] or '')[:32]
        action_slug = (binding['action'] or '')[:255]
        target = f'{service_id}:{action_slug}'[:500] if service_id or action_slug else ''
        short_action_summary = ''
        if 'is_destructive' in body:
            raw_des = body.get('is_destructive')
            if raw_des is not True and raw_des is not False:
                return Response({'error': 'is_destructive must be a JSON boolean.'}, status=status.HTTP_400_BAD_REQUEST)
            is_destructive = raw_des
        else:
            is_destructive = False
        expires_at = timezone.now() + timedelta(minutes=10)
        auth_parsed, auth_err = parse_approval_authority_claims(claims)
        assert auth_err is None and auth_parsed is not None

        if binding.get('is_global'):
            meta = binding['global_meta']
            setup_exp = meta.get('setup_expires_at')
            snap_gv = int(auth_parsed['grant_version'])
            snap_gc = meta['global_company_id']
            snap_cb = int(meta['company_binding_version'])
            row, created = McpApprovalRequest.objects.get_or_create(
                agent=None,
                company=None,
                arguments_hash=binding['arguments_hash'],
                service=binding['service'],
                action=binding['action'],
                status=McpApprovalRequest.STATUS_PENDING,
                global_agent_id=meta['global_agent_id'],
                global_company_id=meta['global_company_id'],
                company_binding_version=meta['company_binding_version'],
                global_user_sub=meta['global_user_sub'],
                defaults={
                    'target': target,
                    'arguments_redacted': {},
                    'expires_at': expires_at,
                    'is_destructive': is_destructive,
                    'short_action_summary': short_action_summary,
                    'authority_grant_version': snap_gv,
                    'authority_global_company_id': snap_gc,
                    'authority_company_binding_version': snap_cb,
                    'setup_expires_at': setup_exp,
                    'is_company_owner_actor': True,
                },
            )
        else:
            agent = agent_probe
            assert agent is not None
            snap_gv = int(agent.grant_version or 0)
            snap_gc = agent.global_company_id
            snap_cb = agent.company_binding_version
            row, created = McpApprovalRequest.objects.get_or_create(
                agent=agent,
                arguments_hash=binding['arguments_hash'],
                service=binding['service'],
                action=binding['action'],
                status=McpApprovalRequest.STATUS_PENDING,
                defaults={
                    'company_id': binding['company_id'],
                    'target': target,
                    'arguments_redacted': {},
                    'expires_at': expires_at,
                    'is_destructive': is_destructive,
                    'short_action_summary': short_action_summary,
                    'authority_grant_version': snap_gv,
                    'authority_global_company_id': snap_gc,
                    'authority_company_binding_version': snap_cb,
                },
            )
        if not created:
            if row.expires_at <= timezone.now():
                row.expires_at = expires_at
                row.arguments_redacted = {}
                row.target = target or row.target
                row.is_destructive = is_destructive
                row.short_action_summary = short_action_summary
                row.save(
                    update_fields=[
                        'expires_at',
                        'arguments_redacted',
                        'target',
                        'is_destructive',
                        'short_action_summary',
                    ]
                )
        token = sign_approval_fallback_token(str(row.id))
        fallback_path = f'/oauth/mcp/approval/{row.id}?token={token}'
        return Response(
            {
                'id': str(row.id),
                'status': row.status,
                'expires_at': row.expires_at.isoformat(),
                'is_destructive': row.is_destructive,
                'fallback_path': fallback_path,
            }
        )


class McpInternalApprovalStateView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        claims, _caller, err = _approval_assertion_claims(request)
        if err:
            return err
        binding = approval_binding_from_claims(claims)
        assert binding is not None
        live_err = _approval_live_authority(claims, binding)
        if live_err is not None:
            return live_err
        row = lookup_approval_row(binding)
        if row is None:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        auth_parsed, auth_err = parse_approval_authority_claims(claims)
        assert auth_err is None and auth_parsed is not None
        if binding.get('is_global'):
            if approval_row_stale_for_authority_only(row, auth_parsed):
                return Response({'error': 'Approval authority stale.'}, status=status.HTTP_409_CONFLICT)
        else:
            try:
                agent = Agent.objects.get(pk=binding['agent_id'], company_id=binding['company_id'])
            except Agent.DoesNotExist:
                return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
            if approval_row_stale_for_agent(agent, row):
                return Response({'error': 'Approval authority stale.'}, status=status.HTTP_409_CONFLICT)
        now = timezone.now()
        public_status = public_approval_status(row, now=now)
        if public_status == 'expired':
            record_approval_expired_once(row)
        payload = {'status': public_status}
        if public_status == 'approved':
            payload['id'] = str(row.id)
        return Response(payload)


class McpInternalApprovalDecideView(APIView):
    """Client/gateway decisions: allow, deny, or allow_session (non-destructive only)."""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        claims, caller, err = _approval_assertion_claims(request)
        if err:
            return err
        binding = approval_binding_from_claims(claims)
        assert binding is not None
        live_err = _approval_live_authority(claims, binding)
        if live_err is not None:
            return live_err
        body = request.data if isinstance(request.data, dict) else {}
        approval_id = str(body.get('approval_id') or '').strip()
        decision = str(body.get('decision') or '').strip().lower()
        actor_email = str(body.get('actor_email') or '').strip() or None
        connection_id = str(body.get('connection_id') or '').strip()
        if not approval_id:
            return Response({'error': 'approval_id required.'}, status=status.HTTP_400_BAD_REQUEST)
        flt = {'pk': approval_id, **approval_lookup_filter(binding)}
        if binding.get('is_global'):
            flt['agent_id__isnull'] = True
            flt['company_id__isnull'] = True
        try:
            row = McpApprovalRequest.objects.select_related('agent').get(**flt)
        except McpApprovalRequest.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        auth_parsed, auth_err = parse_approval_authority_claims(claims)
        assert auth_err is None and auth_parsed is not None
        if binding.get('is_global'):
            if approval_row_stale_for_authority_only(row, auth_parsed):
                return Response({'error': 'Approval authority stale.'}, status=status.HTTP_409_CONFLICT)
        else:
            if row.agent_id is None:
                return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
            if approval_row_stale_for_agent(row.agent, row):
                return Response({'error': 'Approval authority stale.'}, status=status.HTTP_409_CONFLICT)
        if binding.get('is_global') and decision in ('allow_session', 'session'):
            return Response({'error': 'Session allow requires a regional agent.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            if decision in ('allow', 'approve'):
                result = client_allow(row, actor_email=actor_email)
            elif decision in ('deny', 'reject'):
                result = client_deny(row, actor_email=actor_email)
            elif decision in ('allow_session', 'session'):
                result = client_allow_session(
                    row,
                    connection_id=connection_id,
                    actor_email=actor_email,
                    caller_name=caller.name,
                    assertion_claims=claims,
                )
            else:
                return Response({'error': 'decision must be allow, deny, or allow_session.'}, status=status.HTTP_400_BAD_REQUEST)
        except ApprovalDecisionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        return Response({'approval_id': str(result.row.id), 'status': result.row.status, 'audit_status': result.audit_status})


class McpInternalApprovalSessionCheckView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        claims, _caller, err = _approval_assertion_claims(request)
        if err:
            return err
        binding = approval_binding_from_claims(claims)
        assert binding is not None
        if binding.get('is_global'):
            return Response(
                {'error': 'Session grants apply to regional agent approvals only.', 'session_allowed': False},
                status=status.HTTP_400_BAD_REQUEST,
            )
        body = request.data if isinstance(request.data, dict) else {}
        connection_id = str(body.get('connection_id') or '').strip()
        if 'is_destructive' in body:
            raw_des = body.get('is_destructive')
            if raw_des is not True and raw_des is not False:
                return Response(
                    {'error': 'is_destructive must be a JSON boolean.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            is_destructive = raw_des
        else:
            is_destructive = False
        live_err = _approval_live_authority(claims, binding)
        if live_err is not None:
            return live_err
        grant = active_session_grant(
            agent_id=binding['agent_id'],
            company_id=binding['company_id'],
            connection_id=connection_id,
            service=str(binding.get('service') or '')[:32],
            action=str(binding.get('action') or '')[:255],
            arguments_hash=str(binding.get('arguments_hash') or '')[:64],
        )
        allowed = not is_destructive and grant is not None
        payload: dict = {'session_allowed': allowed}
        if allowed:
            assert grant is not None
            ag = Agent.objects.only(
                'grant_version',
                'global_company_id',
                'company_binding_version',
                'global_agent_id',
            ).get(pk=binding['agent_id'], company_id=binding['company_id'])
            payload['grant_version'] = int(ag.grant_version or 0)
            g_agent = getattr(ag, 'global_agent_id', None)
            ag_gc = getattr(ag, 'global_company_id', None)
            ag_cb = getattr(ag, 'company_binding_version', None)
            if g_agent is not None:
                if ag_gc is None or ag_cb is None:
                    return Response(
                        {'error': 'Delegated agent is missing SaaS company binding.', 'session_allowed': False},
                        status=status.HTTP_403_FORBIDDEN,
                    )
                payload['global_company_id'] = str(ag_gc)
                payload['company_binding_version'] = int(ag_cb)
            now = timezone.now()
            setup_cid = getattr(grant, 'setup_company_id', None)
            setup_until = getattr(grant, 'setup_context_expires_at', None)
            setup_unix = None
            new_grant = strict_bool_claim(getattr(grant, 'setup_new_company_grant', False))
            setup_ttl = getattr(grant, 'setup_mcp_session_ttl_seconds', None)
            snap_gc = getattr(grant, 'global_company_id', None)
            snap_cb = getattr(grant, 'company_binding_version', None)
            setup_extended = (
                new_grant
                and snap_gc is not None
                and snap_cb is not None
                and setup_ttl is not None
                and setup_cid is not None
                and setup_until is not None
                and int(setup_cid) == int(binding['company_id'])
                and setup_until > now
            )
            if setup_extended:
                setup_unix = int(setup_until.timestamp())
            payload['expires_at'] = grant.expires_at.isoformat()
            if setup_unix is not None:
                payload['setup_expires_at'] = setup_unix
            if setup_extended:
                payload['setup_flow'] = True
                payload['mcp_new_company_grant'] = True
                payload['mcp_session_ttl_seconds'] = int(setup_ttl)
        return Response(payload)


class McpInternalApprovalSessionRevokeView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        claims, _caller, err = _approval_assertion_claims(request)
        if err:
            return err
        binding = approval_binding_from_claims(claims)
        assert binding is not None
        if binding.get('is_global'):
            return Response({'error': 'Session grants apply to regional agent approvals only.'}, status=status.HTTP_400_BAD_REQUEST)
        body = request.data if isinstance(request.data, dict) else {}
        connection_id = str(body.get('connection_id') or '').strip()
        updated = revoke_session_grant(
            agent_id=binding['agent_id'],
            company_id=binding['company_id'],
            connection_id=connection_id,
        )
        return Response({'revoked': updated > 0})


class McpInternalApprovalConsumeView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        claims, _caller, err = _approval_assertion_claims(request)
        if err:
            return err
        binding = approval_binding_from_claims(claims)
        assert binding is not None
        live_err = _approval_live_authority(claims, binding)
        if live_err is not None:
            return live_err
        body = request.data if isinstance(request.data, dict) else {}
        approval_id_str = str(body.get('approval_id') or '').strip()
        if not approval_id_str:
            return Response({'error': 'approval_id required.'}, status=status.HTTP_400_BAD_REQUEST)
        now = timezone.now()
        with transaction.atomic():
            try:
                flt = {'pk': approval_id_str, **approval_lookup_filter(binding)}
                if binding.get('is_global'):
                    flt['agent_id__isnull'] = True
                    flt['company_id__isnull'] = True
                row = McpApprovalRequest.objects.select_for_update().select_related('agent').filter(**flt).get()
            except McpApprovalRequest.DoesNotExist:
                return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
            auth_parsed, auth_err = parse_approval_authority_claims(claims)
            assert auth_err is None and auth_parsed is not None
            if binding.get('is_global'):
                if approval_row_stale_for_authority_only(row, auth_parsed):
                    return Response({'error': 'Approval authority stale.', 'consumed': False}, status=status.HTTP_409_CONFLICT)
            else:
                if row.agent_id is None:
                    return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
                if approval_row_stale_for_agent(row.agent, row):
                    return Response({'error': 'Approval authority stale.', 'consumed': False}, status=status.HTTP_409_CONFLICT)
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


def _destructive_call_log_outcome_error(*, outcome: str, approval_id: uuid.UUID | None) -> str | None:
    """Status rules for a destructive call log. Fingerprint match is checked by the caller.

    ``allowed`` and ``failed`` require an approved or executed destructive row (consume leaves
    ``executed``). ``denied`` and ``waiting_approval`` are not execution: approval is optional, and
    when present the row must be pending or rejected. ``session_used`` is never a destructive audit.
    """
    if outcome == OUTCOME_SESSION_USED:
        return 'session_used is not allowed for destructive access_kind.'
    if outcome in (OUTCOME_ALLOWED, OUTCOME_FAILED):
        if approval_id is None:
            return 'approval_id required for destructive tools.'
        appr = McpApprovalRequest.objects.get(pk=approval_id)
        if not appr.is_destructive:
            return 'approval_id must reference a destructive approval for destructive access_kind.'
        if appr.status not in (
            McpApprovalRequest.STATUS_APPROVED,
            McpApprovalRequest.STATUS_EXECUTED,
        ):
            return 'approval must be approved or executed for destructive call log.'
        return None
    if outcome in (OUTCOME_DENIED, OUTCOME_WAITING_APPROVAL):
        if approval_id is None:
            return None
        appr = McpApprovalRequest.objects.get(pk=approval_id)
        if not appr.is_destructive:
            return 'approval_id must reference a destructive approval for destructive access_kind.'
        if appr.status not in (
            McpApprovalRequest.STATUS_PENDING,
            McpApprovalRequest.STATUS_REJECTED,
        ):
            return 'denied or waiting_approval cannot reference an approved or executed destructive approval.'
        return None
    return 'Invalid outcome for destructive access_kind.'


def _call_log_matches_approval_row(agent: Agent, appr: McpApprovalRequest) -> bool:
    if appr.agent_id is None or appr.company_id is None:
        return False
    if str(appr.agent_id) != str(agent.id) or int(appr.company_id) != int(agent.company_id):
        return False
    if int(getattr(appr, 'authority_grant_version', 0) or 0) != int(agent.grant_version or 0):
        return False
    agc = getattr(agent, 'global_company_id', None)
    agcb = getattr(agent, 'company_binding_version', None)
    snap_gc = getattr(appr, 'authority_global_company_id', None)
    snap_cb = getattr(appr, 'authority_company_binding_version', None)
    if agc is None:
        return snap_gc is None and snap_cb is None
    return snap_gc == agc and snap_cb is not None and int(snap_cb) == int(agcb or 0)


class McpInternalCallLogView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        try:
            verify_caller_assertion(
                _assertion_from_request(request),
                audience=CALL_LOG_AUDIENCE,
                scope=CALL_LOG_SCOPE,
                target=_identity_origin(),
            )
        except InternalAssertionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        body = request.data if isinstance(request.data, dict) else {}
        agent_id = str(body.get('agent_id') or '')
        company_id_raw = body.get('company_id')
        cid = strict_json_int_for_company_id(company_id_raw)
        if not agent_id or cid is None:
            return Response({'error': 'agent_id and company_id required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            agent = Agent.objects.get(pk=agent_id, company_id=cid)
        except Agent.DoesNotExist:
            return Response({'error': 'Agent not found.'}, status=status.HTTP_404_NOT_FOUND)
        gv_body = strict_non_negative_int(body.get('grant_version'))
        if gv_body is None:
            return Response({'error': 'grant_version required in JSON body.'}, status=status.HTTP_400_BAD_REQUEST)
        raw_gc_body = body.get('global_company_id')
        raw_cb_body = body.get('company_binding_version')
        delegated = agent.global_agent_id is not None
        if delegated:
            if raw_gc_body is None or raw_gc_body == '':
                return Response(
                    {'error': 'global_company_id required for delegated agents.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            cb_body = strict_non_negative_int(raw_cb_body)
            if cb_body is None:
                return Response(
                    {'error': 'company_binding_version required for delegated agents.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if type(raw_gc_body) is not str or not str(raw_gc_body).strip():
                return Response({'error': 'global_company_id must be a uuid string.'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                gc_body = uuid.UUID(str(raw_gc_body).strip())
            except (ValueError, TypeError):
                return Response({'error': 'Invalid global_company_id.'}, status=status.HTTP_400_BAD_REQUEST)
            row_gc = getattr(agent, 'global_company_id', None)
            row_cb = getattr(agent, 'company_binding_version', None)
            if row_gc is None or row_cb is None:
                return Response({'error': 'Agent has no SaaS company binding.'}, status=status.HTTP_404_NOT_FOUND)
            if (
                int(gv_body) != int(agent.grant_version or 0)
                or gc_body != row_gc
                or int(cb_body) != int(row_cb)
            ):
                return Response({'error': 'Call log authority mismatch.'}, status=status.HTTP_409_CONFLICT)
        else:
            if raw_gc_body not in (None, '') or raw_cb_body not in (None, ''):
                return Response(
                    {'error': 'global_company_id and company_binding_version apply to delegated agents only.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if int(gv_body) != int(agent.grant_version or 0):
                return Response({'error': 'Call log authority mismatch.'}, status=status.HTTP_409_CONFLICT)
        if 'arguments' in body:
            return Response({'error': 'arguments not accepted.'}, status=status.HTTP_400_BAD_REQUEST)
        if 'arguments_redacted' in body:
            return Response({'error': 'arguments_redacted not accepted.'}, status=status.HTTP_400_BAD_REQUEST)
        ip_raw = str(body.get('client_ip') or '').strip()
        client_ip = ip_raw if ip_raw else None
        result = str(body.get('result') or '')[:32]
        status_code = int(body.get('status') or 0)
        duration_ms = int(body.get('duration_ms') or 0)
        tool_s = str(body.get('tool') or '')[:255]
        method_s = str(body.get('method') or '')[:10]
        path_s = str(body.get('path') or '')[:500]
        path_s = path_s.split('?', 1)[0].split('#', 1)[0].strip()[:500]
        outcome_raw = str(body.get('outcome') or '').strip().lower()
        normalized = canonical_outcome_ingest(outcome_raw or None)
        if outcome_raw and normalized is None:
            return Response({'error': 'Invalid outcome.'}, status=status.HTTP_400_BAD_REQUEST)
        if not outcome_raw and normalized is None:
            return Response({'error': 'outcome required.'}, status=status.HTTP_400_BAD_REQUEST)
        outcome = normalized or ''
        if body.get('operation_title') not in (None, ''):
            return Response({'error': 'operation_title not accepted.'}, status=status.HTTP_400_BAD_REQUEST)
        operation_title = safe_operation_title(tool_s)
        access_kind = str(body.get('access_kind') or '').strip().lower()[:32]
        if access_kind not in ('read', 'write', 'destructive', 'unknown', ''):
            return Response({'error': 'Invalid access_kind.'}, status=status.HTTP_400_BAD_REQUEST)
        if not access_kind:
            access_kind = 'unknown'
        destructive_write = bool(access_kind == 'destructive')
        if body.get('resource_label') not in (None, ''):
            return Response({'error': 'resource_label not accepted.'}, status=status.HTTP_400_BAD_REQUEST)
        service_id_raw = str(body.get('service') or '')[:32]
        resource_label = fixed_resource_label_for_service(
            service_id=service_id_raw, method=method_s, path=path_s
        )
        if resource_label is None:
            return Response({'error': 'Invalid path for service.'}, status=status.HTTP_400_BAD_REQUEST)
        company_name = company_name_for_agent(agent)
        if destructive_write and not bool(getattr(agent, 'global_max_destructive', False)):
            return Response(
                {'error': 'Destructive tools are not allowed for this agent.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        approval_uuid: uuid.UUID | None = None
        raw_approval = body.get('approval_id')
        if raw_approval not in (None, ''):
            try:
                approval_uuid = uuid.UUID(str(raw_approval))
            except (ValueError, TypeError):
                return Response({'error': 'Invalid approval_id.'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                appr_try = McpApprovalRequest.objects.get(pk=approval_uuid)
            except McpApprovalRequest.DoesNotExist:
                return Response({'error': 'approval row not found.'}, status=status.HTTP_404_NOT_FOUND)
            if (
                str(appr_try.service or '') != service_id_raw
                or str(appr_try.action or '')[:255] != tool_s[:255]
                or not _call_log_matches_approval_row(agent, appr_try)
            ):
                return Response({'error': 'approval_id does not match this call.'}, status=status.HTTP_400_BAD_REQUEST)

        if destructive_write:
            # Keep access_kind destructive. Do not rewrite the approval row (executed stays executed).
            destructive_err = _destructive_call_log_outcome_error(outcome=outcome, approval_id=approval_uuid)
            if destructive_err is not None:
                return Response({'error': destructive_err}, status=status.HTTP_400_BAD_REQUEST)
        elif approval_uuid is not None:
            appr_nd = McpApprovalRequest.objects.get(pk=approval_uuid)
            if appr_nd.is_destructive:
                return Response(
                    {'error': 'destructive approval_id requires access_kind destructive.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        approval_id = approval_uuid
        error_code_raw = body.get('error_code')
        error_code_val = sanitize_error_code(error_code_raw) or ''
        row = McpCallLog.objects.create(
            agent=agent,
            company_id=cid,
            service=str(body.get('service') or '')[:32],
            tool=tool_s,
            http_method=method_s,
            path=path_s,
            status_code=status_code,
            duration_ms=duration_ms,
            result=result,
            operation_title=operation_title,
            access_kind=access_kind,
            outcome=outcome,
            resource_label=resource_label,
            company_name=company_name,
            approval_id=approval_id,
            error_code=error_code_val,
            client_ip=client_ip,
            arguments_redacted={},
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
