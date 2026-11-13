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
    REVOCATION_AUDIENCE,
    REVOCATION_SCOPE,
    InternalAssertionError,
)
from apps.agents.approval_audit import record_approval_expired_once
from apps.agents.approval_decisions import (
    ApprovalDecisionError,
    ConsentFieldError,
    client_allow,
    client_allow_session,
    client_deny,
    lock_approval_for_update,
    parse_decision_consent,
)
from apps.agents.approval_internal import (
    approval_binding_from_claims,
    approval_lookup_filter,
    lookup_approval_row,
    public_approval_status,
)
from apps.agents.approval_links import approval_link
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
from apps.agents.json_strict import strict_json_int_for_company_id, strict_non_negative_int
from apps.agents.mcp_claims import strict_bool_claim
from apps.agents.models import Agent, GlobalAgentRevocation, McpApprovalRequest
from apps.agents.revocation import (
    REVOCATION_CACHE_SECONDS,
    active_max_grant_version,
    blocked_agent_ids,
    regional_agent_snapshots,
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
        agents = regional_agent_snapshots(company_id=cid)
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
            'max_active_grant_version': max_gv,
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


_ARGUMENTS_SUMMARY_MAX = 500


def _arguments_summary_from_body(body: dict) -> tuple[str, Response | None]:
    """Optional plain-text summary. Raw argument objects stay rejected."""
    if 'arguments_summary' not in body:
        return '', None
    raw = body.get('arguments_summary')
    if not isinstance(raw, str):
        return '', Response(
            {'error': 'arguments_summary must be a string.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    text = ''.join(ch for ch in raw if ch in '\n\t' or ord(ch) >= 32)
    text = ' '.join(text.split())
    if len(text) > _ARGUMENTS_SUMMARY_MAX:
        return '', Response(
            {'error': 'arguments_summary must be at most 500 characters.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    return text, None


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
        arguments_summary, summary_err = _arguments_summary_from_body(body)
        if summary_err is not None:
            return summary_err
        service_id = (binding['service'] or '')[:32]
        action_slug = (binding['action'] or '')[:255]
        target = f'{service_id}:{action_slug}'[:500] if service_id or action_slug else ''
        short_action_summary = arguments_summary
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
            elif short_action_summary and not (row.short_action_summary or '').strip():
                row.short_action_summary = short_action_summary
                row.save(update_fields=['short_action_summary'])
        link = approval_link(str(row.id), request=request)
        return Response(
            {
                'id': str(row.id),
                'status': row.status,
                'expires_at': row.expires_at.isoformat(),
                'is_destructive': row.is_destructive,
                'fallback_path': link['fallback_path'],
                'approval_url': link['approval_url'],
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
        link = approval_link(str(row.id), request=request)
        return Response(
            {
                'id': str(row.id),
                'status': public_status,
                'expires_at': row.expires_at.isoformat(),
                'is_destructive': bool(row.is_destructive),
                'approval_url': link['approval_url'],
            }
        )


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
            consent, client_name = parse_decision_consent(body)
        except ConsentFieldError as exc:
            return Response({'error': exc.message}, status=status.HTTP_400_BAD_REQUEST)
        try:
            if decision in ('allow', 'approve'):
                result = client_allow(row, actor_email=actor_email, consent=consent, client_name=client_name)
            elif decision in ('deny', 'reject'):
                result = client_deny(row, actor_email=actor_email, consent=consent, client_name=client_name)
            elif decision in ('allow_session', 'session'):
                result = client_allow_session(
                    row,
                    connection_id=connection_id,
                    actor_email=actor_email,
                    caller_name=caller.name,
                    assertion_claims=claims,
                    consent=consent,
                    client_name=client_name,
                )
            else:
                return Response({'error': 'decision must be allow, deny, or allow_session.'}, status=status.HTTP_400_BAD_REQUEST)
        except ApprovalDecisionError as exc:
            return Response({'error': exc.message}, status=exc.status)
        payload = {
            'approval_id': str(result.row.id),
            'status': result.row.status,
            'audit_status': result.audit_status,
        }
        if result.row.consent:
            payload['consent'] = result.row.consent
        if result.row.client_name:
            payload['client_name'] = result.row.client_name
        return Response(payload)


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
                row = lock_approval_for_update(**flt)
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
