"""Best-effort wake for ai-service waiters after an MCP approval is decided."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any

import jwt
import requests
from django.conf import settings
from rest_framework_simplejwt.settings import api_settings

from apps.agents.approval_internal import public_approval_status
from apps.agents.models import McpApprovalRequest

logger = logging.getLogger(__name__)

APPROVAL_DECIDED_AUDIENCE = 'shellui-mcp-approval-decided'
APPROVAL_DECIDED_SCOPE = 'mcp.approval.decided'
_NOTIFY_PATH = '/internal/mcp-approval-decided'
_NOTIFY_TIMEOUT_SECONDS = 2.0
_ASSERTION_LIFETIME_SECONDS = 60


def schedule_approval_decided_notify(row: McpApprovalRequest) -> None:
    """Queue a non-blocking notify after the current DB transaction commits."""
    from django.db import transaction

    approval_id = str(row.id)
    status = public_approval_status(row, now=row.decided_at or row.expires_at)
    if status not in {'approved', 'denied'}:
        return
    company_id = int(row.company_id) if row.company_id is not None else 0
    agent_id = str(row.agent_id) if row.agent_id is not None else str(row.global_agent_id or '')

    def _run() -> None:
        try:
            notify_ai_approval_decided(
                approval_id=approval_id,
                status=status,
                company_id=company_id,
                agent_id=agent_id,
            )
        except Exception:
            logger.exception('MCP approval decided notify failed approval_id=%s', approval_id)

    transaction.on_commit(lambda: threading.Thread(target=_run, daemon=True).start())


def notify_ai_approval_decided(
    *,
    approval_id: str,
    status: str,
    company_id: int,
    agent_id: str,
) -> bool:
    """POST a short-lived Identity assertion to ai-service. Returns True on 2xx."""
    origin = (getattr(settings, 'AI_SERVICE_URL', '') or '').strip().rstrip('/')
    if not origin:
        return False
    if status not in {'approved', 'denied'}:
        return False
    try:
        token = _sign_decided_assertion(
            approval_id=approval_id,
            status=status,
            company_id=company_id,
            agent_id=agent_id,
            target=f'{origin}{_NOTIFY_PATH}',
        )
    except Exception:
        logger.exception('MCP approval decided assertion failed approval_id=%s', approval_id)
        return False
    url = f'{origin}{_NOTIFY_PATH}'
    try:
        response = requests.post(
            url,
            json={
                'approval_id': approval_id,
                'status': status,
                'company_id': company_id,
                'agent_id': agent_id,
            },
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            timeout=_NOTIFY_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        logger.warning(
            'MCP approval decided notify unreachable approval_id=%s err=%s',
            approval_id,
            type(exc).__name__,
        )
        return False
    if 200 <= response.status_code < 300:
        return True
    logger.warning(
        'MCP approval decided notify status=%s approval_id=%s',
        response.status_code,
        approval_id,
    )
    return False


def _sign_decided_assertion(
    *,
    approval_id: str,
    status: str,
    company_id: int,
    agent_id: str,
    target: str,
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        'iss': (getattr(settings, 'JWT_ISSUER', '') or '').rstrip('/') or 'identity',
        'aud': APPROVAL_DECIDED_AUDIENCE,
        'sub': 'identity',
        'scope': APPROVAL_DECIDED_SCOPE,
        'target': target,
        'approval_id': str(approval_id),
        'status': status,
        'company_id': int(company_id),
        'agent_id': str(agent_id or ''),
        'iat': now,
        'exp': now + _ASSERTION_LIFETIME_SECONDS,
        'jti': uuid.uuid4().hex,
    }
    headers: dict[str, str] = {}
    kid = getattr(settings, 'JWT_ACTIVE_KEY_ID', '') or ''
    if kid:
        headers['kid'] = kid
    token = jwt.encode(
        claims,
        api_settings.SIGNING_KEY,
        algorithm=api_settings.ALGORITHM,
        headers=headers or None,
    )
    return token.decode('utf-8') if isinstance(token, bytes) else token
