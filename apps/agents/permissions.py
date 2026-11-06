"""Company owner / staff checks for MCP admin APIs."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from apps.authapi.authentication import ShellUIJWTAuthentication
from apps.agents.json_strict import decode_jwt_payload_unverified
from apps.agents.staff import is_mcp_oauth_refused_user


def _validated_bearer_claims(request) -> dict | None:
    """Return validated JWT claims when present (may be user or MCP agent token)."""
    auth = ShellUIJWTAuthentication()
    try:
        result = auth.authenticate(request)
    except (InvalidToken, TokenError):
        return None
    if not result:
        return None
    _user, validated = result
    return validated if isinstance(validated, dict) else None


def _agent_access_from_bearer(request) -> dict | None:
    """Agent access claims from Bearer (validated first, else unverified parse for routing)."""
    vc = _validated_bearer_claims(request)
    if vc and vc.get('agent_id') and str(vc.get('token_type') or '') == 'access':
        return vc
    auth = request.META.get('HTTP_AUTHORIZATION') or ''
    if hasattr(request, 'headers') and not auth:
        auth = request.headers.get('Authorization') or ''
    if not auth.lower().startswith('bearer '):
        return None
    raw = auth[7:].strip()
    claims = decode_jwt_payload_unverified(raw)
    if not claims or not claims.get('agent_id'):
        return None
    if str(claims.get('token_type') or '') != 'access':
        return None
    if not str(claims.get('sub') or '').startswith('agent:'):
        return None
    return claims


def require_company_admin(request, *, allow_agent_token: bool = True):
    from apps.authapi.views import (
        _authenticate_bearer_user,
        _is_user_company_owner,
        _required_company_from_request,
    )
    from apps.companies.access import is_company_access_enabled

    if not allow_agent_token and _agent_access_from_bearer(request):
        return None, None, Response({'error': 'Agents cannot perform this action.'}, status=status.HTTP_403_FORBIDDEN)
    user = _authenticate_bearer_user(request)
    if not user:
        return None, None, Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    if is_mcp_oauth_refused_user(user):
        return None, None, Response({'error': 'Staff accounts cannot use MCP company APIs.'}, status=status.HTTP_403_FORBIDDEN)
    company, cerr = _required_company_from_request(request, user=user)
    if cerr:
        return None, None, cerr
    if not _is_user_company_owner(user, company):
        return None, None, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
    if not is_company_access_enabled(company, user):
        return None, None, Response(
            {'error': 'Company access is disabled for this user.'},
            status=status.HTTP_403_FORBIDDEN,
        )
    return user, company, None


def require_company_member(request, *, allow_agent_token: bool = False):
    from apps.authapi.views import _authenticate_bearer_user, _required_company_from_request
    from apps.agents.mcp_signin import is_company_member
    from apps.companies.access import is_company_access_enabled

    if not allow_agent_token and _agent_access_from_bearer(request):
        return None, None, Response({'error': 'Agents cannot perform this action.'}, status=status.HTTP_403_FORBIDDEN)
    user = _authenticate_bearer_user(request)
    if not user:
        return None, None, Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    if is_mcp_oauth_refused_user(user):
        return None, None, Response({'error': 'Staff accounts cannot use MCP company APIs.'}, status=status.HTTP_403_FORBIDDEN)
    company, cerr = _required_company_from_request(request, user=user)
    if cerr:
        return None, None, cerr
    if not is_company_member(company, user):
        return None, None, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
    if not is_company_access_enabled(company, user):
        return None, None, Response(
            {'error': 'Company access is disabled for this user.'},
            status=status.HTTP_403_FORBIDDEN,
        )
    return user, company, None


def require_approval_actor(request, *, allow_agent_token: bool = False):
    """Company owners or the member who created the agent (Settings and fallback)."""
    user, company, err = require_company_member(request, allow_agent_token=allow_agent_token)
    if err:
        return None, None, err
    return user, company, None
