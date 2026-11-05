"""Company owner / staff checks for MCP admin APIs."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from apps.authapi.authentication import ShellUIJWTAuthentication
from apps.agents.staff import is_mcp_oauth_refused_user


def _bearer_agent_id(request) -> str | None:
    token = getattr(request, 'auth', None)
    if token is not None and hasattr(token, 'get') and token.get('agent_id'):
        return str(token.get('agent_id'))
    auth = ShellUIJWTAuthentication()
    try:
        result = auth.authenticate(request)
    except (InvalidToken, TokenError):
        return None
    if not result:
        return None
    _user, validated = result
    if validated.get('agent_id'):
        return str(validated.get('agent_id'))
    return None


def require_company_admin(request, *, allow_agent_token: bool = True):
    from apps.authapi.views import (
        _authenticate_bearer_user,
        _is_user_company_owner,
        _required_company_from_request,
    )
    from apps.companies.access import is_company_access_enabled

    if not allow_agent_token and _bearer_agent_id(request):
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

    if not allow_agent_token and _bearer_agent_id(request):
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
