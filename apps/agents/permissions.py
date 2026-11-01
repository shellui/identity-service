"""Company owner / staff checks for MCP admin APIs."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from apps.authapi.authentication import ShellUIJWTAuthentication


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
    from apps.authapi.views import _require_staff_or_company_owner

    if not allow_agent_token and _bearer_agent_id(request):
        return None, None, Response({'error': 'Agents cannot perform this action.'}, status=status.HTTP_403_FORBIDDEN)
    return _require_staff_or_company_owner(request)
