"""List and revoke the current user's app refresh sessions for one company."""

from __future__ import annotations

from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.agents.mcp_signin import is_company_member
from apps.authapi.models import RefreshTokenSession
from apps.authapi.permissions import ShellUIPermission
from apps.authapi.refresh_sessions import denylist_access_jti, revoke_refresh_session
from apps.authapi.serializers import ShellUIOpenAPISerializer
from apps.companies.models import Company


class SessionRowSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    kind = serializers.CharField()
    user_agent = serializers.CharField()
    created_at = serializers.DateTimeField()
    expires_at = serializers.DateTimeField()
    current = serializers.BooleanField()


class SessionListSerializer(serializers.Serializer):
    sessions = SessionRowSerializer(many=True)


def _session_context(request):
    """Return ``(user, company, sid, error response)``."""
    auth = getattr(request, 'auth', None)
    if auth is None or not hasattr(auth, 'get'):
        return None, None, '', Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    if auth.get('pat_id') or auth.get('agent_id'):
        return None, None, '', Response(
            {'error': 'Use an app session token to manage sessions.'},
            status=status.HTTP_403_FORBIDDEN,
        )
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        return None, None, '', Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    raw_company = auth.get('company_id')
    try:
        company_id = int(raw_company)
    except (TypeError, ValueError):
        return None, None, '', Response({'error': 'Missing company_id.'}, status=status.HTTP_400_BAD_REQUEST)
    company = Company.objects.filter(pk=company_id).first()
    if company is None:
        return None, None, '', Response({'error': 'Company not found.'}, status=status.HTTP_404_NOT_FOUND)
    if not is_company_member(company, user):
        return None, None, '', Response({'error': 'Forbidden for this company.'}, status=status.HTTP_403_FORBIDDEN)
    return user, company, str(auth.get('sid') or ''), None


def _session_payload(row: RefreshTokenSession, *, current_sid: str) -> dict:
    return {
        'id': str(row.id),
        'kind': row.kind or '',
        'user_agent': row.user_agent or '',
        'created_at': row.created_at.isoformat(),
        'expires_at': row.expires_at.isoformat(),
        'current': str(row.id) == current_sid,
    }


@extend_schema_view(
    get=extend_schema(
        tags=['auth-session'],
        operation_id='api_v1_sessions_list',
        summary='List app sessions for the current user',
        description=(
            'Active refresh sessions for the authenticated user in the token company. '
            'A Shellui CLI device login has `kind` `cli` and the user agent captured when the CLI '
            'requested a device code. Other app sessions have an empty `kind`. '
            'Revoke one with `POST /api/v1/sessions/{id}/revoke`. Personal access tokens and MCP '
            'agent tokens are not listed here.'
        ),
        responses={
            200: SessionListSerializer,
            401: OpenApiResponse(description='Missing or invalid bearer token'),
            403: OpenApiResponse(description='Not a member of this company, or the token is not an app session'),
        },
    ),
)
class ShellUISessionListView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        user, company, sid, err = _session_context(request)
        if err is not None:
            return err
        now = timezone.now()
        rows = RefreshTokenSession.objects.filter(
            user=user,
            company=company,
            revoked_at__isnull=True,
            expires_at__gt=now,
        ).order_by('-created_at')
        return Response({'sessions': [_session_payload(row, current_sid=sid) for row in rows]})


@extend_schema_view(
    post=extend_schema(
        tags=['auth-session'],
        operation_id='api_v1_sessions_revoke',
        summary='Revoke one app session',
        description=(
            'Revoke one refresh session that belongs to the authenticated user in the token company. '
            'Later refresh attempts for that session fail. When the session is the current session '
            'of this access token, that access token is revoked as well.'
        ),
        request=None,
        responses={
            200: OpenApiResponse(description='`{"revoked": true}`'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
            403: OpenApiResponse(description='Not a member of this company, or the token is not an app session'),
            404: OpenApiResponse(description='Session not found'),
        },
    ),
)
class ShellUISessionRevokeView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def post(self, request, session_id):
        user, company, sid, err = _session_context(request)
        if err is not None:
            return err
        row = RefreshTokenSession.objects.filter(pk=session_id, user=user, company=company).first()
        if row is None or row.revoked_at is not None:
            return Response({'error': 'Session not found.'}, status=status.HTTP_404_NOT_FOUND)
        if sid and str(row.id) == sid:
            auth = request.auth
            access_jti = auth.get('jti') if hasattr(auth, 'get') else None
            access_exp = auth.get('exp') if hasattr(auth, 'get') else None
            if access_jti and access_exp is not None:
                denylist_access_jti(str(access_jti), exp_unix=int(access_exp))
        revoke_refresh_session(row)
        return Response({'revoked': True})
