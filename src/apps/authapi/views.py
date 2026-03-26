import json
import urllib.request

from django.contrib.auth import get_user_model
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .oauth import build_authorize_url, exchange_code_for_token, fetch_provider_userinfo
from .serializers import ProviderAuthorizeSerializer, ProviderCallbackSerializer

User = get_user_model()


def _extract_user_data(provider: str, userinfo: dict, access_token: str) -> tuple[str, str, str]:
    provider_id = str(
        userinfo.get('id')
        or userinfo.get('sub')
        or userinfo.get('userPrincipalName')
        or userinfo.get('mail')
    )
    email = userinfo.get('email') or userinfo.get('mail') or userinfo.get('userPrincipalName')
    full_name = userinfo.get('name') or userinfo.get('displayName') or ''

    if provider == 'github' and not email:
        req = urllib.request.Request(
            'https://api.github.com/user/emails',
            headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
            },
        )
        with urllib.request.urlopen(req, timeout=20) as response:
            emails = json.loads(response.read().decode('utf-8'))
        primary = next((item for item in emails if item.get('primary')), None)
        if primary:
            email = primary.get('email')

    if not email:
        email = f'{provider_id}@{provider}.local'

    if not full_name:
        full_name = email.split('@')[0]

    return provider_id, email.lower(), full_name


def _issue_tokens(user: User) -> dict:
    user_payload = {
        'id': user.id,
        'email': user.email,
        'username': user.get_username(),
        'full_name': user.get_full_name() or user.get_username(),
    }
    refresh = RefreshToken.for_user(user)
    refresh['user'] = user_payload
    access = refresh.access_token
    access['user'] = user_payload
    return {
        'refresh': str(refresh),
        'access': str(access),
        'user': user_payload,
    }


@extend_schema_view(
    get=extend_schema(
        tags=['auth'],
        summary='Get social provider authorize URL',
        description='Generate an OAuth2 authorize URL for GitHub, Google, or Microsoft.',
        responses={200: OpenApiResponse(description='Authorization URL generated')},
    )
)
class SocialAuthorizeView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, provider: str):
        serializer = ProviderAuthorizeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        authorize_url = build_authorize_url(
            provider=provider,
            redirect_uri=serializer.validated_data['redirect_uri'],
        )
        return Response({'provider': provider, 'authorize_url': authorize_url})


@extend_schema_view(
    post=extend_schema(
        tags=['auth'],
        summary='Login with social provider',
        description='Exchange OAuth code and return JWT tokens plus user profile.',
        request=ProviderCallbackSerializer,
        responses={200: OpenApiResponse(description='Authenticated successfully')},
    )
)
class SocialLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, provider: str):
        serializer = ProviderCallbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            access_token = exchange_code_for_token(
                provider=provider,
                code=serializer.validated_data['code'],
                redirect_uri=serializer.validated_data['redirect_uri'],
            )
            userinfo = fetch_provider_userinfo(provider, access_token)
            provider_id, email, full_name = _extract_user_data(provider, userinfo, access_token)
        except Exception as exc:
            return Response(
                {'detail': str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': f'{provider}_{provider_id}',
                'first_name': full_name.split(' ')[0],
                'last_name': ' '.join(full_name.split(' ')[1:]),
            },
        )
        if not created:
            if not user.first_name and full_name:
                user.first_name = full_name.split(' ')[0]
            if not user.last_name and ' ' in full_name:
                user.last_name = ' '.join(full_name.split(' ')[1:])
            user.save(update_fields=['first_name', 'last_name'])

        token_payload = _issue_tokens(user)
        return Response(token_payload, status=status.HTTP_200_OK)
