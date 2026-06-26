"""Public JWKS endpoint for external JWT verification."""

from __future__ import annotations

from django.conf import settings
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

from .jwks import build_jwks_document


@method_decorator(cache_page(60 * 15), name='dispatch')
class ShellUIJwksView(APIView):
    """Expose the public signing keys used for ShellUI JWT verification."""

    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        tags=['auth-session'],
        summary='JSON Web Key Set (JWKS)',
        description=(
            'Public signing keys for verifying RS256 JWTs issued by identity-service. '
            'Standard location for OIDC-compatible verifiers.'
        ),
        responses={200: OpenApiResponse(description='JWKS document with RSA public keys.')},
    )
    def get(self, request):
        signing_key = getattr(settings, 'JWT_SIGNING_KEY', None)
        if signing_key is None:
            return JsonResponse({'keys': []})

        document = build_jwks_document(
            signing_key,
            getattr(settings, 'JWT_PREVIOUS_VERIFYING_KEYS', []),
        )
        response = JsonResponse(document)
        response['Cache-Control'] = 'public, max-age=900'
        return response
