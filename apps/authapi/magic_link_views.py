"""REST and browser endpoints for passwordless magic-link login."""

from __future__ import annotations

import uuid

from django.contrib.auth import get_user_model
from django.db import transaction
from django.http import HttpResponseRedirect
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.actions.magic_link_hooks import emit_magic_link_requested
from apps.actions.user_hooks import emit_user_account_created
from apps.companies.access import apply_company_join
from apps.companies.redirect_allowlist import validate_redirect_to_for_company
from apps.authapi import metrics as auth_metrics
from apps.authapi.login_audit import get_client_ip, record_login_event
from apps.authapi.magic_link import (
    create_magic_link_token,
    magic_link_enabled_for_company,
    redeem_magic_link_token,
)
from apps.authapi.models import LoginEvent
from apps.authapi.serializers import (
    ShellUIMagicLinkConsumeSerializer,
    ShellUIMagicLinkRequestSerializer,
)
from apps.authapi.throttling import check_rate_limit, rate_limit
from apps.authapi.views import (
    _build_oauth_login_redirect,
    _join_denied_response,
    _issue_shellui_tokens,
    _notify_user_logged_in_for_oauth,
    _required_company_from_request,
    _resolve_token_delivery,
)

User = get_user_model()

MAGIC_LINK_PROVIDER = 'magic_link'

_GENERIC_REQUEST_OK = {
    'ok': True,
    'message': (
        'If an account exists for this email and magic link sign-in is allowed, '
        'you will receive a sign-in link shortly.'
    ),
}


def _magic_link_rate_limits(request, *, company_id: int, email: str) -> Response | None:
    ip = get_client_ip(request) or 'unknown'
    buckets = [
        f'ip:{ip}',
        f'email:{email}:{company_id}',
        f'company:{company_id}',
    ]
    for bucket in buckets:
        limited = check_rate_limit(request, scope='magic_link', identity=bucket)
        if limited is not None:
            return limited
    return None


@extend_schema_view(
    post=extend_schema(
        tags=['auth-magic-link'],
        summary='Request a magic sign-in link',
        description=(
            'Send a one-time email sign-in link for the requested company. '
            'Always returns the same success shape when enabled (does not reveal whether the email exists).'
        ),
        auth=[],
        request=ShellUIMagicLinkRequestSerializer,
        responses={
            200: OpenApiResponse(description='Request accepted (email may be sent via Action rules)'),
            403: OpenApiResponse(description='Magic link disabled for this company or deployment'),
        },
    ),
)
@rate_limit('magic_link')
class ShellUIMagicLinkRequestView(APIView):
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request):
        company, company_err = _required_company_from_request(request)
        if company_err:
            return company_err

        if not magic_link_enabled_for_company(company):
            return Response(
                {
                    'error': 'Magic link sign-in is disabled for this company.',
                    'error_code': 'magic_link_disabled',
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = ShellUIMagicLinkRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email'].strip().lower()
        redirect_to, rerr = validate_redirect_to_for_company(
            company=company,
            request=request,
            redirect_to_raw=serializer.validated_data['redirect_to'],
        )
        if rerr or not redirect_to:
            return Response({'error': rerr or 'Invalid redirect_to.'}, status=status.HTTP_400_BAD_REQUEST)

        limited = _magic_link_rate_limits(request, company_id=company.id, email=email)
        if limited is not None:
            return limited

        existing = User.objects.filter(email__iexact=email).first()
        client_tz = serializer.validated_data.get('client_timezone') or ''
        client_dev = serializer.validated_data.get('client_device_id') or None

        row = create_magic_link_token(
            company=company,
            email=email,
            redirect_to=redirect_to,
            user=existing,
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        emit_magic_link_requested(company, row, user=existing)
        return Response(_GENERIC_REQUEST_OK, status=status.HTTP_200_OK)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-magic-link'],
        summary='Verify magic link (browser redirect)',
        description=(
            'Validate a one-time magic link token and redirect to the stored redirect_to with Shellui tokens '
            '(session code or fragment, matching OAUTH_TOKEN_DELIVERY).'
        ),
        auth=[],
        parameters=[
            OpenApiParameter(name='token', type=str, location=OpenApiParameter.QUERY, required=True),
            OpenApiParameter(name='company_id', type=int, location=OpenApiParameter.QUERY, required=True),
        ],
        responses={
            302: OpenApiResponse(description='Redirect to application with tokens or OAuth error params'),
            400: OpenApiResponse(description='Invalid or expired link'),
        },
    ),
    post=extend_schema(
        tags=['auth-magic-link'],
        summary='Consume magic link (JSON tokens)',
        description='Exchange a one-time magic link token for Shellui JWTs (API clients).',
        auth=[],
        request=ShellUIMagicLinkConsumeSerializer,
        responses={
            200: OpenApiResponse(description='Shellui token payload'),
            403: OpenApiResponse(description='Company access denied'),
        },
    ),
)
@rate_limit('magic_link')
class ShellUIMagicLinkVerifyView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return self._consume(request, browser_redirect=True)

    def post(self, request):
        serializer = ShellUIMagicLinkConsumeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self._consume(
            request,
            browser_redirect=False,
            token=serializer.validated_data['token'],
            company_id=serializer.validated_data['company_id'],
        )

    def _consume(
        self,
        request,
        *,
        browser_redirect: bool,
        token: str | None = None,
        company_id: int | None = None,
    ):
        company, company_err = _required_company_from_request(request)
        if company_err and browser_redirect:
            return Response({'error': 'company_id is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if company_err:
            return company_err

        if not magic_link_enabled_for_company(company):
            return Response(
                {
                    'error': 'Magic link sign-in is disabled for this company.',
                    'error_code': 'magic_link_disabled',
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        raw_token = token if token is not None else request.GET.get('token')
        cid = company_id if company_id is not None else company.id
        if company.id != cid:
            return Response({'error': 'company_id mismatch.'}, status=status.HTTP_400_BAD_REQUEST)

        row, err = redeem_magic_link_token(raw_token=raw_token or '', company_id=cid)
        if err or row is None:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=MAGIC_LINK_PROVIDER,
                user=None,
                company=company,
                failure_reason=err or 'invalid_token',
            )
            return Response({'error': err or 'Invalid link.'}, status=status.HTTP_400_BAD_REQUEST)

        redirect_to = row.redirect_to
        client_tz = row.client_timezone or ''
        client_dev = row.client_device_id

        user = row.user
        created = False
        if user is None:
            user = User.objects.filter(email__iexact=row.email).first()
        if user is None:
            local = row.email.split('@', 1)[0] or 'user'
            username = f'magic_{local}_{uuid.uuid4().hex[:8]}'
            user = User(username=username, email=row.email)
            user.set_unusable_password()
            user.save()
            created = True
            row.user = user
            row.save(update_fields=['user'])

        if created:
            emit_user_account_created(company, user, source='magic_link')

        join = apply_company_join(company, user, email=row.email)
        if not join.allowed:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=MAGIC_LINK_PROVIDER,
                user=user,
                company=company,
                failure_reason=join.error_code or 'access_denied',
                client_timezone=client_tz,
                client_device_id=client_dev,
            )
            if browser_redirect:
                return _join_denied_response(decision=join, redirect_to=redirect_to)
            return _join_denied_response(decision=join)

        _notify_user_logged_in_for_oauth(request, user)
        payload = _issue_shellui_tokens(user, company=company, oauth_provider=MAGIC_LINK_PROVIDER)
        auth_metrics.record_successful_login(MAGIC_LINK_PROVIDER, company_id=company.id)
        record_login_event(
            request=request,
            outcome=LoginEvent.OUTCOME_SUCCESS,
            provider=MAGIC_LINK_PROVIDER,
            user=user,
            company=company,
            client_timezone=client_tz,
            client_device_id=client_dev,
        )

        if browser_redirect:
            delivery_mode = _resolve_token_delivery(request=request)
            location = _build_oauth_login_redirect(
                user=user,
                company=company,
                redirect_to=redirect_to,
                payload=payload,
                provider=MAGIC_LINK_PROVIDER,
                token_delivery=delivery_mode,
            )
            return HttpResponseRedirect(location)

        return Response(payload, status=status.HTTP_200_OK)
