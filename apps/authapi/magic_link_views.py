"""REST and browser endpoints for passwordless magic-link login."""

from __future__ import annotations

import logging
import uuid

from urllib.parse import urlencode

from allauth.account.adapter import get_adapter as get_account_adapter
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.actions.email_client import TEMPLATE_MAGIC_LINK, EmailUnavailable, RecipientSuppressed
from apps.actions.magic_link_hooks import emit_magic_link_requested
from apps.authapi.email_delivery import AuthEmailError, deliver_magic_link_email, has_enabled_webhook_rule
from apps.actions.user_hooks import emit_user_account_created
from apps.companies.access import (
    apply_company_join,
    invitation_revoked_decision,
    is_login_blocked_by_revoked_invitation,
)
from apps.companies.redirect_allowlist import validate_redirect_to_for_company
from apps.authapi import metrics as auth_metrics
from apps.authapi.login_audit import (
    LoginOutcome,
    client_ip_rate_limit_key,
    get_client_ip,
    record_login_event,
)
from apps.authapi.magic_link import (
    create_magic_link_token,
    lookup_magic_link_token,
    magic_link_enabled_for_company,
    normalize_magic_link_language,
    redeem_magic_link_token,
)
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
logger = logging.getLogger(__name__)

MAGIC_LINK_PROVIDER = 'magic_link'

_GENERIC_REQUEST_OK = {
    'ok': True,
    'message': (
        'If an account exists for this email and magic link sign-in is allowed, '
        'you will receive a sign-in link shortly.'
    ),
}


def _create_magic_link_user(request, *, email: str):
    """Create a user whose username is derived from the email local part (``ada`` for ``ada@acme.com``)."""
    adapter = get_account_adapter(request)
    local_part = email.split('@', 1)[0].split('+', 1)[0]
    for _attempt in range(3):
        username = adapter.generate_unique_username([local_part, email, 'user'])
        user = User(username=username, email=email)
        user.set_unusable_password()
        try:
            with transaction.atomic():
                user.save()
        except IntegrityError:
            # Another sign-up claimed the same username between lookup and insert.
            continue
        return user
    user = User(username=f'user_{uuid.uuid4().hex[:12]}', email=email)
    user.set_unusable_password()
    user.save()
    return user


def _magic_link_rate_limits(request, *, company_id: int, email: str) -> Response | None:
    ip = client_ip_rate_limit_key(get_client_ip(request))
    buckets = [
        f'ip:{ip}',
        f'email:{email}:{company_id}',
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
            400: OpenApiResponse(description='`auth_link_missing` or `auth_link_host_not_allowed`'),
            403: OpenApiResponse(description='Magic link disabled for this company or deployment'),
            409: OpenApiResponse(description='`provider_not_configured` or `platform_sender_not_allowed`'),
            422: OpenApiResponse(description='`recipient_suppressed`'),
            429: OpenApiResponse(description='`company_rate_limited` or `recipient_rate_limited`'),
            503: OpenApiResponse(description='`email_unavailable`'),
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
        if is_login_blocked_by_revoked_invitation(company, email, existing):
            return Response(_GENERIC_REQUEST_OK, status=status.HTTP_200_OK)
        client_tz = serializer.validated_data.get('client_timezone') or ''
        client_dev = serializer.validated_data.get('client_device_id') or None

        row, raw_token = create_magic_link_token(
            company=company,
            email=email,
            redirect_to=redirect_to,
            user=existing,
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        requested_lang = normalize_magic_link_language(serializer.validated_data.get('language'))
        pref_lang = None
        if existing is not None:
            pref = getattr(existing, 'preference', None)
            if pref is not None:
                pref_lang = getattr(pref, 'language', None)
        request_base_url = request.build_absolute_uri('/')
        mail_language = requested_lang or pref_lang
        webhook_delivers = has_enabled_webhook_rule(company, TEMPLATE_MAGIC_LINK)

        def _send_mail() -> None:
            deliver_magic_link_email(
                row=row,
                company=company,
                user=existing,
                language=mail_language,
                raw_token=raw_token,
                fallback_base_url=request_base_url,
            )

        if not webhook_delivers:
            try:
                deliver_magic_link_email(
                    row=row,
                    company=company,
                    user=existing,
                    language=mail_language,
                    raw_token=raw_token,
                    fallback_base_url=request_base_url,
                )
            except RecipientSuppressed:
                transaction.set_rollback(True)
                return Response({'error_code': 'recipient_suppressed'}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
            except AuthEmailError as exc:
                transaction.set_rollback(True)
                return Response({'error_code': exc.error_code}, status=exc.status)
            except EmailUnavailable:
                logger.warning(
                    'magic_link_email_failed company_id=%s request_id=%s',
                    company.pk,
                    row.pk,
                )
                transaction.set_rollback(True)
                return Response({'error_code': 'email_unavailable'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        def _after_commit() -> None:
            try:
                queued = emit_magic_link_requested(
                    company,
                    row,
                    user=existing,
                    raw_token=raw_token,
                    fallback_base_url=request_base_url,
                    language=requested_lang,
                )
            except Exception:  # noqa: BLE001
                logger.warning(
                    'magic_link_webhook_emit_failed company_id=%s request_id=%s',
                    company.pk,
                    row.pk,
                )
                if not webhook_delivers:
                    return
                try:
                    _send_mail()
                except Exception:  # noqa: BLE001
                    logger.warning(
                        'magic_link_email_failed company_id=%s request_id=%s',
                        company.pk,
                        row.pk,
                    )
                return
            if queued or not webhook_delivers:
                return
            try:
                _send_mail()
            except Exception:  # noqa: BLE001
                logger.warning(
                    'magic_link_email_failed company_id=%s request_id=%s',
                    company.pk,
                    row.pk,
                )

        transaction.on_commit(_after_commit)
        return Response(_GENERIC_REQUEST_OK, status=status.HTTP_200_OK)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-magic-link'],
        summary='Open magic link (browser)',
        description=(
            'Returns a page that submits itself (POST) right away in a browser, so the user is '
            'signed in and redirected without clicking. Does not consume the token, so email link '
            'scanners that only fetch the URL do not burn it. Without JavaScript the page shows a '
            '"Continue sign-in" button.'
        ),
        auth=[],
        parameters=[
            OpenApiParameter(name='token', type=str, location=OpenApiParameter.QUERY, required=True),
            OpenApiParameter(name='company_id', type=int, location=OpenApiParameter.QUERY, required=True),
        ],
        responses={
            200: OpenApiResponse(description='HTML page that auto-submits the sign-in form'),
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
@method_decorator(csrf_protect, name='dispatch')
@rate_limit('magic_link')
class ShellUIMagicLinkVerifyView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
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
        raw_token = request.GET.get('token') or ''
        row, err = lookup_magic_link_token(raw_token=raw_token, company_id=company.id)
        if err or row is None:
            return render(
                request,
                'authapi/magic_link_confirm.html',
                {
                    'error_message': err or 'Invalid link.',
                    'company_name': company.name,
                    'email': '',
                    'token': '',
                    'company_id': company.id,
                    'form_action': request.build_absolute_uri(
                        '?' + urlencode({'company_id': str(company.id)})
                    ),
                },
                status=400,
            )
        form_action = request.build_absolute_uri('?' + urlencode({'company_id': str(company.id)}))
        return render(
            request,
            'authapi/magic_link_confirm.html',
            {
                'error_message': None,
                'company_name': company.name,
                'email': row.email,
                'token': raw_token,
                'company_id': company.id,
                'form_action': form_action,
            },
        )

    def post(self, request):
        content_type = (request.content_type or '').lower()
        if 'application/json' in content_type:
            serializer = ShellUIMagicLinkConsumeSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            return self._consume(
                request,
                browser_redirect=False,
                token=serializer.validated_data['token'],
                company_id=serializer.validated_data['company_id'],
            )
        token = (request.POST.get('token') or '').strip()
        try:
            company_id = int(request.POST.get('company_id') or '')
        except (TypeError, ValueError):
            return Response({'error': 'Missing or invalid company_id.'}, status=status.HTTP_400_BAD_REQUEST)
        return self._consume(
            request,
            browser_redirect=True,
            token=token,
            company_id=company_id,
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
                outcome=LoginOutcome.FAILURE,
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
        if is_login_blocked_by_revoked_invitation(company, row.email, user):
            join = invitation_revoked_decision()
            record_login_event(
                request=request,
                outcome=LoginOutcome.FAILURE,
                provider=MAGIC_LINK_PROVIDER,
                user=user,
                company=company,
                failure_reason=join.error_code,
                client_timezone=client_tz,
                client_device_id=client_dev,
            )
            if browser_redirect:
                return _join_denied_response(decision=join, redirect_to=redirect_to)
            return _join_denied_response(decision=join)
        if user is None:
            user = _create_magic_link_user(request, email=row.email)
            created = True
            row.user = user
            row.save(update_fields=['user'])

        if created:
            emit_user_account_created(company, user, source='magic_link')

        join = apply_company_join(company, user, email=row.email)
        if not join.allowed:
            record_login_event(
                request=request,
                outcome=LoginOutcome.FAILURE,
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
            outcome=LoginOutcome.SUCCESS,
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
