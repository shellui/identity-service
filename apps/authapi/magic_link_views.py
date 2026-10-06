"""REST and browser endpoints for passwordless magic-link login."""

from __future__ import annotations

import logging
import uuid
from types import SimpleNamespace
from urllib.parse import urlencode

from allauth.account.adapter import get_adapter as get_account_adapter
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation.trans_real import parse_accept_lang_header
from django.views.decorators.csrf import csrf_protect
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.actions.email_client import EmailUnavailable, RecipientSuppressed
from apps.actions.magic_link_hooks import emit_magic_link_requested
from apps.authapi.email_delivery import (
    AuthEmailError,
    deliver_magic_link_email,
    deliver_staff_magic_link_notice,
)
from apps.actions.user_hooks import emit_user_account_created
from apps.companies.access import (
    apply_company_join,
    invitation_revoked_decision,
    is_login_blocked_by_revoked_invitation,
)
from apps.companies.redirect_allowlist import append_oauth_error_params, validate_redirect_to_for_company
from apps.authapi import metrics as auth_metrics
from apps.authapi.login_audit import (
    LoginOutcome,
    client_ip_rate_limit_key,
    get_client_ip,
    record_login_event,
)
from apps.authapi.magic_link import (
    MAGIC_LINK_STAFF_DISABLED,
    MAGIC_LINK_STAFF_DISABLED_MESSAGE,
    create_magic_link_token,
    delete_unused_magic_link_tokens_for_user,
    is_staff_account,
    lookup_magic_link_token,
    magic_link_enabled_for_company,
    magic_link_row_is_for_staff,
    magic_link_ttl,
    normalize_magic_link_language,
    redeem_magic_link_token,
    sign_in_page_url,
    staff_account_for_email,
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


# Shown by the verify page (GET) when the link belongs to a staff account.
_STAFF_DISABLED_PAGE = {
    'en': {
        'title': 'Sign-in links are off for staff accounts',
        'body': (
            "For security, staff accounts can't sign in with an email link. "
            'Sign in with your usual sign-in method instead.'
        ),
        'button': 'Go to sign-in',
    },
    'fr': {
        'title': 'Les liens de connexion sont désactivés pour les comptes staff',
        'body': (
            'Par sécurité, les comptes staff ne peuvent pas se connecter avec un lien envoyé par e-mail. '
            'Connectez-vous avec votre méthode de connexion habituelle.'
        ),
        'button': 'Aller à la connexion',
    },
}


# Every key the confirm template reads. A missing one makes Django log the whole
# template context, which holds the raw token.
_CONFIRM_PAGE_DEFAULTS = {
    'staff_disabled': False,
    'error_code': '',
    'page_language': 'en',
    'copy': {},
    'sign_in_url': '',
}


def _page_language(request, user=None) -> str:
    """Browser language first, then the account preference, then the email default."""
    for tag, _quality in parse_accept_lang_header(request.META.get('HTTP_ACCEPT_LANGUAGE', '')):
        lang = normalize_magic_link_language(tag)
        if lang:
            return lang
    pref = getattr(user, 'preference', None) if user is not None else None
    lang = normalize_magic_link_language(getattr(pref, 'language', None)) if pref is not None else None
    if lang:
        return lang
    return normalize_magic_link_language(getattr(settings, 'MAGIC_LINK_EMAIL_DEFAULT_LANGUAGE', None)) or 'en'


def _deliver_or_error_response(send, *, company, request_id) -> Response | None:
    """Run ``send``. Return the API error for a refusal, or None once the message is accepted.

    Shared by the magic link and the staff notice, so a staff address gets the same
    answers as any other address for the same delivery outcome.
    """
    try:
        send()
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
            request_id,
        )
        transaction.set_rollback(True)
        return Response({'error_code': 'email_unavailable'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
    return None


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
            'Always returns the same success shape when enabled (does not reveal whether the email exists). '
            'A staff account gets a notice without a link instead, with the same response.'
        ),
        auth=[],
        request=ShellUIMagicLinkRequestSerializer,
        responses={
            200: OpenApiResponse(description='Request accepted. Identity sends the sign-in email'),
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

        staff_user = existing if is_staff_account(existing) else staff_account_for_email(email)
        if staff_user is not None:
            return self._staff_notice(
                request,
                company=company,
                email=email,
                existing=existing,
                staff_user=staff_user,
                redirect_to=redirect_to,
                requested_lang=normalize_magic_link_language(serializer.validated_data.get('language')),
            )

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

        # Identity always sends the sign-in email itself. A webhook rule for
        # identity.auth.magic_link.requested is only a notification and never replaces
        # this send (its payload carries no link or token).
        failed = _deliver_or_error_response(
            lambda: deliver_magic_link_email(
                row=row,
                company=company,
                user=existing,
                language=mail_language,
                raw_token=raw_token,
                fallback_base_url=request_base_url,
            ),
            company=company,
            request_id=row.pk,
        )
        if failed is not None:
            return failed

        def _after_commit() -> None:
            try:
                emit_magic_link_requested(
                    company,
                    row,
                    user=existing,
                    language=requested_lang,
                )
            except Exception:  # noqa: BLE001
                logger.warning(
                    'magic_link_webhook_emit_failed company_id=%s request_id=%s',
                    company.pk,
                    row.pk,
                )

        transaction.on_commit(_after_commit)
        return Response(_GENERIC_REQUEST_OK, status=status.HTTP_200_OK)

    def _staff_notice(
        self,
        request,
        *,
        company,
        email: str,
        existing,
        staff_user,
        redirect_to: str,
        requested_lang: str | None,
    ) -> Response:
        """
        A staff account asked for a magic link. No token is created and no link is sent.

        The address gets the built-in staff notice instead (no link or token). The API
        answers exactly as for any other address, and the webhook notification is the same
        ``identity.auth.magic_link.requested`` a normal request emits, so neither the caller
        nor the company's webhooks learn that the address is staff.
        """
        request_id = uuid.uuid4()
        # Tokens issued before this release, or before the account became staff.
        delete_unused_magic_link_tokens_for_user(staff_user)
        failed = _deliver_or_error_response(
            lambda: deliver_staff_magic_link_notice(
                company=company,
                email=email,
                user=staff_user,
                language=requested_lang,
                sign_in_url=sign_in_page_url(redirect_to),
                request_id=request_id,
            ),
            company=company,
            request_id=request_id,
        )
        if failed is not None:
            return failed

        # Same shape as a real request row, so the notification payload looks the same.
        notice = SimpleNamespace(pk=request_id, email=email, expires_at=timezone.now() + magic_link_ttl())

        def _after_commit() -> None:
            try:
                emit_magic_link_requested(company, notice, user=existing, language=requested_lang)
            except Exception:  # noqa: BLE001
                logger.warning(
                    'magic_link_webhook_emit_failed company_id=%s request_id=%s',
                    company.pk,
                    request_id,
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
            403: OpenApiResponse(description='HTML page explaining that staff accounts cannot use magic links'),
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
            403: OpenApiResponse(
                description='Company access denied, or `magic_link_staff_disabled` (the token belongs to a staff account)'
            ),
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
                    **_CONFIRM_PAGE_DEFAULTS,
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
        if magic_link_row_is_for_staff(row):
            # The link holder has this account's token, so saying why is fine here.
            lang = _page_language(request, row.user)
            return render(
                request,
                'authapi/magic_link_confirm.html',
                {
                    'error_message': None,
                    'staff_disabled': True,
                    'error_code': MAGIC_LINK_STAFF_DISABLED,
                    'page_language': lang,
                    'copy': _STAFF_DISABLED_PAGE[lang],
                    'sign_in_url': sign_in_page_url(row.redirect_to),
                    'company_name': company.name,
                    'email': '',
                    'token': '',
                    'company_id': company.id,
                    'form_action': '',
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        form_action = request.build_absolute_uri('?' + urlencode({'company_id': str(company.id)}))
        return render(
            request,
            'authapi/magic_link_confirm.html',
            {
                **_CONFIRM_PAGE_DEFAULTS,
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

        if magic_link_row_is_for_staff(row):
            # Staff never sign in with a magic link, even with a token issued before the
            # account became staff. The token is already consumed above.
            staff_user = row.user if is_staff_account(row.user) else staff_account_for_email(row.email)
            record_login_event(
                request=request,
                outcome=LoginOutcome.FAILURE,
                provider=MAGIC_LINK_PROVIDER,
                user=staff_user,
                company=company,
                failure_reason=MAGIC_LINK_STAFF_DISABLED,
                client_timezone=client_tz,
                client_device_id=client_dev,
            )
            if browser_redirect and redirect_to:
                return HttpResponseRedirect(
                    append_oauth_error_params(redirect_to, MAGIC_LINK_STAFF_DISABLED_MESSAGE, MAGIC_LINK_STAFF_DISABLED)
                )
            return Response(
                {'error': MAGIC_LINK_STAFF_DISABLED_MESSAGE, 'error_code': MAGIC_LINK_STAFF_DISABLED},
                status=status.HTTP_403_FORBIDDEN,
            )

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
