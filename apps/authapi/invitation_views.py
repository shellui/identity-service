"""Admin API to invite a user to a company by email."""

from __future__ import annotations

import logging

from django.contrib.auth import get_user_model
from django.db import transaction
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.actions.user_hooks import emit_user_account_created, emit_user_invited
from apps.companies.access import get_membership, set_company_access
from apps.companies.redirect_allowlist import validate_redirect_to_for_company

from .invitation_email import send_invitation_email
from .magic_link_views import _create_magic_link_user
from .models import UserPreference
from .permissions import ShellUIPermission
from .serializers import ShellUIInvitationCreateSerializer, ShellUIOpenAPISerializer
from .throttling import check_rate_limit
from .views import _admin_user_payload, _require_staff_or_company_owner

User = get_user_model()
logger = logging.getLogger(__name__)

ALREADY_MEMBER = 'already_member'
INVALID_APP_URL = 'invalid_app_url'


@extend_schema_view(
    post=extend_schema(
        tags=['directory-users'],
        summary='Invite a user to this company (staff or company owner)',
        description=(
            'Reuses the account with this email or creates one, then enables access to the company '
            '(this also approves a pending access request). Sends an invitation email in `language` '
            'linking to `app_url`, or emits `identity.user.invited` instead when the company has an '
            'enabled webhook rule for it. The email is not a sign-in credential: the user signs in with '
            'any method that matches the email. Returns 409 `already_member` when the user already '
            'has access.'
        ),
        request=ShellUIInvitationCreateSerializer,
        responses={
            201: OpenApiResponse(description='Invitation sent; body has `user` and `user_created`'),
            400: OpenApiResponse(description='Invalid email, language, or app_url'),
            403: OpenApiResponse(description='Not staff or company owner'),
            409: OpenApiResponse(description='User already has access to this company'),
            429: OpenApiResponse(description='Too many invitations'),
        },
    ),
)
class ShellUIAdminInvitationView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    @transaction.atomic
    def post(self, request):
        actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err

        serializer = ShellUIInvitationCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email'].strip().lower()
        language = serializer.validated_data.get('language') or 'en'

        app_url = None
        raw_app_url = (serializer.validated_data.get('app_url') or '').strip()
        if raw_app_url:
            app_url, url_err = validate_redirect_to_for_company(
                company=company,
                request=request,
                redirect_to_raw=raw_app_url,
            )
            if url_err or not app_url:
                return Response(
                    {'error': url_err or 'Invalid app_url.', 'error_code': INVALID_APP_URL},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        limited = check_rate_limit(request, scope='invitation', identity=f'company:{company.pk}')
        if limited is not None:
            return limited

        user = User.objects.filter(email__iexact=email).order_by('pk').first()
        user_created = user is None
        if user_created:
            user = _create_magic_link_user(request, email=email)
            UserPreference.objects.get_or_create(user=user, defaults={'language': language})
        else:
            membership = get_membership(company, user)
            if membership is not None and membership.is_enabled:
                return Response(
                    {
                        'error': 'This user already has access to this company.',
                        'error_code': ALREADY_MEMBER,
                    },
                    status=status.HTTP_409_CONFLICT,
                )

        set_company_access(company, user, enabled=True)
        if user_created:
            emit_user_account_created(company, user, source='invitation')

        inviter_email = (actor.email or '').strip() or None
        inviter_name = actor.get_full_name() or inviter_email or actor.get_username()

        def _after_commit() -> None:
            try:
                queued = emit_user_invited(
                    company,
                    user,
                    invited_by=inviter_email,
                    invitation_url=app_url,
                    user_created=user_created,
                    language=language,
                )
            except Exception:  # noqa: BLE001
                logger.exception('invitation_webhook_emit_failed company_id=%s user_id=%s', company.pk, user.pk)
                queued = []
            if queued:
                return
            try:
                send_invitation_email(
                    company=company,
                    email=email,
                    inviter_name=inviter_name,
                    app_url=app_url,
                    language=language,
                )
            except Exception:  # noqa: BLE001
                logger.exception('invitation_email_failed company_id=%s user_id=%s', company.pk, user.pk)

        transaction.on_commit(_after_commit)
        return Response(
            {'user': _admin_user_payload(user, company), 'user_created': user_created},
            status=status.HTTP_201_CREATED,
        )
