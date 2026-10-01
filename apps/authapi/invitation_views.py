"""Admin API to invite someone to a company by email, list open invitations, and revoke them."""

from __future__ import annotations

import logging

from django.db import IntegrityError, transaction
from django.db.models import Exists, OuterRef, Subquery
from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.actions.user_hooks import emit_user_invitation_revoked, emit_user_invited
from apps.companies.models import CompanyInvitation, CompanyMembership
from apps.companies.redirect_allowlist import validate_redirect_to_for_company

from .invitation_email import send_invitation_email
from .permissions import ShellUIPermission
from .serializers import ShellUIInvitationCreateSerializer, ShellUIOpenAPISerializer
from .throttling import check_rate_limit
from .views import _require_staff_or_company_owner

logger = logging.getLogger(__name__)

ALREADY_MEMBER = 'already_member'
ALREADY_INVITED = 'already_invited'
INVALID_APP_URL = 'invalid_app_url'
INVITATION_NOT_PENDING = 'invitation_not_pending'
INVITATION_NOT_REVOKED = 'invitation_not_revoked'


def _iso(value):
    return value.isoformat() if value else None


def _invitation_payload(invitation: CompanyInvitation) -> dict:
    inviter = invitation.invited_by
    return {
        'id': invitation.pk,
        'email': invitation.email,
        'language': invitation.language,
        'status': invitation.status,
        'invited_by': (
            {
                'id': inviter.pk,
                'email': inviter.email or None,
                'name': inviter.get_full_name() or inviter.get_username(),
            }
            if inviter is not None
            else None
        ),
        'created_at': _iso(invitation.created_at),
        'revoked_at': _iso(invitation.revoked_at),
    }


def _open_invitations(company):
    """
    Pending invitations, plus revoked ones that still block sign-in: the latest invitation for
    the email, with no enabled member using that email.
    """
    latest_id = (
        CompanyInvitation.objects.filter(company=company, email=OuterRef('email'))
        .order_by('-id')
        .values('id')[:1]
    )
    enabled_member = CompanyMembership.objects.filter(
        company=company,
        is_enabled=True,
        user__email__iexact=OuterRef('email'),
    )
    return (
        CompanyInvitation.objects.filter(
            company=company,
            status__in=[CompanyInvitation.STATUS_PENDING, CompanyInvitation.STATUS_REVOKED],
            id=Subquery(latest_id),
        )
        .exclude(Exists(enabled_member))
        .select_related('invited_by')
        .order_by('-created_at', '-id')
    )


@extend_schema_view(
    get=extend_schema(
        tags=['directory-users'],
        summary='List open invitations for this company (staff or company owner)',
        description=(
            'Pending invitations, plus revoked invitations that still block sign-in for that email. '
            'Accepted invitations are not listed: those users appear in the users list.'
        ),
        responses={
            200: OpenApiResponse(description='`{"results": [invitation, …]}`'),
            403: OpenApiResponse(description='Not staff or company owner'),
        },
    ),
    post=extend_schema(
        tags=['directory-users'],
        summary='Invite someone to this company (staff or company owner)',
        description=(
            'Stores a pending invitation; no user account is created. The invitee gets access on their '
            'first sign-in with that email (magic link, or OAuth/SAML with a verified email). Sends an '
            'invitation email in `language` linking to `app_url`, or emits `identity.user.invited` '
            'instead when the company has an enabled webhook rule for it. Returns 409 `already_member` '
            'when someone with this email already has access, or `already_invited` when an invitation '
            'is pending.'
        ),
        request=ShellUIInvitationCreateSerializer,
        responses={
            201: OpenApiResponse(description='Invitation created; body has `invitation`'),
            400: OpenApiResponse(description='Invalid email, language, or app_url'),
            403: OpenApiResponse(description='Not staff or company owner'),
            409: OpenApiResponse(description='Already a member, or invitation already pending'),
            429: OpenApiResponse(description='Too many invitations'),
        },
    ),
)
class ShellUIAdminInvitationView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        return Response({'results': [_invitation_payload(i) for i in _open_invitations(company)]})

    @transaction.atomic
    def post(self, request):
        actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err

        serializer = ShellUIInvitationCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email'].strip().lower()
        language = serializer.validated_data.get('language') or 'en'

        app_url = ''
        raw_app_url = (serializer.validated_data.get('app_url') or '').strip()
        if raw_app_url:
            validated_url, url_err = validate_redirect_to_for_company(
                company=company,
                request=request,
                redirect_to_raw=raw_app_url,
            )
            if url_err or not validated_url:
                return Response(
                    {'error': url_err or 'Invalid app_url.', 'error_code': INVALID_APP_URL},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            app_url = validated_url

        limited = check_rate_limit(request, scope='invitation', identity=f'company:{company.pk}')
        if limited is not None:
            return limited

        if CompanyMembership.objects.filter(company=company, is_enabled=True, user__email__iexact=email).exists():
            return Response(
                {'error': 'Someone with this email already has access to this company.', 'error_code': ALREADY_MEMBER},
                status=status.HTTP_409_CONFLICT,
            )

        already_invited = Response(
            {'error': 'An invitation is already pending for this email.', 'error_code': ALREADY_INVITED},
            status=status.HTTP_409_CONFLICT,
        )
        if CompanyInvitation.objects.filter(
            company=company,
            email=email,
            status=CompanyInvitation.STATUS_PENDING,
        ).exists():
            return already_invited
        try:
            with transaction.atomic():
                invitation = CompanyInvitation.objects.create(
                    company=company,
                    email=email,
                    language=language,
                    app_url=app_url,
                    invited_by=actor,
                )
        except IntegrityError:
            return already_invited

        inviter_name = actor.get_full_name() or (actor.email or '').strip() or actor.get_username()

        def _after_commit() -> None:
            try:
                queued = emit_user_invited(invitation)
            except Exception:  # noqa: BLE001
                logger.exception('invitation_webhook_emit_failed company_id=%s invitation_id=%s', company.pk, invitation.pk)
                queued = []
            if queued:
                return
            try:
                send_invitation_email(
                    company=company,
                    email=email,
                    inviter_name=inviter_name,
                    app_url=app_url or None,
                    language=language,
                )
            except Exception:  # noqa: BLE001
                logger.exception('invitation_email_failed company_id=%s invitation_id=%s', company.pk, invitation.pk)

        transaction.on_commit(_after_commit)
        return Response({'invitation': _invitation_payload(invitation)}, status=status.HTTP_201_CREATED)


def _locked_company_invitation(request, pk: int):
    """Returns ``(actor, invitation, err)`` with the invitation row locked, scoped to the caller's company."""
    actor, company, err = _require_staff_or_company_owner(request)
    if err:
        return None, None, err
    invitation = (
        CompanyInvitation.objects.select_for_update()
        .select_related('invited_by')
        .filter(company=company, pk=pk)
        .first()
    )
    if invitation is None:
        return None, None, Response({'error': 'Invitation not found.'}, status=status.HTTP_404_NOT_FOUND)
    return actor, invitation, None


@extend_schema_view(
    delete=extend_schema(
        tags=['directory-users'],
        summary='Delete a revoked invitation for good (staff or company owner)',
        description=(
            'Removes every revoked invitation for this email in the company from the database. This lifts '
            'the sign-in block: the email is then treated as never invited. Pending invitations must be '
            'revoked first (409 `invitation_not_revoked`).'
        ),
        responses={
            204: OpenApiResponse(description='Invitation deleted'),
            403: OpenApiResponse(description='Not staff or company owner'),
            404: OpenApiResponse(description='No invitation with this id in the company'),
            409: OpenApiResponse(description='Invitation is not revoked'),
        },
    ),
)
class ShellUIAdminInvitationDetailView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    @transaction.atomic
    def delete(self, request, pk: int):
        _actor, invitation, err = _locked_company_invitation(request, pk)
        if err:
            return err
        if invitation.status != CompanyInvitation.STATUS_REVOKED:
            return Response(
                {'error': 'Only revoked invitations can be deleted.', 'error_code': INVITATION_NOT_REVOKED},
                status=status.HTTP_409_CONFLICT,
            )
        CompanyInvitation.objects.filter(
            company_id=invitation.company_id,
            email=invitation.email,
            status=CompanyInvitation.STATUS_REVOKED,
        ).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    post=extend_schema(
        tags=['directory-users'],
        summary='Revoke a pending invitation (staff or company owner)',
        description=(
            'Marks the invitation revoked and emits `identity.user.invitation_revoked`. Sign-in with that '
            'email is refused for this company (`invitation_revoked`) until a new invitation is sent or '
            'the revoked invitation is deleted.'
        ),
        request=None,
        responses={
            200: OpenApiResponse(description='Invitation revoked; body has `invitation`'),
            403: OpenApiResponse(description='Not staff or company owner'),
            404: OpenApiResponse(description='No invitation with this id in the company'),
            409: OpenApiResponse(description='Invitation is not pending'),
        },
    ),
)
class ShellUIAdminInvitationRevokeView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    @transaction.atomic
    def post(self, request, pk: int):
        actor, invitation, err = _locked_company_invitation(request, pk)
        if err:
            return err
        if invitation.status != CompanyInvitation.STATUS_PENDING:
            return Response(
                {'error': 'Only pending invitations can be revoked.', 'error_code': INVITATION_NOT_PENDING},
                status=status.HTTP_409_CONFLICT,
            )
        invitation.status = CompanyInvitation.STATUS_REVOKED
        invitation.revoked_at = timezone.now()
        invitation.revoked_by = actor
        invitation.save(update_fields=['status', 'revoked_at', 'revoked_by'])
        emit_user_invitation_revoked(invitation)
        return Response({'invitation': _invitation_payload(invitation)})
