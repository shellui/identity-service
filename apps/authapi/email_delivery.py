"""Magic-link and invitation delivery through email-service, with SMTP fallback."""

from __future__ import annotations

import logging

from apps.actions.email_client import (
    INVITATION_TTL_SECONDS,
    MAGIC_LINK_TTL_SECONDS,
    TEMPLATE_INVITED,
    TEMPLATE_MAGIC_LINK,
    EmailServiceRejected,
    EmailServiceUnreachable,
    EmailUnavailable,
    RecipientSuppressed,
    email_service_configured,
    invitation_idempotency_key,
    magic_link_idempotency_key,
    post_json,
)
from apps.authapi.invitation_email import send_invitation_email
from apps.authapi.magic_link import magic_link_url_for_request, normalize_magic_link_language
from apps.authapi.magic_link_email import _resolve_language, send_magic_link_email
from apps.companies.access import get_membership

logger = logging.getLogger(__name__)


def _recipient_name(user) -> str:
    if user is None:
        return ''
    name = (user.get_full_name() or '').strip()
    return name


def _member_user_id(company, user) -> int | None:
    if user is None or not getattr(user, 'pk', None):
        return None
    if get_membership(company, user) is None:
        return None
    return user.pk


def _send_or_fallback(*, path_body: dict, smtp_send) -> None:
    """
    POST ``/api/v1/send`` when a service key is set.

    SMTP is used when the key is unset, and when email-service cannot be reached
    after the caller retry policy. A refusal such as ``recipient_suppressed`` is not
    sent again over SMTP.
    """
    if not email_service_configured():
        try:
            smtp_send()
        except Exception as exc:
            logger.warning(
                'smtp_send_failed template=%s error=%s',
                path_body.get('template_key'),
                exc.__class__.__name__,
            )
            raise EmailUnavailable from None
        return
    try:
        post_json('/api/v1/send', path_body)
    except EmailServiceRejected as exc:
        if exc.error_code == 'recipient_suppressed' or exc.status == 422:
            raise RecipientSuppressed from None
        logger.warning(
            'email_service_send_rejected template=%s status=%s error_code=%s',
            path_body.get('template_key'),
            exc.status,
            exc.error_code,
        )
        raise EmailUnavailable from None
    except EmailServiceUnreachable:
        logger.warning('email_service_smtp_fallback template=%s', path_body.get('template_key'))
        try:
            smtp_send()
        except Exception as exc:
            logger.warning(
                'smtp_fallback_failed template=%s error=%s',
                path_body.get('template_key'),
                exc.__class__.__name__,
            )
            raise EmailUnavailable from None
    except Exception as exc:
        logger.warning(
            'email_service_send_failed template=%s error=%s',
            path_body.get('template_key'),
            exc.__class__.__name__,
        )
        raise EmailUnavailable from None


def deliver_magic_link_email(
    *,
    row,
    company,
    user=None,
    language: str | None = None,
    raw_token: str,
    fallback_base_url: str | None = None,
) -> None:
    """Send the sign-in message. Raises ``EmailUnavailable`` or ``RecipientSuppressed``."""
    magic_link_url = magic_link_url_for_request(
        row.pk,
        raw_token=raw_token,
        fallback_base_url=fallback_base_url,
    )
    if not magic_link_url:
        raise EmailUnavailable

    lang = _resolve_language(user=user, payload_language=language)
    user_id = _member_user_id(company, user)
    recipient: dict = {'email': row.email}
    if user_id is not None:
        recipient['user_id'] = user_id
    variables = {
        'company_name': company.name,
        'magic_link_url': magic_link_url,
    }
    recipient_name = _recipient_name(user)
    if recipient_name:
        variables['recipient_name'] = recipient_name
    body = {
        'company_id': company.pk,
        'template_key': TEMPLATE_MAGIC_LINK,
        'language': lang,
        'idempotency_key': magic_link_idempotency_key(
            company_id=company.pk,
            user_id=user_id,
            request_id=row.pk,
        ),
        'ttl_seconds': MAGIC_LINK_TTL_SECONDS,
        'to': [recipient],
        'variables': variables,
    }

    def smtp_send() -> None:
        send_magic_link_email(
            row=row,
            company=company,
            user=user,
            language=language,
            raw_token=raw_token,
            fallback_base_url=fallback_base_url,
        )

    _send_or_fallback(path_body=body, smtp_send=smtp_send)


def deliver_invitation_email(
    *,
    company,
    invitation,
    email: str,
    inviter_name: str,
    app_url: str | None,
    language: str,
) -> None:
    """Send the invitation. Raises ``EmailUnavailable`` or ``RecipientSuppressed``."""
    lang = normalize_magic_link_language(language) or 'en'

    def smtp_send() -> None:
        send_invitation_email(
            company=company,
            email=email,
            inviter_name=inviter_name,
            app_url=app_url,
            language=lang,
        )

    # The catalog template requires invitation_url. An invitation with no app URL
    # cannot be represented on /send, so it stays on the SMTP templates.
    if email_service_configured() and not (app_url or '').strip():
        logger.info(
            'invitation_smtp_without_app_url company_id=%s invitation_id=%s',
            company.pk,
            invitation.pk,
        )
        try:
            smtp_send()
        except Exception as exc:
            logger.warning('smtp_send_failed template=%s error=%s', TEMPLATE_INVITED, exc.__class__.__name__)
            raise EmailUnavailable from None
        return

    variables = {
        'company_name': company.name,
        'recipient_email': email,
    }
    if (inviter_name or '').strip():
        variables['inviter_name'] = inviter_name.strip()
    if (app_url or '').strip():
        variables['invitation_url'] = app_url.strip()
    body = {
        'company_id': company.pk,
        'template_key': TEMPLATE_INVITED,
        'language': lang,
        'idempotency_key': invitation_idempotency_key(
            company_id=company.pk,
            invitation_id=invitation.pk,
        ),
        'ttl_seconds': INVITATION_TTL_SECONDS,
        'to': [{'email': email}],
        'variables': variables,
    }
    _send_or_fallback(path_body=body, smtp_send=smtp_send)


def has_enabled_webhook_rule(company, event_type: str) -> bool:
    from apps.actions.models import ActionRule

    return ActionRule.objects.filter(
        company=company,
        event_type=event_type,
        enabled=True,
        action_kind=ActionRule.ACTION_WEBHOOK,
    ).exists()
