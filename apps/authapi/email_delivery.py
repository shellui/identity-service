"""Magic-link and invitation delivery through email-service, with SMTP fallback."""

from __future__ import annotations

import logging

from django.core.exceptions import ImproperlyConfigured

from apps.actions.email_client import (
    INVITATION_TTL_SECONDS,
    MAGIC_LINK_TTL_SECONDS,
    STAFF_NOTICE_TTL_SECONDS,
    TEMPLATE_INVITED,
    TEMPLATE_MAGIC_LINK,
    TEMPLATE_MAGIC_LINK_STAFF_BLOCKED,
    EmailServiceRejected,
    EmailServiceUnreachable,
    EmailUnavailable,
    PASSTHROUGH_SEND_CODES,
    RecipientSuppressed,
    email_service_configured,
    invitation_idempotency_key,
    magic_link_idempotency_key,
    post_json,
    staff_notice_idempotency_key,
)
from apps.authapi.invitation_email import send_invitation_email
from apps.authapi.magic_link import (
    identity_public_base_url,
    magic_link_url_for_request,
    normalize_magic_link_language,
)
from apps.authapi.magic_link_email import (
    _resolve_language,
    send_magic_link_email,
    send_staff_magic_link_notice_email,
)
from apps.companies.access import get_membership

logger = logging.getLogger(__name__)


class AuthEmailError(Exception):
    """email-service refused an auth send. The API returns this code and does not use SMTP."""

    def __init__(self, *, status: int, error_code: str) -> None:
        super().__init__(error_code)
        self.status = status
        self.error_code = error_code


def _passthrough_status(exc: EmailServiceRejected) -> int | None:
    if exc.error_code == 'platform_sender_not_allowed':
        return exc.status if exc.status in (403, 409) else 409
    return PASSTHROUGH_SEND_CODES.get(exc.error_code)


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


def _send_or_fallback(*, path_body: dict, smtp_send, smtp_on_codes: frozenset[str] = frozenset()) -> None:
    """
    POST ``/api/v1/send`` when a service key is set.

    SMTP is used when the key is unset, and when email-service cannot be reached
    after the caller retry policy. A refusal such as ``recipient_suppressed`` is not
    sent again over SMTP. ``smtp_on_codes`` lists refusals that do go to SMTP, for
    example ``template_not_found`` from an email-service that predates a template.
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
        if exc.error_code in smtp_on_codes:
            logger.warning(
                'email_service_smtp_fallback template=%s error_code=%s',
                path_body.get('template_key'),
                exc.error_code,
            )
            try:
                smtp_send()
            except Exception as smtp_exc:
                logger.warning(
                    'smtp_fallback_failed template=%s error=%s',
                    path_body.get('template_key'),
                    smtp_exc.__class__.__name__,
                )
                raise EmailUnavailable from None
            return
        if exc.error_code == 'recipient_suppressed' or exc.status == 422:
            raise RecipientSuppressed from None
        mapped = _passthrough_status(exc)
        if mapped is not None:
            raise AuthEmailError(status=mapped, error_code=exc.error_code) from None
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


def deliver_staff_magic_link_notice(
    *,
    company,
    email: str,
    user=None,
    language: str | None = None,
    sign_in_url: str | None = None,
    request_id,
) -> None:
    """
    Tell a staff account that magic links are off for it. Sent instead of the sign-in link.

    Same path as the magic link: ``POST /api/v1/send`` on the auth lane (one recipient,
    built-in copy only), or SMTP. No link or token. An email-service that does not know
    the template yet (``template_not_found``) falls back to SMTP.
    Raises ``EmailUnavailable``, ``RecipientSuppressed`` or ``AuthEmailError`` like
    ``deliver_magic_link_email``, so the API answers the same way as for other addresses.
    """
    lang = _resolve_language(user=user, payload_language=language)
    user_id = _member_user_id(company, user)
    recipient: dict = {'email': email}
    if user_id is not None:
        recipient['user_id'] = user_id
    variables = {'company_name': company.name}
    if sign_in_url:
        variables['sign_in_url'] = sign_in_url
    body = {
        'company_id': company.pk,
        'template_key': TEMPLATE_MAGIC_LINK_STAFF_BLOCKED,
        'language': lang,
        'idempotency_key': staff_notice_idempotency_key(
            company_id=company.pk,
            user_id=user_id,
            request_id=request_id,
        ),
        'ttl_seconds': STAFF_NOTICE_TTL_SECONDS,
        'to': [recipient],
        'variables': variables,
    }

    def smtp_send() -> None:
        send_staff_magic_link_notice_email(
            company=company,
            email=email,
            user=user,
            language=language,
            sign_in_url=sign_in_url,
        )

    _send_or_fallback(
        path_body=body,
        smtp_send=smtp_send,
        smtp_on_codes=frozenset({'template_not_found'}),
    )


def invitation_link(*, app_url: str | None, fallback_base_url: str | None = None) -> str:
    """
    URL for ``identity.user.invited``.

    ``app_url`` wins. Otherwise the link is identity's public landing page
    (``JWT_ISSUER``, or the request base URL when ``DEBUG`` is true and the issuer is unset).
    """
    provided = (app_url or '').strip()
    if provided:
        return provided
    return f'{identity_public_base_url(fallback=fallback_base_url)}/'


def deliver_invitation_email(
    *,
    company,
    invitation,
    email: str,
    inviter_name: str,
    app_url: str | None,
    language: str,
    fallback_base_url: str | None = None,
) -> None:
    """Send the invitation. Raises ``EmailUnavailable`` or ``RecipientSuppressed``."""
    lang = normalize_magic_link_language(language) or 'en'
    provided = (app_url or '').strip()

    def smtp_send(link: str | None) -> None:
        send_invitation_email(
            company=company,
            email=email,
            inviter_name=inviter_name,
            app_url=link or None,
            language=lang,
        )

    if not email_service_configured():
        try:
            smtp_send(provided or None)
        except Exception as exc:
            logger.warning('smtp_send_failed template=%s error=%s', TEMPLATE_INVITED, exc.__class__.__name__)
            raise EmailUnavailable from None
        return

    try:
        link = invitation_link(app_url=provided, fallback_base_url=fallback_base_url)
    except ImproperlyConfigured:
        logger.warning(
            'invitation_url_unavailable company_id=%s invitation_id=%s',
            company.pk,
            invitation.pk,
        )
        raise EmailUnavailable from None

    variables = {
        'company_name': company.name,
        'invitation_url': link,
        'recipient_email': email,
    }
    if (inviter_name or '').strip():
        variables['inviter_name'] = inviter_name.strip()
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
    _send_or_fallback(path_body=body, smtp_send=lambda: smtp_send(link))


def has_enabled_webhook_rule(company, event_type: str) -> bool:
    from apps.actions.models import ActionRule

    return ActionRule.objects.filter(
        company=company,
        event_type=event_type,
        enabled=True,
        action_kind=ActionRule.ACTION_WEBHOOK,
    ).exists()
