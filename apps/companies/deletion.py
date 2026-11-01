"""Company deletion: flag first, then purge from a Celery job.

``request_company_deletion`` only flags the company. It is hidden from lists and refused at
sign-in right away. ``purge_deleted_companies`` runs every 60 seconds and:

1. asks each regional service (storage, hosting, email) to flag the company too, with a
   short-lived assertion signed by this identity-service (audience ``shellui-company-deletion``,
   never accepted as a user token);
2. once every service answered, deletes the company and its rows;
3. tells the dashboard (saas-service) with a signed ``identity.company.deleted`` webhook.

Every step is idempotent, so a failed run is simply retried by the next one.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import timedelta

import jwt
import requests
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework_simplejwt.settings import api_settings

from apps.companies.models import Company, CompanyDeletionNotice

logger = logging.getLogger(__name__)

DELETION_AUDIENCE = 'shellui-company-deletion'
DELETION_SCOPE = 'company.delete'
ASSERTION_LIFETIME = 60
COMPANY_DELETED = 'identity.company.deleted'
# A notice the dashboard never accepted is dropped after this long, so nothing piles up.
NOTICE_MAX_AGE = timedelta(days=7)


def request_company_deletion(company: Company) -> Company:
    """Flag ``company`` for deletion. Safe to call twice."""
    from apps.authapi.refresh_sessions import revoke_company_refresh_sessions
    from apps.federation.models import ProvisionedCompany

    now = timezone.now()
    with transaction.atomic():
        if company.deletion_requested_at is None:
            company.deletion_requested_at = now
            company.save(update_fields=['deletion_requested_at'])
        ProvisionedCompany.objects.filter(company_id=company.pk).exclude(
            status=ProvisionedCompany.STATUS_DELETING
        ).update(status=ProvisionedCompany.STATUS_DELETING, deletion_requested_at=now, updated_at=now)
    revoke_company_refresh_sessions(company)
    return company


def is_company_deleting(company: Company | None) -> bool:
    if company is None or company.pk is None:
        return False
    if company.deletion_requested_at is not None:
        return True
    return Company.all_objects.filter(pk=company.pk, deletion_requested_at__isnull=False).exists()


# Fixed path every service exposes for identity's deletion call.
DELETION_PATH = '/api/v1/internal/company-deletions'


def deletion_services() -> list[tuple[str, str]]:
    """``(setting name, origin)`` of each service told to purge a company. Empty origin: skipped.

    Email takes part only when identity actually uses email-service (``EMAIL_SERVICE_API_KEY`` set),
    since ``EMAIL_SERVICE_URL`` always has a default.
    """
    email = getattr(settings, 'EMAIL_SERVICE_URL', '') if getattr(settings, 'EMAIL_SERVICE_API_KEY', '') else ''
    services = [
        ('STORAGE_SERVICE_URL', getattr(settings, 'STORAGE_SERVICE_URL', '')),
        ('HOSTING_SERVICE_URL', getattr(settings, 'HOSTING_SERVICE_URL', '')),
        ('EMAIL_SERVICE_URL' if getattr(settings, 'EMAIL_SERVICE_API_KEY', '') else 'EMAIL_SERVICE_API_KEY', email),
    ]
    return [(name, str(url or '').strip().rstrip('/')) for name, url in services]


def deletion_service_urls() -> list[str]:
    return [url for _, url in deletion_services() if url]


def _warn_skipped_services() -> None:
    skipped = [name for name, url in deletion_services() if not url]
    if skipped:
        logger.warning('company deletion: %s not set, those services are skipped', ', '.join(skipped))


def build_deletion_assertion(company_id: int, audience_url: str) -> str:
    now = int(time.time())
    claims = {
        'iss': api_settings.ISSUER or '',
        'aud': DELETION_AUDIENCE,
        'sub': f'company:{company_id}',
        'scope': DELETION_SCOPE,
        'company_id': company_id,
        'target': audience_url,
        'iat': now,
        'exp': now + ASSERTION_LIFETIME,
        'jti': uuid.uuid4().hex,
    }
    headers = {}
    kid = getattr(settings, 'JWT_ACTIVE_KEY_ID', '')
    if kid:
        headers['kid'] = kid
    token = jwt.encode(claims, api_settings.SIGNING_KEY, algorithm=api_settings.ALGORITHM, headers=headers or None)
    return token.decode('utf-8') if isinstance(token, bytes) else token


def _notify_service(url: str, company_id: int) -> bool:
    try:
        response = requests.post(
            f'{url}{DELETION_PATH}',
            json={'company_id': company_id},
            headers={'Authorization': f'Bearer {build_deletion_assertion(company_id, url)}'},
            timeout=float(getattr(settings, 'COMPANY_DELETION_TIMEOUT_SECONDS', 10)),
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        logger.warning('company deletion: %s unreachable for company=%s (%s)', url, company_id, type(exc).__name__)
        return False
    if response.status_code in (200, 202):
        return True
    if 300 <= response.status_code < 400:
        location = str(getattr(response, 'headers', {}).get('Location', '') or '').split('?')[0]
        logger.warning(
            'company deletion: %s redirected (%s to %s) for company=%s; set the service URL to an address '
            'that does not redirect (https:// or a redirect-exempt internal name)',
            url, response.status_code, location or '?', company_id,
        )
        return False
    snippet = ' '.join(str(getattr(response, 'text', '') or '')[:200].split())
    hint = ' (400 with an HTML body usually means DisallowedHost: add this host to ALLOWED_HOSTS on that service)' if response.status_code == 400 else ''
    logger.warning(
        'company deletion: %s answered %s for company=%s: %s%s', url, response.status_code, company_id, snippet or '-', hint
    )
    return False


def _purge_company(company: Company) -> bool:
    """Return True when the company is gone."""
    acks = list(company.deletion_acks or [])
    for url in deletion_service_urls():
        if url in acks:
            continue
        if not _notify_service(url, company.pk):
            continue
        acks.append(url)
        Company.all_objects.filter(pk=company.pk).update(deletion_acks=acks)
    if any(url not in acks for url in deletion_service_urls()):
        return False
    from apps.federation.models import ProvisionedCompany

    with transaction.atomic():
        row = ProvisionedCompany.objects.filter(company_id=company.pk).first()
        if row is not None:
            CompanyDeletionNotice.objects.get_or_create(
                global_company_id=row.global_company_id,
                defaults={'regional_company_id': str(company.pk)},
            )
        Company.all_objects.filter(pk=company.pk).delete()
    logger.info('company deletion: purged company=%s', company.pk)
    return True


def _send_notice(notice: CompanyDeletionNotice) -> bool:
    from apps.actions.webhook_signing import encode_webhook_envelope, sign_webhook_body

    url = (getattr(settings, 'DASHBOARD_WEBHOOK_URL', '') or '').strip()
    secret = (getattr(settings, 'DASHBOARD_WEBHOOK_SECRET', '') or '').strip()
    if not url or not secret:
        return False
    webhook_id = f'msg_company_deleted_{notice.pk}_{notice.global_company_id}'[:200]
    body = encode_webhook_envelope(
        {
            'type': COMPANY_DELETED,
            'timestamp': notice.created_at.isoformat(),
            'data': {'global_company_id': notice.global_company_id, 'id': notice.regional_company_id},
        }
    )
    headers = {'Content-Type': 'application/json', **sign_webhook_body(secret=secret, body=body, webhook_id=webhook_id)}
    try:
        response = requests.post(url, data=body, headers=headers, timeout=10)
    except requests.RequestException as exc:
        logger.warning('company deletion: dashboard unreachable (%s)', type(exc).__name__)
        return False
    if 200 <= response.status_code < 300:
        return True
    logger.warning('company deletion: dashboard answered %s', response.status_code)
    return False


def purge_deleted_companies(*, max_seconds: float = 50) -> dict:
    deadline = time.monotonic() + max_seconds
    purged = pending = sent = dropped = 0
    if Company.all_objects.filter(deletion_requested_at__isnull=False).exists():
        _warn_skipped_services()
    for company in Company.all_objects.filter(deletion_requested_at__isnull=False).order_by('deletion_requested_at'):
        if time.monotonic() > deadline:
            break
        if _purge_company(company):
            purged += 1
        else:
            pending += 1
    cutoff = timezone.now() - NOTICE_MAX_AGE
    for notice in CompanyDeletionNotice.objects.order_by('pk'):
        if time.monotonic() > deadline:
            break
        if _send_notice(notice):
            notice.delete()
            sent += 1
        elif notice.created_at < cutoff:
            notice.delete()
            dropped += 1
        else:
            CompanyDeletionNotice.objects.filter(pk=notice.pk).update(attempts=notice.attempts + 1)
    return {'purged': purged, 'pending': pending, 'notices_sent': sent, 'notices_dropped': dropped}
