"""Company join rules: public, domain allow-list, or invitation-only (per-company access)."""

from __future__ import annotations

import ast
import json
import logging
from dataclasses import dataclass

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils import timezone

from .models import Company, CompanyInvitation, CompanyMembership

logger = logging.getLogger(__name__)
User = get_user_model()

ERROR_ACCESS_PENDING = 'access_pending'
ERROR_ACCESS_DENIED = 'access_denied'
ERROR_INVITATION_REVOKED = 'invitation_revoked'

MSG_ACCESS_PENDING = (
    'Your account was created and is waiting for an administrator to grant access.'
)
MSG_ACCESS_DENIED = (
    'Your email domain is not authorized for this company. An administrator has been notified.'
)
MSG_INVITATION_REVOKED = (
    'Your invitation to this company was revoked. Contact an administrator to be invited again.'
)


@dataclass(frozen=True)
class JoinDecision:
    allowed: bool
    error_code: str | None = None
    message: str | None = None
    newly_joined: bool = False


def normalize_email_domain(email: str) -> str | None:
    raw = (email or '').strip().lower()
    if '@' not in raw:
        return None
    domain = raw.rsplit('@', 1)[-1].strip().lstrip('@').rstrip('.')
    return domain or None


def normalize_allowed_domains(domains) -> list[str]:
    """
    Normalize allow-list input to a flat list of lowercase domains.

    Accepts a list, a comma-separated string, or accidental stringified lists from
    admin widgets (e.g. ``["['acme.com']"]`` / ``"['acme.com']"``).
    """
    items = _coerce_domain_items(domains)
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, str):
            continue
        domain = item.strip().lower().lstrip('@').rstrip('.')
        # Strip leftover quote/bracket noise from stringified lists.
        domain = domain.strip('[]\'" ')
        if not domain or domain in seen:
            continue
        if any(ch.isspace() for ch in domain) or '/' in domain:
            continue
        seen.add(domain)
        out.append(domain)
    return out


def _coerce_domain_items(value) -> list:
    if value is None or value == '':
        return []
    if isinstance(value, list):
        flat: list = []
        for item in value:
            if isinstance(item, list):
                flat.extend(_coerce_domain_items(item))
            elif isinstance(item, str) and item.strip().startswith('['):
                flat.extend(_coerce_domain_items(item))
            else:
                flat.append(item)
        return flat
    if isinstance(value, str):
        text = value.strip()
        if text.startswith('[') and text.endswith(']'):
            try:
                parsed = ast.literal_eval(text)
            except (ValueError, SyntaxError):
                parsed = None
            if isinstance(parsed, list):
                return _coerce_domain_items(parsed)
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, list):
                return _coerce_domain_items(parsed)
        return [part for part in text.replace(';', ',').split(',') if part.strip()]
    return []



def email_matches_allowed_domains(email: str, allowed_domains) -> bool:
    user_domain = normalize_email_domain(email)
    if not user_domain:
        return False
    allowed = normalize_allowed_domains(allowed_domains)
    if not allowed:
        return False
    for domain in allowed:
        if user_domain == domain or user_domain.endswith(f'.{domain}'):
            return True
    return False


def get_membership(company: Company, user) -> CompanyMembership | None:
    if not getattr(user, 'pk', None) or not getattr(company, 'pk', None):
        return None
    return CompanyMembership.objects.filter(company=company, user=user).first()


def is_company_access_enabled(company: Company, user) -> bool:
    membership = get_membership(company, user)
    return bool(membership and membership.is_enabled)


def set_company_access(company: Company, user, *, enabled: bool) -> CompanyMembership:
    """Ensure membership exists and set per-company access. Does not touch User.is_active."""
    membership, _created = CompanyMembership.objects.get_or_create(
        company=company,
        user=user,
        defaults={'is_enabled': bool(enabled)},
    )
    if membership.is_enabled != bool(enabled):
        membership.is_enabled = bool(enabled)
        membership.save(update_fields=['is_enabled', 'updated_at'])
    return membership


def latest_invitation(company: Company, email: str | None) -> CompanyInvitation | None:
    address = (email or '').strip().lower()
    if not address or not getattr(company, 'pk', None):
        return None
    return CompanyInvitation.objects.filter(company=company, email=address).order_by('-id').first()


def invitation_revoked_decision() -> JoinDecision:
    return JoinDecision(
        allowed=False,
        error_code=ERROR_INVITATION_REVOKED,
        message=MSG_INVITATION_REVOKED,
    )


def is_login_blocked_by_revoked_invitation(company: Company, email: str | None, user=None) -> bool:
    """
    True when the latest invitation for this email was revoked and nobody with this email (nor
    ``user``) has enabled access. Lets sign-in flows refuse before creating an account.
    """
    if user is not None and is_company_access_enabled(company, user):
        return False
    invitation = latest_invitation(company, email)
    if invitation is None or invitation.status != CompanyInvitation.STATUS_REVOKED:
        return False
    return not CompanyMembership.objects.filter(
        company=company,
        is_enabled=True,
        user__email__iexact=invitation.email,
    ).exists()


def accept_invitation(invitation: CompanyInvitation, user) -> None:
    from apps.authapi.models import UserPreference

    company = invitation.company
    first_company = not CompanyMembership.objects.filter(user=user).exclude(company=company).exists()
    set_company_access(company, user, enabled=True)
    invitation.status = CompanyInvitation.STATUS_ACCEPTED
    invitation.accepted_user = user
    invitation.accepted_at = timezone.now()
    invitation.save(update_fields=['status', 'accepted_user', 'accepted_at'])
    if first_company:
        UserPreference.objects.get_or_create(user=user, defaults={'language': invitation.language})


def apply_company_join(company: Company, user, email: str | None = None) -> JoinDecision:
    """
    Add the user to the company according to access_mode and decide whether tokens may be issued.

    Access is per company (CompanyMembership.is_enabled), so disabling one company does not
    affect other companies the same user belongs to.

    A pending invitation is accepted only when ``email`` is passed explicitly: callers pass it
    when the sign-in method proved the user owns that address. The stored ``user.email`` is not
    enough to claim an invitation, but a revoked invitation for it still blocks sign-in.
    """
    address = (email or getattr(user, 'email', '') or '').strip()
    membership = get_membership(company, user)

    if membership is not None and membership.is_enabled:
        return JoinDecision(allowed=True)

    invitation = latest_invitation(company, address)
    if invitation is not None:
        if invitation.status == CompanyInvitation.STATUS_REVOKED:
            return invitation_revoked_decision()
        if invitation.status == CompanyInvitation.STATUS_PENDING and email:
            accept_invitation(invitation, user)
            return JoinDecision(allowed=True, newly_joined=membership is None)

    if membership is not None:
        return JoinDecision(
            allowed=False,
            error_code=ERROR_ACCESS_PENDING,
            message=MSG_ACCESS_PENDING,
            newly_joined=False,
        )

    mode = company.access_mode or Company.ACCESS_PUBLIC

    if mode == Company.ACCESS_PUBLIC:
        set_company_access(company, user, enabled=True)
        return JoinDecision(allowed=True, newly_joined=True)

    if mode == Company.ACCESS_DOMAIN:
        if email_matches_allowed_domains(address, company.allowed_email_domains):
            set_company_access(company, user, enabled=True)
            return JoinDecision(allowed=True, newly_joined=True)
        set_company_access(company, user, enabled=False)
        notify_admins_new_access_request(company, user, reason='domain_mismatch')
        return JoinDecision(
            allowed=False,
            error_code=ERROR_ACCESS_DENIED,
            message=MSG_ACCESS_DENIED,
            newly_joined=True,
        )

    # Invitation only (default fallback for unknown modes).
    set_company_access(company, user, enabled=False)
    notify_admins_new_access_request(company, user, reason='invite')
    return JoinDecision(
        allowed=False,
        error_code=ERROR_ACCESS_PENDING,
        message=MSG_ACCESS_PENDING,
        newly_joined=True,
    )


def _admin_recipients(company: Company) -> list[str]:
    emails: list[str] = []
    seen: set[str] = set()
    for owner in company.owners.all().only('email'):
        addr = (owner.email or '').strip()
        if addr and addr.lower() not in seen:
            seen.add(addr.lower())
            emails.append(addr)
    if emails:
        return emails
    for staff in User.objects.filter(is_staff=True).only('email'):
        addr = (staff.email or '').strip()
        if addr and addr.lower() not in seen:
            seen.add(addr.lower())
            emails.append(addr)
    return emails


def notify_admins_new_access_request(
    company: Company,
    user,
    *,
    reason: str,
) -> None:
    recipients = _admin_recipients(company)
    if not recipients:
        logger.info(
            'No admin email recipients for company %s access request (user=%s reason=%s)',
            company.id,
            user.pk,
            reason,
        )
        return
    subject = f'[{company.name}] New account awaiting access'
    if reason == 'domain_mismatch':
        body = (
            f'A user signed in with an unauthorized email domain.\n\n'
            f'Company: {company.name}\n'
            f'User: {user.get_full_name() or user.get_username()}\n'
            f'Email: {user.email}\n'
            f'Reason: email domain not in the company allow list.\n\n'
            f'Enable company access for this user in the admin users directory.'
        )
    else:
        body = (
            f'A new user signed in and is waiting for approval (invitation-only company).\n\n'
            f'Company: {company.name}\n'
            f'User: {user.get_full_name() or user.get_username()}\n'
            f'Email: {user.email}\n\n'
            f'Enable company access for this user in the admin users directory.'
        )
    _send(subject, body, recipients)


def notify_user_access_enabled(company: Company, user) -> None:
    addr = (user.email or '').strip()
    if not addr:
        return
    subject = f'[{company.name}] Your access has been enabled'
    body = (
        f'An administrator enabled your access to {company.name}.\n\n'
        f'You can sign in again to access the application.'
    )
    _send(subject, body, [addr])


def _send(subject: str, body: str, recipients: list[str]) -> None:
    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None) or 'noreply@localhost'
    try:
        send_mail(subject, body, from_email, recipients, fail_silently=True)
    except Exception:
        logger.exception('Failed to send company access email to %s', recipients)
