"""Guardrails for SCIM writes to shared global User rows."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django_scim import exceptions

User = get_user_model()

SCIM_UNIQUENESS_DETAIL = 'userName or email already in use.'
SCIM_IDENTITY_LOCKED_DETAIL = (
    'Cannot change userName or primary email for a user who belongs to more than one company, '
    'or who is a platform administrator.'
)
SCIM_PASSWORD_FORBIDDEN_DETAIL = 'Password must not be sent in SCIM user resources.'


def reject_scim_password(body: dict) -> None:
    if 'password' in body:
        raise exceptions.BadRequestError(SCIM_PASSWORD_FORBIDDEN_DETAIL)


def scim_user_identity_locked(user, company_id: int) -> bool:
    """True when global email/username must not be changed via this company's SCIM token."""
    if getattr(user, 'is_staff', False) or getattr(user, 'is_superuser', False):
        return True
    company_ids = set(user.company_memberships.values_list('company_id', flat=True))
    if not company_ids:
        return False
    return company_ids != {company_id}


def assert_scim_identity_change_allowed(
    *,
    user,
    company_id: int,
    new_email: str,
    new_username: str,
) -> None:
    if user.pk is None:
        return
    original = User.objects.get(pk=user.pk)
    email_changed = (new_email or '').strip().lower() != (original.email or '').strip().lower()
    username_changed = (new_username or '').strip() != (original.username or '').strip()
    if not email_changed and not username_changed:
        return
    if scim_user_identity_locked(original, company_id):
        raise exceptions.IntegrityError(
            detail=SCIM_IDENTITY_LOCKED_DETAIL,
            scim_type='mutability',
        )


def find_existing_user_for_scim_post(*, email: str, username: str):
    normalized_email = (email or '').strip().lower()
    username = (username or '').strip()
    if normalized_email:
        match = User.objects.filter(email__iexact=normalized_email).first()
        if match is not None:
            return match
    if username:
        return User.objects.filter(username=username).first()
    return None
