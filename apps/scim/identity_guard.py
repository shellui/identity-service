"""Guardrails for SCIM writes to shared global User rows."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django_scim import exceptions

from apps.scim.email_normalization import assert_scim_email_local_part_ascii, normalize_scim_email
from apps.scim.provisioner import is_scim_provisioner_user

User = get_user_model()

SCIM_UNIQUENESS_DETAIL = 'userName or email already in use.'
SCIM_IDENTITY_LOCKED_DETAIL = (
    'Cannot change userName or primary email for a user who belongs to more than one company, '
    'who has no company membership, who is the internal SCIM provisioner, '
    'or who is a platform administrator.'
)
SCIM_PASSWORD_FORBIDDEN_DETAIL = 'Password must not be sent in SCIM user resources.'


def reject_scim_password(body: dict) -> None:
    if 'password' in body:
        raise exceptions.BadRequestError(SCIM_PASSWORD_FORBIDDEN_DETAIL)


def scim_user_identity_locked(user, company_id: int) -> bool:
    """True when global email/username must not be changed or linked via this company's SCIM token."""
    if is_scim_provisioner_user(user):
        return True
    if getattr(user, 'is_staff', False) or getattr(user, 'is_superuser', False):
        return True
    company_ids = set(user.company_memberships.values_list('company_id', flat=True))
    if not company_ids:
        return True
    return company_ids != {company_id}


def _assert_email_not_taken_by_other_user(*, user, new_email: str) -> None:
    normalized = normalize_scim_email(new_email)
    if not normalized:
        return
    if user.pk is not None:
        taken = User.objects.filter(email__iexact=normalized).exclude(pk=user.pk).exists()
    else:
        taken = User.objects.filter(email__iexact=normalized).exists()
    if taken:
        raise exceptions.IntegrityError(
            detail=SCIM_UNIQUENESS_DETAIL,
            scim_type='uniqueness',
        )


def assert_scim_identity_change_allowed(
    *,
    user,
    company_id: int,
    new_email: str,
    new_username: str,
) -> None:
    if user.pk is None:
        assert_scim_email_local_part_ascii(new_email)
        _assert_email_not_taken_by_other_user(user=user, new_email=new_email)
        return
    original = User.objects.get(pk=user.pk)
    locked = scim_user_identity_locked(original, company_id)
    if locked:
        email_changed = new_email != (original.email or '')
        username_changed = new_username != (original.username or '')
    else:
        normalized_new = normalize_scim_email(new_email)
        normalized_old = normalize_scim_email(original.email or '')
        email_changed = normalized_new != normalized_old
        username_changed = (new_username or '').strip() != (original.username or '').strip()
    if not email_changed and not username_changed:
        return
    if locked:
        raise exceptions.IntegrityError(
            detail=SCIM_IDENTITY_LOCKED_DETAIL,
            scim_type='mutability',
        )
    assert_scim_email_local_part_ascii(new_email)
    if email_changed:
        _assert_email_not_taken_by_other_user(user=original, new_email=new_email)


def find_existing_user_for_scim_post(*, email: str, username: str):
    normalized_email = normalize_scim_email(email)
    username = (username or '').strip()
    if normalized_email:
        match = User.objects.filter(email__iexact=normalized_email).first()
        if match is not None:
            return match
    if username:
        return User.objects.filter(username=username).first()
    return None
