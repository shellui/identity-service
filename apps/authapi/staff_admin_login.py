"""Django admin staff sign-in: per-account lockout and TOTP when DEBUG is false."""

from __future__ import annotations

from datetime import timedelta

from django import forms
from django.conf import settings
from django.contrib.admin.forms import AdminAuthenticationForm
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from apps.authapi.models import StaffAdminGuard
from apps.authapi.staff_totp import totp_matches


def staff_lockout_enabled() -> bool:
    """On when the process started with DEBUG false, unless the setting overrides it.

    Django's test runner sets DEBUG false after startup. The flag is captured
    at import, so the suite keeps password sign-in unless a test turns it on.
    """
    return bool(getattr(settings, 'STAFF_ADMIN_LOGIN_HARDENED', False))


def _is_django_staff(user) -> bool:
    return bool(getattr(user, 'is_staff', False) or getattr(user, 'is_superuser', False))


def staff_user_for_username(username: str | None):
    if username is None or not str(username).strip():
        return None
    User = get_user_model()
    try:
        user = User.objects.get(**{User.USERNAME_FIELD: username})
    except User.DoesNotExist:
        return None
    if not _is_django_staff(user):
        return None
    return user


def _guard(user) -> StaffAdminGuard | None:
    try:
        return user.staff_admin_guard
    except StaffAdminGuard.DoesNotExist:
        return None


def staff_account_locked(user) -> bool:
    if not staff_lockout_enabled() or not _is_django_staff(user):
        return False
    guard = _guard(user)
    if guard is None or guard.locked_until is None:
        return False
    return guard.locked_until > timezone.now()


@transaction.atomic
def record_staff_login_failure(user) -> None:
    if not staff_lockout_enabled() or user is None or not _is_django_staff(user):
        return
    guard, created = StaffAdminGuard.objects.get_or_create(user=user)
    if not created:
        guard = StaffAdminGuard.objects.select_for_update().get(pk=guard.pk)
    if guard.locked_until and guard.locked_until > timezone.now():
        return
    guard.failed_attempts = int(guard.failed_attempts or 0) + 1
    limit = max(1, int(getattr(settings, 'STAFF_ADMIN_LOCKOUT_FAILURES', 5)))
    if guard.failed_attempts >= limit:
        seconds = max(1, int(getattr(settings, 'STAFF_ADMIN_LOCKOUT_SECONDS', 900)))
        guard.locked_until = timezone.now() + timedelta(seconds=seconds)
        guard.failed_attempts = 0
    guard.save(update_fields=['failed_attempts', 'locked_until'])


@transaction.atomic
def clear_staff_login_failures(user) -> None:
    if user is None:
        return
    guard = _guard(user)
    if guard is None:
        return
    if guard.failed_attempts == 0 and guard.locked_until is None:
        return
    guard.failed_attempts = 0
    guard.locked_until = None
    guard.save(update_fields=['failed_attempts', 'locked_until'])


def staff_totp_confirmed(user) -> bool:
    guard = _guard(user)
    return bool(guard and guard.totp_secret and guard.totp_confirmed_at)


class StaffAdminAuthenticationForm(AdminAuthenticationForm):
    """Password form plus an authenticator code when staff lockout is on."""

    otp = forms.CharField(
        label='Authenticator code',
        required=False,
        widget=forms.TextInput(
            attrs={'autocomplete': 'one-time-code', 'inputmode': 'numeric'},
        ),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not staff_lockout_enabled():
            self.fields.pop('otp', None)

    def clean(self):
        if staff_lockout_enabled():
            username = self.data.get(get_user_model().USERNAME_FIELD) or self.data.get('username')
            staff = staff_user_for_username(username)
            if staff is not None and staff_account_locked(staff):
                raise forms.ValidationError(
                    'This account is temporarily locked.',
                    code='locked',
                )
        cleaned = super().clean()
        if not staff_lockout_enabled():
            return cleaned
        user = self.get_user()
        if user is None or not _is_django_staff(user):
            return cleaned
        if not staff_totp_confirmed(user):
            record_staff_login_failure(user)
            raise forms.ValidationError(
                'This staff account has no authenticator. Enroll one with enroll_staff_totp.',
                code='totp_required',
            )
        code = self.cleaned_data.get('otp') if 'otp' in self.fields else ''
        if not totp_matches(user.staff_admin_guard.totp_secret, code):
            record_staff_login_failure(user)
            raise forms.ValidationError(
                'That authenticator code is not valid.',
                code='totp_invalid',
            )
        return cleaned
