"""
Record sign-in events for Django admin username/password sign-in (contrib.admin login form).

Uses auth signals so we do not fork or wrap AdminSite. Scoped to requests whose path is the
admin login URL (success and failure).

Also deletes unused magic-link tokens of an account saved as staff or superuser (for
example in Django admin): staff never sign in with a magic link.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.db.models.signals import post_save
from django.dispatch import receiver

from .login_audit import LoginOutcome, record_login_event
from .magic_link import delete_unused_magic_link_tokens_for_user, is_staff_account
from .user_activity import touch_user_last_seen

User = get_user_model()

PROVIDER_DJANGO_ADMIN = 'django_admin'


def _is_django_admin_login_path(request) -> bool:
    if not request:
        return False
    path = (getattr(request, 'path', None) or '').rstrip('/')
    return path.endswith('/admin/login')


def _user_from_failed_credentials(credentials: dict | None) -> User | None:
    if not credentials:
        return None
    field = User.USERNAME_FIELD
    username = credentials.get(field) or credentials.get('username')
    if username is None or not str(username).strip():
        return None
    try:
        return User.objects.get(**{field: username})
    except User.DoesNotExist:
        return None


@receiver(user_logged_in)
def login_event_on_admin_session_login(sender, request, user, **kwargs):
    if not _is_django_admin_login_path(request):
        return
    record_login_event(
        request=request,
        outcome=LoginOutcome.SUCCESS,
        provider=PROVIDER_DJANGO_ADMIN,
        user=user,
    )
    touch_user_last_seen(user)


@receiver(user_login_failed)
def login_event_on_admin_session_login_failed(sender, credentials, request, **kwargs):
    if not _is_django_admin_login_path(request):
        return
    candidate = _user_from_failed_credentials(credentials if isinstance(credentials, dict) else None)
    record_login_event(
        request=request,
        outcome=LoginOutcome.FAILURE,
        provider=PROVIDER_DJANGO_ADMIN,
        user=candidate,
        failure_reason='Invalid credentials',
    )


@receiver(post_save, sender=User, dispatch_uid='authapi_staff_magic_link_tokens')
def delete_magic_link_tokens_of_staff(sender, instance, raw=False, **kwargs):
    """A token issued before the account became staff must not sign it in."""
    if raw or not is_staff_account(instance):
        return
    delete_unused_magic_link_tokens_for_user(instance)
