"""Internal user attached to SCIM requests (not used for interactive login)."""

from django.contrib.auth import get_user_model

_PROVISIONER_USERNAME = 'scim-provisioner@system.local'


def is_scim_provisioner_user(user) -> bool:
    if user is None or not getattr(user, 'pk', None):
        return False
    return (getattr(user, 'username', None) or '') == _PROVISIONER_USERNAME


def get_scim_provisioner_user():
    User = get_user_model()
    user, _created = User.objects.get_or_create(
        username=_PROVISIONER_USERNAME,
        defaults={
            'email': _PROVISIONER_USERNAME,
            'is_active': True,
            'is_staff': False,
        },
    )
    if not user.has_usable_password():
        user.set_unusable_password()
        user.save(update_fields=['password'])
    return user
