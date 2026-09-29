"""Attach django-scim2 attribute names onto User instances via ``UserScimAttributes``."""

from __future__ import annotations

from django.contrib.auth import get_user_model

from .models import UserScimAttributes

User = get_user_model()


def scim_profile_for(user) -> UserScimAttributes:
    profile, _created = UserScimAttributes.objects.get_or_create(user=user)
    if not profile.scim_id:
        profile.scim_id = str(user.pk)
        profile.save(update_fields=['scim_id'])
    return profile


class ScimUserBridge:
    """Proxy so django-scim2 adapters can read/write ``scim_*`` fields on User."""

    def __init__(self, user):
        self.user = user
        self._profile: UserScimAttributes | None = None
        self._pending_scim_external_id: str | None = None
        self._pending_scim_username: str | None = None

    @property
    def profile(self) -> UserScimAttributes:
        if self._profile is None:
            self._profile = scim_profile_for(self.user)
        return self._profile

    @property
    def scim_id(self):
        if self.user.pk is None:
            return ''
        return self.profile.scim_id or str(self.user.pk)

    @scim_id.setter
    def scim_id(self, value):
        if self.user.pk is None:
            return
        self.profile.scim_id = value

    @property
    def scim_external_id(self):
        if self._pending_scim_external_id is not None:
            return self._pending_scim_external_id
        if self.user.pk is None:
            return ''
        return self.profile.scim_external_id or ''

    @scim_external_id.setter
    def scim_external_id(self, value):
        if self.user.pk is None:
            self._pending_scim_external_id = value or ''
            return
        self.profile.scim_external_id = value or ''

    @property
    def scim_username(self):
        if self._pending_scim_username is not None:
            return self._pending_scim_username
        if self.user.pk is None:
            return ''
        return self.profile.scim_username or ''

    @scim_username.setter
    def scim_username(self, value):
        if self.user.pk is None:
            self._pending_scim_username = value or ''
            return
        self.profile.scim_username = value or ''

    def save_scim_fields(self):
        profile = scim_profile_for(self.user)
        if self._pending_scim_external_id is not None:
            profile.scim_external_id = self._pending_scim_external_id
        if self._pending_scim_username is not None:
            profile.scim_username = self._pending_scim_username
        if not profile.scim_id:
            profile.scim_id = str(self.user.pk)
        profile.save()
        self._profile = profile
        self._pending_scim_external_id = None
        self._pending_scim_username = None

    def __getattr__(self, item):
        return getattr(self.user, item)

    @property
    def scim_groups(self):
        from apps.companies.models import CompanyGroup

        return CompanyGroup.objects.none()

    def save(self, *args, **kwargs):
        self.user.save(*args, **kwargs)
        self.save_scim_fields()

    @property
    def is_active(self):
        return self.user.is_active

    @is_active.setter
    def is_active(self, value):
        self.user.is_active = value

    @property
    def username(self):
        return self.user.username

    @username.setter
    def username(self, value):
        self.user.username = value

    @property
    def email(self):
        return self.user.email

    @email.setter
    def email(self, value):
        self.user.email = value

    @property
    def first_name(self):
        return self.user.first_name

    @first_name.setter
    def first_name(self, value):
        self.user.first_name = value

    @property
    def last_name(self):
        return self.user.last_name

    @last_name.setter
    def last_name(self, value):
        self.user.last_name = value

    @property
    def date_joined(self):
        return self.user.date_joined

    def set_password(self, raw_password):
        self.user.set_password(raw_password)

    def has_usable_password(self):
        return self.user.has_usable_password()

    @property
    def pk(self):
        return self.user.pk

    @property
    def id(self):
        return self.user.id

    def companies(self):
        return self.user.companies
