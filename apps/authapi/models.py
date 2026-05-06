import uuid

from django.conf import settings
from django.db import models


class LoginEvent(models.Model):
    """
    Security audit trail for OAuth sign-in outcomes.

    Privacy notes:
    - IP is stored only as a salted hash (correlation / abuse detection, not exact location).
    - User-Agent is truncated; optional client device id is stored hashed.
    - Optional `client_timezone` is IANA zone from the client (coarse; not GPS).
    - `client_country` / `client_city` come from optional GeoIP lookup against the client IP;
      leave empty when no database is configured or lookup fails.
    """

    OUTCOME_SUCCESS = 'success'
    OUTCOME_FAILURE = 'failure'
    OUTCOME_CHOICES = [
        (OUTCOME_SUCCESS, 'Success'),
        (OUTCOME_FAILURE, 'Failure'),
    ]

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='login_events',
    )
    company = models.ForeignKey(
        'companies.Company',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='login_events',
    )
    outcome = models.CharField(max_length=16, choices=OUTCOME_CHOICES, db_index=True)
    provider = models.CharField(max_length=32, db_index=True)
    failure_reason = models.CharField(max_length=255, blank=True)
    is_staff_at_event = models.BooleanField(default=False, db_index=True)
    ip_hash = models.CharField(max_length=64, blank=True, db_index=True)
    user_agent = models.CharField(max_length=512, blank=True)
    client_timezone = models.CharField(max_length=64, blank=True)
    client_device_id_hash = models.CharField(max_length=64, blank=True)
    client_country = models.CharField(
        max_length=64,
        blank=True,
        help_text='ISO country code or name from GeoIP when configured.',
    )
    client_city = models.CharField(
        max_length=128,
        blank=True,
        help_text='City from GeoIP when configured.',
    )

    class Meta:
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['user', '-created_at']),
        ]

    def __str__(self) -> str:
        return f'LoginEvent(id={self.pk}, outcome={self.outcome}, provider={self.provider})'


class UserActivity(models.Model):
    """
    Tracks when a user last interacted in a way we care about (sign-in or token refresh).

    Distinct from ``User.last_login`` (Django session login / OAuth signal); ``last_seen_at``
    also moves on refresh-token use so MAU reflects active API clients.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='activity',
    )
    last_seen_at = models.DateTimeField(db_index=True)

    class Meta:
        ordering = ['-last_seen_at']

    def __str__(self) -> str:
        return f'UserActivity(user_id={self.user_id})'


class UserPreference(models.Model):
    LANGUAGE_EN = 'en'
    LANGUAGE_FR = 'fr'
    LANGUAGE_CHOICES = [
        (LANGUAGE_EN, 'English'),
        (LANGUAGE_FR, 'French'),
    ]

    COLOR_SCHEME_LIGHT = 'light'
    COLOR_SCHEME_DARK = 'dark'
    COLOR_SCHEME_SYSTEM = 'system'
    COLOR_SCHEME_CHOICES = [
        (COLOR_SCHEME_LIGHT, 'Light'),
        (COLOR_SCHEME_DARK, 'Dark'),
        (COLOR_SCHEME_SYSTEM, 'System'),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name='preference',
        on_delete=models.CASCADE,
    )
    theme_name = models.CharField(max_length=100, default='default')
    language = models.CharField(max_length=8, choices=LANGUAGE_CHOICES, default=LANGUAGE_EN)
    region = models.CharField(max_length=64, default='UTC')
    color_scheme = models.CharField(
        max_length=16,
        choices=COLOR_SCHEME_CHOICES,
        default=COLOR_SCHEME_SYSTEM,
    )
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['user_id']

    def __str__(self) -> str:
        return f'UserPreference(user_id={self.user_id})'


class PersonalAccessToken(models.Model):
    """
    Metadata for a long-lived JWT (ShellUI access token shape with ``pat_id``, ``pat_ro``, ``pat_agm``).

    The secret is only the signed JWT returned once at creation; we store ``jti`` to validate
    revocation; ``read_only`` / ``access_global_metrics`` must match claims ``pat_ro`` / ``pat_agm``.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.ForeignKey(
        'companies.Company',
        on_delete=models.CASCADE,
        related_name='personal_access_tokens',
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='personal_access_tokens',
    )
    jti = models.CharField(max_length=255, db_index=True)
    read_only = models.BooleanField(
        default=False,
        help_text='If True, only safe HTTP methods are allowed when this PAT is used.',
    )
    access_global_metrics = models.BooleanField(
        default=False,
        help_text='If True, PAT may call GET /api/v1/metrics/all (cross-company). Only staff may enable.',
    )
    name = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Personal access token'
        verbose_name_plural = 'Personal access tokens'
        indexes = [
            models.Index(fields=['company', '-created_at']),
            models.Index(fields=['user', '-created_at']),
        ]

    def __str__(self) -> str:
        return f'PersonalAccessToken(id={self.pk}, company_id={self.company_id})'
