import uuid

from django.conf import settings
from django.db import models


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
    Metadata for a long-lived JWT (Shellui access token shape with ``pat_id``, ``pat_ro``, ``pat_agm``).

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


class RefreshTokenSession(models.Model):
    """
    Server-side refresh token registry for rotation and logout revocation.

    Each issued refresh JWT ``jti`` maps to one row. Rotation revokes the prior row and
    issues a new ``jti`` in the same ``family_id``. Presenting a revoked refresh token
    revokes the entire family (reuse detection).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='refresh_token_sessions',
    )
    company = models.ForeignKey(
        'companies.Company',
        on_delete=models.CASCADE,
        related_name='refresh_token_sessions',
    )
    jti = models.CharField(max_length=255, unique=True, db_index=True)
    family_id = models.UUIDField(db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['family_id', 'revoked_at']),
        ]

    def __str__(self) -> str:
        return f'RefreshTokenSession(id={self.pk}, user_id={self.user_id})'


class OAuthSessionDeliveryCode(models.Model):
    """
    One-time OAuth login delivery code exchanged for JWTs via POST /api/v1/oauth/session.

    Replaces URL-fragment token delivery (H-03). Codes are short-lived and single-use.
    """

    code = models.CharField(max_length=64, unique=True, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='oauth_session_delivery_codes',
    )
    company = models.ForeignKey(
        'companies.Company',
        on_delete=models.CASCADE,
        related_name='oauth_session_delivery_codes',
    )
    redirect_to = models.CharField(max_length=2048)
    token_payload = models.JSONField()
    expires_at = models.DateTimeField(db_index=True)
    redeemed_at = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self) -> str:
        return f'OAuthSessionDeliveryCode(code={self.code[:8]}…)'


class MagicLinkToken(models.Model):
    """
    One-time company-scoped magic link for passwordless email login.

    Only a SHA-256 hash of the token is stored; the raw secret exists only in email and verify requests.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.ForeignKey(
        'companies.Company',
        on_delete=models.CASCADE,
        related_name='magic_link_tokens',
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='magic_link_tokens',
    )
    email = models.EmailField(max_length=254, db_index=True)
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    redirect_to = models.CharField(max_length=2048)
    expires_at = models.DateTimeField(db_index=True)
    consumed_at = models.DateTimeField(null=True, blank=True, db_index=True)
    client_timezone = models.CharField(max_length=64, blank=True)
    client_device_id = models.CharField(max_length=128, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['company', 'email', '-created_at']),
        ]

    def __str__(self) -> str:
        return f'MagicLinkToken(id={self.pk}, email={self.email})'


class OidcSocialAccountKeyMigration(models.Model):
    """Audit rows updated by migration 0014 (reverse restores only these accounts)."""

    social_account_id = models.BigIntegerField(db_index=True)
    old_provider = models.CharField(max_length=200)
    old_uid = models.CharField(max_length=255)
    migrated_at = models.DateTimeField(auto_now_add=True)
