import uuid

from django.conf import settings
from django.db import models


class UserScimAttributes(models.Model):
    """SCIM 2.0 metadata stored beside ``auth.User`` (django-scim2 common-attribute fields)."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scim_attributes',
    )
    scim_id = models.CharField(
        max_length=254,
        null=True,
        blank=True,
        unique=True,
        db_index=True,
        help_text='Published SCIM resource id (defaults to Django user pk).',
    )
    scim_external_id = models.CharField(max_length=254, null=True, blank=True, default=None, db_index=True)
    scim_username = models.CharField(max_length=254, null=True, blank=True, default=None, db_index=True)

    class Meta:
        verbose_name = 'User SCIM attributes'
        verbose_name_plural = 'User SCIM attributes'

    def __str__(self) -> str:
        return f'UserScimAttributes(user_id={self.user_id})'


class CompanyScimToken(models.Model):
    """
    Long-lived bearer credential for IdP → SCIM provisioning (one company per token).

    The secret is shown once at creation; only ``token_hash`` is stored.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.ForeignKey(
        'companies.Company',
        on_delete=models.CASCADE,
        related_name='scim_tokens',
    )
    token_prefix = models.CharField(max_length=16, db_index=True)
    token_hash = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Company SCIM token'
        verbose_name_plural = 'Company SCIM tokens'
        indexes = [
            models.Index(fields=['company', '-created_at']),
        ]

    def __str__(self) -> str:
        label = self.name or self.token_prefix
        return f'CompanyScimToken({self.company_id}, {label})'


class ScimProvisioningEvent(models.Model):
    """Append-only SCIM/admin provisioning signals for operator visibility."""

    TYPE_GROUP_DISPLAY_NAME_CONFLICT = 'group_display_name_conflict'

    TYPE_CHOICES = [
        (TYPE_GROUP_DISPLAY_NAME_CONFLICT, 'Group display name conflict'),
    ]

    CHANNEL_SCIM = 'scim'
    CHANNEL_ADMIN = 'admin'
    CHANNEL_CHOICES = [
        (CHANNEL_SCIM, 'SCIM'),
        (CHANNEL_ADMIN, 'Admin REST'),
    ]

    company = models.ForeignKey(
        'companies.Company',
        on_delete=models.CASCADE,
        related_name='scim_provisioning_events',
    )
    event_type = models.CharField(max_length=64, choices=TYPE_CHOICES, db_index=True)
    channel = models.CharField(max_length=16, choices=CHANNEL_CHOICES)
    scim_token = models.ForeignKey(
        CompanyScimToken,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='provisioning_events',
    )
    detail = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['company', '-created_at']),
            models.Index(fields=['company', 'event_type', '-created_at']),
        ]

    def __str__(self) -> str:
        return f'ScimProvisioningEvent({self.company_id}, {self.event_type}, {self.created_at})'


class CompanyScimProvisioningState(models.Model):
    """Latest provisioning error snapshot for admin SCIM status (one row per company)."""

    company = models.OneToOneField(
        'companies.Company',
        on_delete=models.CASCADE,
        related_name='scim_provisioning_state',
    )
    last_error_at = models.DateTimeField(null=True, blank=True)
    last_error_code = models.PositiveSmallIntegerField(null=True, blank=True)
    last_error_type = models.CharField(max_length=64, blank=True, default='')
    last_error_detail = models.JSONField(default=dict, blank=True)

    def __str__(self) -> str:
        return f'CompanyScimProvisioningState(company_id={self.company_id})'
