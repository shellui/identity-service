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
