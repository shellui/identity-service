from django.conf import settings
from django.db import models


class VerifiedEmail(models.Model):
    """Email a provider-role sign-in proved. Absent means the address is not verified."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='federation_verified_email',
    )
    email = models.EmailField()
    verified_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f'VerifiedEmail(user_id={self.user_id})'


class UpstreamAccount(models.Model):
    """Local user linked to one subject at the trusted upstream provider."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='upstream_accounts',
    )
    issuer = models.CharField(max_length=255)
    sub = models.CharField(max_length=255)
    email = models.EmailField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['issuer', 'sub'], name='federation_upstream_sub_unique'),
            models.UniqueConstraint(fields=['user', 'issuer'], name='federation_upstream_user_issuer_unique'),
        ]

    def __str__(self) -> str:
        return f'UpstreamAccount(user_id={self.user_id})'


class ProvisioningReceipt(models.Model):
    """Stored result for one idempotency key."""

    idempotency_key = models.CharField(max_length=200, unique=True)
    body_hash = models.CharField(max_length=64)
    status_code = models.PositiveSmallIntegerField()
    response_body = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f'ProvisioningReceipt({self.idempotency_key})'


class AssertionUse(models.Model):
    """A signed assertion ``jti`` that has already been accepted."""

    jti = models.CharField(max_length=128, unique=True)
    idempotency_key = models.CharField(max_length=200, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f'AssertionUse({self.jti})'


class CompanyPlan(models.Model):
    """Limits stored and served by a relying-party deployment."""

    company = models.OneToOneField(
        'companies.Company',
        on_delete=models.CASCADE,
        related_name='plan_limits',
    )
    limits = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f'CompanyPlan(company_id={self.company_id})'


class ProvisionedCompany(models.Model):
    """A company the dashboard created on this region, keyed by its global id."""

    STATUS_ACTIVE = 'active'
    STATUS_SUSPENDED = 'suspended'
    STATUS_DELETING = 'deleting'
    STATUS_CHOICES = [
        (STATUS_ACTIVE, 'Active'),
        (STATUS_SUSPENDED, 'Suspended'),
        (STATUS_DELETING, 'Deleting'),
    ]

    company = models.OneToOneField(
        'companies.Company',
        on_delete=models.CASCADE,
        related_name='provisioned',
    )
    global_company_id = models.CharField(max_length=64, unique=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    plan = models.CharField(max_length=64, blank=True, default='')
    limits_version = models.PositiveIntegerField(default=0)
    deletion_requested_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f'ProvisionedCompany(company_id={self.company_id})'
