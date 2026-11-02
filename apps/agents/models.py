from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.companies.models import Company


class McpOAuthClient(models.Model):
    """Dynamically registered MCP OAuth client (public, PKCE-only)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client_id = models.CharField(max_length=64, unique=True, db_index=True)
    client_name = models.CharField(max_length=255, blank=True)
    redirect_uris = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self) -> str:
        return self.client_id


class Agent(models.Model):
    ACCESS_READ_ONLY = 'read_only'
    ACCESS_ASK = 'ask'
    ACCESS_FULL = 'full'
    ACCESS_CHOICES = [
        (ACCESS_READ_ONLY, 'Read only'),
        (ACCESS_ASK, 'Ask before changes'),
        (ACCESS_FULL, 'Full access'),
    ]

    READ_SAFE = 'safe'
    READ_SENSITIVE = 'sensitive'
    READ_CHOICES = [
        (READ_SAFE, 'Safe reads'),
        (READ_SENSITIVE, 'Sensitive data'),
    ]

    SERVICE_IDENTITY = 'identity'
    SERVICE_STORAGE = 'storage'
    SERVICE_HOSTING = 'hosting'
    SERVICE_EMAIL = 'email'
    SERVICE_SAAS = 'saas'
    SERVICE_CHOICES = [
        (SERVICE_IDENTITY, 'Identity'),
        (SERVICE_STORAGE, 'Storage'),
        (SERVICE_HOSTING, 'Hosting'),
        (SERVICE_EMAIL, 'Email'),
        (SERVICE_SAAS, 'SaaS'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='mcp_agents')
    name = models.CharField(max_length=255)
    oauth_client = models.ForeignKey(
        McpOAuthClient,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='agents',
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_mcp_agents',
    )
    access_mode = models.CharField(max_length=20, choices=ACCESS_CHOICES, default=ACCESS_ASK)
    allow_destructive_without_asking = models.BooleanField(
        default=False,
        help_text='When true, destructive tools may run without an extra approval (high risk).',
    )
    read_level = models.CharField(max_length=20, choices=READ_CHOICES, default=READ_SAFE)
    services_allowed = models.JSONField(
        default=list,
        help_text='List of service ids: identity, storage, hosting, email, saas.',
    )
    project_scope = models.CharField(
        max_length=255,
        blank=True,
        help_text='Optional project id or label chosen at consent.',
    )
    expires_at = models.DateTimeField(null=True, blank=True)
    paused_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self) -> str:
        return f'{self.company_id}:{self.name}'

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None or self.paused_at is not None:
            return False
        if self.expires_at and self.expires_at <= timezone.now():
            return False
        return True


class McpAuthorizationCode(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=128, unique=True)
    client = models.ForeignKey(McpOAuthClient, on_delete=models.CASCADE, related_name='codes')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='authorization_codes')
    redirect_uri = models.CharField(max_length=500)
    code_challenge = models.CharField(max_length=128)
    resource = models.CharField(max_length=500, blank=True, default='')
    scope = models.CharField(max_length=500, blank=True)
    expires_at = models.DateTimeField()
    redeemed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class AgentRefreshSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='refresh_sessions')
    jti = models.CharField(max_length=64, unique=True, db_index=True)
    resource = models.CharField(max_length=500, blank=True, default='')
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class McpApprovalRequest(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_APPROVED = 'approved'
    STATUS_REJECTED = 'rejected'
    STATUS_EXPIRED = 'expired'
    STATUS_EXECUTED = 'executed'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_REJECTED, 'Rejected'),
        (STATUS_EXPIRED, 'Expired'),
        (STATUS_EXECUTED, 'Executed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='approval_requests')
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='mcp_approval_requests')
    service = models.CharField(max_length=32)
    action = models.CharField(max_length=255)
    target = models.CharField(max_length=500, blank=True)
    arguments_hash = models.CharField(max_length=64)
    arguments_redacted = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    expires_at = models.DateTimeField()
    decided_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='mcp_approval_decisions',
    )
    executed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class McpCallLog(models.Model):
    id = models.BigAutoField(primary_key=True)
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='call_logs')
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='mcp_call_logs')
    service = models.CharField(max_length=32)
    tool = models.CharField(max_length=255, blank=True)
    http_method = models.CharField(max_length=10, blank=True)
    path = models.CharField(max_length=500, blank=True)
    status_code = models.PositiveSmallIntegerField(default=0)
    duration_ms = models.PositiveIntegerField(default=0)
    arguments_redacted = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
