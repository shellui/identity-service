from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.companies.models import Company


class GlobalAgentRevocation(models.Model):
    """Global MCP agent ids revoked by saas-service (blocks further token exchange)."""

    global_agent_id = models.UUIDField(primary_key=True)
    revoked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-revoked_at']


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
    SERVICE_AI = 'ai'
    SERVICE_CHOICES = [
        (SERVICE_IDENTITY, 'Identity'),
        (SERVICE_STORAGE, 'Storage'),
        (SERVICE_HOSTING, 'Hosting'),
        (SERVICE_EMAIL, 'Email'),
        (SERVICE_SAAS, 'SaaS'),
        (SERVICE_AI, 'AI'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    global_agent_id = models.UUIDField(
        null=True,
        blank=True,
        db_index=True,
        help_text='Global MCP agent id when this row was created by token exchange.',
    )
    global_company_id = models.UUIDField(
        null=True,
        blank=True,
        db_index=True,
        help_text='SaaS global company id when this regional agent is company-bound.',
    )
    company_binding_version = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text='SaaS company binding version last accepted at token exchange.',
    )
    # Caps from the last verified global subject token (never widened by regional exchange).
    global_allowed_services = models.JSONField(
        default=list,
        help_text='Service ids allowed by the last global subject token scope (exchange cap).',
    )
    global_max_access_mode = models.CharField(max_length=20, default=ACCESS_ASK)
    global_max_read_level = models.CharField(max_length=20, default=READ_SAFE)
    global_max_destructive = models.BooleanField(default=False)
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
    setup_company_id = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text='Company id for server-authorized setup context from global token exchange.',
    )
    setup_context_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Absolute end of new-company setup for this agent from the global subject token.',
    )
    setup_new_company_grant = models.BooleanField(
        default=False,
        help_text='True when setup context came from a delegated new-company grant on the global token.',
    )
    setup_mcp_session_ttl_seconds = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text='mcp_session_ttl_seconds copied from global subject during active setup.',
    )
    grant_version = models.PositiveIntegerField(
        default=0,
        help_text='Monotonic integer; bumps when MCP grants narrow or session-invalidating rules apply.',
    )
    expires_at = models.DateTimeField(null=True, blank=True)
    paused_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(
                fields=['company', 'global_agent_id'],
                condition=models.Q(global_agent_id__isnull=False),
                name='agents_company_global_agent_unique',
            ),
        ]

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
    # Authority at issuance: refresh must not widen vs this snapshot or current agent.
    grant_version = models.PositiveIntegerField(default=0)
    services_allowed = models.JSONField(default=list)
    access_mode = models.CharField(max_length=20, default=Agent.ACCESS_ASK)
    read_level = models.CharField(max_length=20, default=Agent.READ_SAFE)
    allow_destructive = models.BooleanField(default=False)
    global_company_id = models.UUIDField(null=True, blank=True)
    company_binding_version = models.PositiveIntegerField(null=True, blank=True)
    setup_company_id = models.PositiveIntegerField(null=True, blank=True)
    setup_context_expires_at = models.DateTimeField(null=True, blank=True)
    setup_new_company_grant = models.BooleanField(default=False)


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
    agent = models.ForeignKey(
        Agent,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='approval_requests',
    )
    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='mcp_approval_requests',
    )
    global_agent_id = models.UUIDField(null=True, blank=True, db_index=True)
    global_company_id = models.UUIDField(null=True, blank=True, db_index=True)
    company_binding_version = models.PositiveIntegerField(null=True, blank=True)
    setup_expires_at = models.DateTimeField(null=True, blank=True)
    global_user_sub = models.CharField(max_length=255, null=True, blank=True)
    is_company_owner_actor = models.BooleanField(
        default=False,
        help_text='Set for global-account approvals when the actor is an owner in SaaS.',
    )
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
    is_destructive = models.BooleanField(default=False)
    short_action_summary = models.CharField(max_length=500, blank=True)
    expired_event_logged = models.BooleanField(default=False)
    authority_grant_version = models.PositiveIntegerField(default=0)
    authority_global_company_id = models.UUIDField(null=True, blank=True)
    authority_company_binding_version = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class McpApprovalSessionGrant(models.Model):
    """Non-destructive write bypass for one MCP connection until TTL, revoke, or disconnect."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='approval_session_grants')
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='mcp_approval_session_grants')
    approval_request = models.ForeignKey(
        'McpApprovalRequest',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='session_grants',
    )
    service = models.CharField(max_length=32, blank=True, default='')
    action = models.CharField(max_length=255, blank=True, default='')
    arguments_hash = models.CharField(max_length=64, blank=True, default='')
    connection_id = models.CharField(max_length=128, blank=True, db_index=True)
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='mcp_approval_session_grants',
    )
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    agent_grant_version = models.PositiveIntegerField(default=0)
    global_company_id = models.UUIDField(null=True, blank=True)
    company_binding_version = models.PositiveIntegerField(null=True, blank=True)
    services_allowed = models.JSONField(default=list)
    setup_company_id = models.PositiveIntegerField(null=True, blank=True)
    setup_context_expires_at = models.DateTimeField(null=True, blank=True)
    setup_new_company_grant = models.BooleanField(default=False)
    setup_mcp_session_ttl_seconds = models.PositiveIntegerField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']


class PersonalAgentCredential(models.Model):
    """Long-lived MCP agent bearer credential for a company member (show token once, store jti hash)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.OneToOneField(Agent, on_delete=models.CASCADE, related_name='personal_credential')
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='personal_agent_credentials')
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='personal_agent_credentials',
    )
    name = models.CharField(max_length=255)
    token_jti_digest = models.CharField(max_length=64, db_index=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at <= timezone.now():
            return False
        return self.agent.is_active


class McpCallLog(models.Model):
    OUTCOME_CHOICES = (
        ('allowed', 'Allowed'),
        ('failed', 'Failed'),
        ('denied', 'Denied'),
        ('waiting_approval', 'Waiting approval'),
        ('session_used', 'Session used'),
        ('success', 'Success (legacy)'),
        ('error', 'Error (legacy)'),
        ('pending_approval', 'Pending approval (legacy)'),
    )

    id = models.BigAutoField(primary_key=True)
    agent = models.ForeignKey(
        Agent,
        on_delete=models.CASCADE,
        related_name='call_logs',
        null=True,
        blank=True,
    )
    # Set only for dashboard global-company activity. Never a stand-in for agent_id.
    global_agent_id = models.UUIDField(null=True, blank=True, db_index=True)
    global_company_id = models.UUIDField(null=True, blank=True)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='mcp_call_logs')
    service = models.CharField(max_length=32)
    tool = models.CharField(max_length=255, blank=True)
    http_method = models.CharField(max_length=10, blank=True)
    path = models.CharField(max_length=500, blank=True)
    status_code = models.PositiveSmallIntegerField(default=0)
    duration_ms = models.PositiveIntegerField(default=0)
    result = models.CharField(max_length=32, blank=True, default='')
    operation_title = models.CharField(max_length=500, blank=True, default='')
    access_kind = models.CharField(max_length=32, blank=True, default='')
    outcome = models.CharField(max_length=32, blank=True, default='', choices=OUTCOME_CHOICES)
    resource_label = models.CharField(max_length=500, blank=True, default='')
    company_name = models.CharField(max_length=255, blank=True, default='')
    approval_id = models.UUIDField(null=True, blank=True)
    error_code = models.CharField(max_length=64, blank=True, default='')
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    arguments_redacted = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
