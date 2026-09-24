from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils.text import slugify
from allauth.socialaccount.models import SocialApp


class CompanyMembership(models.Model):
    """Per-company membership and access flag (a user may belong to many companies)."""

    company = models.ForeignKey(
        'Company',
        on_delete=models.CASCADE,
        related_name='memberships',
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='company_memberships',
    )
    is_enabled = models.BooleanField(
        default=True,
        help_text='When false, the user cannot obtain tokens for this company.',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['company_id', 'user_id']
        constraints = [
            models.UniqueConstraint(
                fields=['company', 'user'],
                name='company_membership_unique_user_per_company',
            ),
        ]

    def __str__(self) -> str:
        state = 'enabled' if self.is_enabled else 'disabled'
        return f'{self.company_id}:{self.user_id}:{state}'


class Company(models.Model):
    ACCESS_PUBLIC = 'public'
    ACCESS_DOMAIN = 'domain'
    ACCESS_INVITE = 'invite'
    ACCESS_MODE_CHOICES = [
        (ACCESS_PUBLIC, 'Public'),
        (ACCESS_DOMAIN, 'Domain'),
        (ACCESS_INVITE, 'Invitation only'),
    ]

    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='companies',
        blank=True,
        through='CompanyMembership',
        through_fields=('company', 'user'),
    )
    owners = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='owned_companies',
        blank=True,
    )
    access_mode = models.CharField(
        max_length=20,
        choices=ACCESS_MODE_CHOICES,
        default=ACCESS_PUBLIC,
        help_text=(
            'How new OAuth users join: Public (open), Domain (email allow list), '
            'or Invitation only (admin must enable the user).'
        ),
    )
    allowed_email_domains = models.JSONField(
        default=list,
        blank=True,
        help_text='Lowercase domains without @ (e.g. ["acme.com"]). Used when access mode is Domain.',
    )

    class Meta:
        ordering = ['name']

    def __str__(self) -> str:
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(self.name)
            candidate = base_slug
            suffix = 1
            while Company.objects.filter(slug=candidate).exclude(pk=self.pk).exists():
                candidate = f'{base_slug}-{suffix}'
                suffix += 1
            self.slug = candidate
        super().save(*args, **kwargs)


class CompanyGroup(models.Model):
    SOURCE_MANUAL = 'manual'
    SOURCE_SCIM = 'scim'
    SOURCE_CHOICES = [
        (SOURCE_MANUAL, 'Manual'),
        (SOURCE_SCIM, 'SCIM'),
    ]

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name='groups',
    )
    source = models.CharField(
        max_length=20,
        choices=SOURCE_CHOICES,
        default=SOURCE_MANUAL,
        db_index=True,
        help_text='manual = Shellui admin; scim = IdP provisioning (read-only in admin REST).',
    )
    display_name = models.CharField(
        max_length=150,
        help_text='SCIM displayName (unique per company).',
    )
    external_id = models.CharField(
        max_length=254,
        null=True,
        blank=True,
        db_index=True,
        help_text='SCIM externalId from the provisioning client (unique per company when set).',
    )
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='company_groups',
        blank=True,
        help_text='Direct user members (SCIM members with type User).',
    )
    member_groups = models.ManyToManyField(
        'self',
        symmetrical=False,
        related_name='parent_groups',
        blank=True,
        help_text='Nested SCIM group members (type Group). Same company only; cycles rejected.',
    )

    class Meta:
        ordering = ['display_name']
        constraints = [
            models.UniqueConstraint(
                fields=['company', 'display_name'],
                name='company_group_unique_display_name_per_company',
            ),
            models.UniqueConstraint(
                fields=['company', 'external_id'],
                name='company_group_unique_external_id_per_company',
                condition=Q(external_id__isnull=False) & ~Q(external_id=''),
            ),
        ]

    @property
    def scim_external_id(self):
        return self.external_id

    @scim_external_id.setter
    def scim_external_id(self, value):
        self.external_id = (value or '').strip() or None

    @classmethod
    def create_scim_provisioned(cls, *, company, display_name, **fields):
        group = cls(
            company=company,
            display_name=display_name,
            source=cls.SOURCE_SCIM,
            **fields,
        )
        group.save(scim_source=True)
        return group

    def save(self, *args, **kwargs):
        scim_source = kwargs.pop('scim_source', False)
        previous = None
        if self.pk:
            previous = (
                CompanyGroup.objects.filter(pk=self.pk).values_list('source', flat=True).first()
            )
        if self.source == self.SOURCE_SCIM and not scim_source:
            if not self.pk or previous != self.SOURCE_SCIM:
                raise ValueError(
                    'Company group source scim may only be set via SCIM provisioning.'
                )
        if previous == self.SOURCE_SCIM and self.source == self.SOURCE_MANUAL:
            raise ValueError('SCIM-provisioned groups cannot be changed to manual source.')
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f'{self.company_id}:{self.display_name}'


class CompanyOAuthClient(models.Model):
    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name='oauth_clients',
    )
    social_app = models.ForeignKey(
        SocialApp,
        on_delete=models.CASCADE,
        related_name='company_oauth_clients',
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['social_app__provider', 'social_app__name', 'id']
        constraints = [
            models.UniqueConstraint(
                fields=['company', 'social_app'],
                name='company_oauth_client_unique_social_app_per_company',
            ),
        ]

    def __str__(self) -> str:
        return f'{self.company_id}:{self.social_app.provider}:{self.social_app.name}'


class CompanyOAuthRedirect(models.Model):
    """Allowed post-OAuth bounce origins for a company (shell /login/callback hosts)."""

    SOURCE_MANUAL = 'manual'
    SOURCE_HOSTING = 'hosting'
    SOURCE_CHOICES = [
        (SOURCE_MANUAL, 'Manual'),
        (SOURCE_HOSTING, 'Hosting'),
    ]

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name='oauth_redirect_allowlist',
    )
    base_url = models.CharField(
        max_length=500,
        help_text='Canonical origin only (e.g. https://app.example.com).',
    )
    label = models.CharField(blank=True, max_length=150)
    source = models.CharField(
        max_length=20,
        choices=SOURCE_CHOICES,
        default=SOURCE_MANUAL,
        help_text='manual = owner-managed; hosting = synced from hosting-service preview sites.',
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['id']
        constraints = [
            models.UniqueConstraint(
                fields=['company', 'base_url'],
                name='company_oauth_redirect_unique_base_per_company',
            ),
        ]

    def __str__(self) -> str:
        return f'{self.company_id}:{self.base_url}'
