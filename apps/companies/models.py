from django.conf import settings
from django.db import models
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
    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name='groups',
    )
    name = models.CharField(max_length=150)
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='company_groups',
        blank=True,
    )

    class Meta:
        ordering = ['name']
        constraints = [
            models.UniqueConstraint(fields=['company', 'name'], name='company_group_unique_name_per_company'),
        ]

    def __str__(self) -> str:
        return f'{self.company_id}:{self.name}'


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
