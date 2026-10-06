from django import forms
from django.contrib import admin, messages
from django.http import Http404, HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html

from apps.actions.retention import retention_status
from apps.actions.scim_hooks import (
    emit_group_created,
    emit_group_deleted,
    emit_group_membership_changed,
    emit_group_updated,
)
from apps.authapi.provider_registry import supported_oauth_provider_slugs
from .access import normalize_allowed_domains
from .models import Company, CompanyGroup, CompanyMembership, CompanyOAuthClient, CompanyOAuthRedirect


class VerifiedEmailDomainsField(forms.CharField):
    """Platform-only SAML domain list; comma-separated in the widget."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('required', False)
        kwargs.setdefault(
            'widget',
            forms.TextInput(attrs={'size': 60, 'placeholder': 'acme.com'}),
        )
        kwargs.setdefault(
            'help_text',
            'Comma-separated domains Shellui has confirmed this company owns. '
            'Used for SAML email linking when the IdP is trusted. '
            'Not exposed to company admins in the Shellui API.',
        )
        super().__init__(*args, **kwargs)

    def prepare_value(self, value):
        return ', '.join(normalize_allowed_domains(value))

    def to_python(self, value):
        if value in self.empty_values:
            return []
        return normalize_allowed_domains(value)


class AllowedEmailDomainsField(forms.CharField):
    """Comma-separated domains in the widget; list[str] in cleaned_data / model."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('required', False)
        kwargs.setdefault(
            'widget',
            forms.TextInput(attrs={'size': 60, 'placeholder': 'acme.com, acme.co.uk'}),
        )
        kwargs.setdefault(
            'help_text',
            'Comma-separated email domains (no @). Used when Access mode is Domain. '
            'Subdomains of a listed domain also match.',
        )
        super().__init__(*args, **kwargs)

    def prepare_value(self, value):
        # Always show a plain comma-separated string — never Python list repr.
        return ', '.join(normalize_allowed_domains(value))

    def to_python(self, value):
        if value in self.empty_values:
            return []
        return normalize_allowed_domains(value)


class CompanyAdminForm(forms.ModelForm):
    """Edit allowed_email_domains as a comma-separated list instead of raw JSON."""

    allowed_email_domains = AllowedEmailDomainsField(label='Allowed email domains')
    verified_email_domains = VerifiedEmailDomainsField(label='Verified email domains (SAML)')

    class Meta:
        model = Company
        fields = (
            'name',
            'slug',
            'access_mode',
            'allowed_email_domains',
            'verified_email_domains',
            'enable_magic_link',
            'data_retention_days',
            'owners',
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            # Force widget value from normalized domains (fixes previously corrupted rows).
            self.initial['allowed_email_domains'] = normalize_allowed_domains(
                self.instance.allowed_email_domains
            )
            self.initial['verified_email_domains'] = normalize_allowed_domains(
                self.instance.verified_email_domains
            )
        self.fields['access_mode'].help_text = (
            'Public: anyone who signs in gets access for this company. '
            'Domain: only listed email domains get access; others are blocked and owners emailed. '
            'Invitation only: new members stay disabled for this company until an admin enables them.'
        )

    def clean_allowed_email_domains(self):
        return normalize_allowed_domains(self.cleaned_data.get('allowed_email_domains'))

    def clean_verified_email_domains(self):
        return normalize_allowed_domains(self.cleaned_data.get('verified_email_domains'))

    def clean(self):
        cleaned = super().clean()
        mode = cleaned.get('access_mode')
        domains = cleaned.get('allowed_email_domains') or []
        if mode == Company.ACCESS_DOMAIN and not domains:
            self.add_error(
                'allowed_email_domains',
                'Add at least one domain when Access mode is Domain.',
            )
        return cleaned


class CompanyMembershipInline(admin.TabularInline):
    model = CompanyMembership
    extra = 0
    autocomplete_fields = ('user',)
    fields = ('user', 'is_enabled', 'created_at', 'updated_at')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('user__email', 'user__username')
    verbose_name = 'Member'
    verbose_name_plural = 'Members (per-company access)'


class CompanyOAuthClientInline(admin.TabularInline):
    model = CompanyOAuthClient
    extra = 1
    fields = ('social_app', 'is_active', 'created_at')
    readonly_fields = ('created_at',)


@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    form = CompanyAdminForm
    list_display = (
        'id',
        'name',
        'slug',
        'access_mode',
        'domains_display',
        'oauth_clients_link',
    )
    list_filter = ('access_mode',)
    list_editable = ('access_mode',)
    search_fields = ('name', 'slug')
    filter_horizontal = ('owners',)
    inlines = [CompanyMembershipInline, CompanyOAuthClientInline]
    readonly_fields = ('retention_status_display',)
    fieldsets = (
        (None, {'fields': ('name', 'slug')}),
        (
            'Join access',
            {
                'fields': ('access_mode', 'allowed_email_domains'),
                'description': (
                    'Controls how new OAuth users join this company. '
                    'Access is granted per company via membership is_enabled (see Members inline).'
                ),
            },
        ),
        (
            'SAML domain verification (platform only)',
            {
                'fields': ('verified_email_domains',),
                'description': (
                    'Domains confirmed owned by this company. Required for SAML email linking when '
                    'an IdP has trusted_for_verified_domains. Set here after manual ownership proof; '
                    'company owners cannot change this through the Shellui admin API.'
                ),
            },
        ),
        (
            'Data retention (platform only)',
            {
                'fields': ('data_retention_days', 'retention_status_display'),
                'description': (
                    'Event log rows, finished webhook deliveries and SCIM provisioning events are deleted '
                    'after this many days by the purge_expired_data scheduled job. '
                    'Company owners see the value in the admin panel but cannot change it.'
                ),
            },
        ),
        (
            'Owners',
            {
                'fields': ('owners',),
                'description': 'Owners receive access-request emails and can manage the company in Shellui admin.',
            },
        ),
    )

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                '<int:company_id>/oauth-clients/',
                self.admin_site.admin_view(self.oauth_clients_view),
                name='companies_company_oauth_clients',
            ),
            path(
                '<int:company_id>/oauth-clients/add/<str:provider>/',
                self.admin_site.admin_view(self.oauth_client_add_for_provider_view),
                name='companies_company_oauth_client_add_for_provider',
            ),
        ]
        return custom_urls + urls

    @admin.display(description='Allowed domains')
    def domains_display(self, obj: Company) -> str:
        domains = normalize_allowed_domains(obj.allowed_email_domains)
        if not domains:
            return '—' if obj.access_mode != Company.ACCESS_DOMAIN else '(none)'
        text = ', '.join(domains)
        if len(text) > 48:
            return text[:45] + '…'
        return text

    @admin.display(description='Retention status')
    def retention_status_display(self, obj: Company):
        if not obj.pk:
            return '-'
        status = retention_status(obj)
        if status['stale_events']:
            return format_html(
                '<strong style="color:#ba2121">Events older than {} days are still stored (oldest: {}). '
                'The purge_expired_data job is not running: check REDIS_URL and the container logs '
                '(see docs/scheduled-jobs.md).</strong>',
                status['data_retention_days'] + 1,
                status['oldest_event_at'],
            )
        return f"OK. Oldest event: {status['oldest_event_at'] or 'none'}."

    @admin.display(description='OAuth clients')
    def oauth_clients_link(self, obj: Company):
        url = reverse('admin:companies_company_oauth_clients', args=[obj.pk])
        return format_html('<a href="{}">Manage OAuth clients</a>', url)

    @staticmethod
    def _enabled_providers() -> list[str]:
        return sorted(supported_oauth_provider_slugs())

    def oauth_clients_view(self, request, company_id: int):
        try:
            company = Company.objects.get(pk=company_id)
        except Company.DoesNotExist as exc:
            raise Http404('Company not found.') from exc
        mappings = list(
            CompanyOAuthClient.objects.filter(company=company)
            .select_related('social_app')
            .order_by('social_app__provider', 'social_app__name', 'id')
        )
        by_provider: dict[str, list[CompanyOAuthClient]] = {}
        for row in mappings:
            provider = str(row.social_app.provider or '').strip().lower()
            by_provider.setdefault(provider, []).append(row)
        provider_rows: list[dict] = []
        for provider in self._enabled_providers():
            rows = by_provider.get(provider, [])
            provider_rows.append(
                {
                    'provider': provider,
                    'enabled': bool(rows),
                    'rows': rows,
                    'add_url': reverse(
                        'admin:companies_company_oauth_client_add_for_provider',
                        args=[company.pk, provider],
                    ),
                }
            )
        context = {
            **self.admin_site.each_context(request),
            'opts': self.model._meta,
            'company': company,
            'title': f'OAuth clients for {company.name}',
            'provider_rows': provider_rows,
        }
        return TemplateResponse(request, 'admin/companies/company/oauth_clients.html', context)

    def oauth_client_add_for_provider_view(self, request, company_id: int, provider: str):
        try:
            company = Company.objects.get(pk=company_id)
        except Company.DoesNotExist as exc:
            raise Http404('Company not found.') from exc
        normalized_provider = str(provider or '').strip().lower()
        if normalized_provider not in self._enabled_providers():
            messages.error(request, f"Provider '{normalized_provider}' is not supported.")
            return HttpResponseRedirect(reverse('admin:companies_company_oauth_clients', args=[company.pk]))
        add_url = reverse('admin:socialaccount_socialapp_add')
        next_url = reverse('admin:companies_company_oauth_clients', args=[company.pk])
        redirect_to = f'{add_url}?provider={normalized_provider}&_popup=0&next={next_url}'
        return HttpResponseRedirect(redirect_to)


@admin.register(CompanyMembership)
class CompanyMembershipAdmin(admin.ModelAdmin):
    list_display = ('id', 'company', 'user', 'is_enabled', 'created_at', 'updated_at')
    list_filter = ('is_enabled', 'company')
    list_editable = ('is_enabled',)
    search_fields = ('user__email', 'user__username', 'company__name', 'company__slug')
    autocomplete_fields = ('company', 'user')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('company__name', 'user__email')


class CompanyGroupAdminForm(forms.ModelForm):
    class Meta:
        model = CompanyGroup
        fields = '__all__'

    def clean_source(self):
        if self.instance and self.instance.pk:
            return self.instance.source
        return CompanyGroup.SOURCE_MANUAL


@admin.register(CompanyGroup)
class CompanyGroupAdmin(admin.ModelAdmin):
    form = CompanyGroupAdminForm
    list_display = ('id', 'display_name', 'source', 'external_id', 'company_id')
    search_fields = ('display_name', 'external_id', 'company__name')
    list_filter = ('source', 'company')
    filter_horizontal = ('members', 'member_groups')

    def get_fields(self, request, obj=None):
        fields = list(super().get_fields(request, obj))
        if obj is None and 'source' in fields:
            return [name for name in fields if name != 'source']
        return fields

    def get_readonly_fields(self, request, obj=None):
        readonly = list(super().get_readonly_fields(request, obj))
        if obj is not None:
            readonly.append('source')
        return readonly

    def save_model(self, request, obj, form, change):
        previous = None
        if change:
            previous = CompanyGroup.objects.filter(pk=obj.pk).first()
            obj.source = (
                CompanyGroup.objects.filter(pk=obj.pk).values_list('source', flat=True).first()
                or obj.source
            )
        else:
            obj.source = CompanyGroup.SOURCE_MANUAL
        super().save_model(request, obj, form, change)
        if not change:
            emit_group_created(obj.company, obj)
        elif previous is not None:
            changed: list[str] = []
            if previous.display_name != obj.display_name:
                changed.append('display_name')
            if previous.external_id != obj.external_id:
                changed.append('external_id')
            if changed:
                emit_group_updated(obj.company, obj, changed_fields=changed)

    def save_related(self, request, form, formsets, change):
        group = form.instance
        before_users = set(group.members.values_list('pk', flat=True)) if change else set()
        before_groups = set(group.member_groups.values_list('pk', flat=True)) if change else set()
        super().save_related(request, form, formsets, change)
        after_users = set(group.members.values_list('pk', flat=True))
        after_groups = set(group.member_groups.values_list('pk', flat=True))
        for change_name, user_ids, group_ids in (
            ('members_added', after_users - before_users, after_groups - before_groups),
            ('members_removed', before_users - after_users, before_groups - after_groups),
        ):
            if user_ids or group_ids:
                emit_group_membership_changed(
                    group.company,
                    group,
                    change=change_name,
                    user_ids=sorted(user_ids),
                    nested_group_ids=sorted(group_ids),
                )

    def delete_model(self, request, obj):
        company = obj.company
        emit_group_deleted(company, obj)
        super().delete_model(request, obj)

    def delete_queryset(self, request, queryset):
        for group in queryset.select_related('company'):
            emit_group_deleted(group.company, group)
        super().delete_queryset(request, queryset)


@admin.register(CompanyOAuthClient)
class CompanyOAuthClientAdmin(admin.ModelAdmin):
    list_display = ('id', 'company', 'provider', 'social_app', 'is_active', 'created_at')
    list_filter = ('social_app__provider', 'is_active', 'company')
    search_fields = ('social_app__name', 'social_app__client_id', 'company__name')
    autocomplete_fields = ('company',)
    raw_id_fields = ('social_app',)

    @admin.display(ordering='social_app__provider')
    def provider(self, obj: CompanyOAuthClient) -> str:
        return obj.social_app.provider


@admin.register(CompanyOAuthRedirect)
class CompanyOAuthRedirectAdmin(admin.ModelAdmin):
    list_display = ('id', 'company', 'base_url', 'label', 'source', 'is_active', 'created_at')
    list_filter = ('source', 'is_active', 'company')
    search_fields = ('base_url', 'label', 'company__name')
    autocomplete_fields = ('company',)
