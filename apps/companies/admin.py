from django import forms
from django.contrib import admin, messages
from django.http import Http404, HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html

from apps.authapi.oauth import SUPPORTED_OAUTH_PROVIDERS
from .access import normalize_allowed_domains
from .models import Company, CompanyGroup, CompanyMembership, CompanyOAuthClient, CompanyOAuthRedirect


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

    class Meta:
        model = Company
        fields = (
            'name',
            'slug',
            'access_mode',
            'allowed_email_domains',
            'owners',
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            # Force widget value from normalized domains (fixes previously corrupted rows).
            self.initial['allowed_email_domains'] = normalize_allowed_domains(
                self.instance.allowed_email_domains
            )
        self.fields['access_mode'].help_text = (
            'Public: anyone who signs in gets access for this company. '
            'Domain: only listed email domains get access; others are blocked and owners emailed. '
            'Invitation only: new members stay disabled for this company until an admin enables them.'
        )

    def clean_allowed_email_domains(self):
        return normalize_allowed_domains(self.cleaned_data.get('allowed_email_domains'))

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

    @admin.display(description='OAuth clients')
    def oauth_clients_link(self, obj: Company):
        url = reverse('admin:companies_company_oauth_clients', args=[obj.pk])
        return format_html('<a href="{}">Manage OAuth clients</a>', url)

    @staticmethod
    def _enabled_providers() -> list[str]:
        return sorted(SUPPORTED_OAUTH_PROVIDERS)

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


@admin.register(CompanyGroup)
class CompanyGroupAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'company_id')
    search_fields = ('name', 'company__name')
    list_filter = ('company',)
    filter_horizontal = ('members',)


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
