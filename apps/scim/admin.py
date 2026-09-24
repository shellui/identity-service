from django.contrib import admin, messages

from .models import CompanyScimToken
from .tokens import generate_scim_token


@admin.register(CompanyScimToken)
class CompanyScimTokenAdmin(admin.ModelAdmin):
    list_display = ('company', 'name', 'token_prefix', 'created_at', 'revoked_at', 'last_used_at')
    list_filter = ('company', 'revoked_at')
    search_fields = ('name', 'token_prefix', 'company__name', 'company__slug')
    readonly_fields = ('token_prefix', 'token_hash', 'created_at', 'last_used_at')
    autocomplete_fields = ('company',)

    def save_model(self, request, obj, form, change):
        if change:
            super().save_model(request, obj, form, change)
            return
        raw, prefix, digest = generate_scim_token()
        obj.token_prefix = prefix
        obj.token_hash = digest
        super().save_model(request, obj, form, change)
        messages.warning(
            request,
            f'SCIM bearer token (copy now — shown once): {raw}',
        )
