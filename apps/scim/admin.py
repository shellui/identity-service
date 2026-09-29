from django.contrib import admin, messages

from apps.actions.token_hooks import emit_scim_token_created, emit_scim_token_revoked

from .models import CompanyScimProvisioningState, CompanyScimToken, ScimProvisioningEvent
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
            if 'revoked_at' in form.changed_data and obj.revoked_at is not None:
                emit_scim_token_revoked(obj.company, obj)
            return
        raw, prefix, digest = generate_scim_token()
        obj.token_prefix = prefix
        obj.token_hash = digest
        super().save_model(request, obj, form, change)
        emit_scim_token_created(obj.company, obj)
        messages.warning(
            request,
            f'SCIM bearer token (copy now — shown once): {raw}',
        )


@admin.register(ScimProvisioningEvent)
class ScimProvisioningEventAdmin(admin.ModelAdmin):
    list_display = ('id', 'company', 'event_type', 'channel', 'created_at')
    list_filter = ('event_type', 'channel', 'company')
    search_fields = ('company__name', 'company__slug')
    readonly_fields = (
        'company',
        'event_type',
        'channel',
        'scim_token',
        'detail',
        'created_at',
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(CompanyScimProvisioningState)
class CompanyScimProvisioningStateAdmin(admin.ModelAdmin):
    list_display = ('company', 'last_error_at', 'last_error_code', 'last_error_type')
    search_fields = ('company__name', 'company__slug')
    readonly_fields = (
        'company',
        'last_error_at',
        'last_error_code',
        'last_error_type',
        'last_error_detail',
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
