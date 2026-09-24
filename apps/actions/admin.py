from __future__ import annotations

from django.contrib import admin, messages
from django.utils.safestring import mark_safe

from apps.actions.delivery import deliver_outbox_row
from apps.actions.models import ActionOutbox, ActionRule, DeliveryAttempt
class WebhookSecretWidgetMixin:
    """Mask webhook signing secrets in admin list/detail views."""

    @staticmethod
    def _mask_secret(config: dict) -> dict:
        if not isinstance(config, dict):
            return {}
        masked = dict(config)
        if masked.get('secret'):
            masked['secret'] = '••••••••'
        if masked.get('authorization_header'):
            masked['authorization_header'] = '••••••••'
        return masked


@admin.register(ActionRule)
class ActionRuleAdmin(WebhookSecretWidgetMixin, admin.ModelAdmin):
    list_display = ('name', 'company', 'event_type', 'action_kind', 'enabled', 'updated_at')
    list_filter = ('enabled', 'action_kind', 'event_type', 'company')
    search_fields = ('name', 'description', 'company__name', 'company__slug')
    autocomplete_fields = ('company',)
    readonly_fields = ('created_at', 'updated_at')

    fieldsets = (
        (
            None,
            {
                'fields': (
                    'company',
                    'name',
                    'description',
                    'enabled',
                )
            },
        ),
        (
            'Trigger',
            {
                'fields': ('event_type', 'action_kind'),
                'description': (
                    'Pick a catalog event type (not a Django signal). '
                    'Each rule delivers one action when the event fires for that company.'
                ),
            },
        ),
        (
            'Configuration (JSON)',
            {
                'fields': ('config',),
                'description': mark_safe(
                    '<p><strong>Email:</strong> '
                    '<code>{"recipients": ["ops@example.com"], "include_payload_email": false}</code></p>'
                    '<p><strong>Webhook:</strong> '
                    '<code>{"url": "https://…", "secret": "…", '
                    '"authorization_header": "Bearer …", "allow_private_urls": false}</code></p>'
                    '<p>See docs/actions.md for payload fields and n8n verification.</p>'
                ),
            },
        ),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )

    def get_readonly_fields(self, request, obj=None):
        fields = list(super().get_readonly_fields(request, obj))
        return fields

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if obj.action_kind == ActionRule.ACTION_WEBHOOK:
            cfg = obj.config or {}
            if not cfg.get('url') or not cfg.get('secret'):
                messages.warning(
                    request,
                    'Webhook rules need both config.url and config.secret before delivery succeeds.',
                )


@admin.register(ActionOutbox)
class ActionOutboxAdmin(admin.ModelAdmin):
    list_display = ('id', 'company', 'event_type', 'status', 'attempt_count', 'created_at')
    list_filter = ('status', 'event_type', 'company')
    search_fields = ('id', 'event_type', 'company__slug')
    readonly_fields = (
        'company',
        'action_rule',
        'event_type',
        'envelope',
        'status',
        'attempt_count',
        'next_attempt_at',
        'last_error',
        'created_at',
        'updated_at',
        'delivered_at',
    )
    actions = ['retry_selected_deliveries']

    @admin.action(description='Retry delivery for selected outbox rows')
    def retry_selected_deliveries(self, request, queryset):
        count = 0
        for row in queryset:
            ActionOutbox.objects.filter(pk=row.pk).update(
                status=ActionOutbox.STATUS_PENDING,
                next_attempt_at=None,
            )
            deliver_outbox_row(row.pk)
            count += 1
        messages.success(request, f'Retried delivery for {count} outbox row(s).')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(DeliveryAttempt)
class DeliveryAttemptAdmin(admin.ModelAdmin):
    list_display = ('id', 'outbox', 'status', 'http_status', 'attempt_number', 'created_at')
    list_filter = ('status',)
    search_fields = ('outbox__id', 'error_message')
    readonly_fields = (
        'outbox',
        'status',
        'http_status',
        'error_message',
        'attempt_number',
        'duration_ms',
        'created_at',
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
