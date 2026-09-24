from __future__ import annotations

from django.contrib import admin, messages
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from apps.actions.admin_forms import ActionRuleAdminForm
from apps.actions.models import ActionOutbox, ActionRule, DeliveryAttempt
from apps.actions.registry import get_event_type


def _config_summary(obj: ActionRule) -> str:
    cfg = obj.config or {}
    if obj.action_kind == ActionRule.ACTION_EMAIL:
        count = len(cfg.get('recipients') or [])
        return f'{count} recipient(s)'
    if obj.action_kind == ActionRule.ACTION_WEBHOOK:
        url = (cfg.get('url') or '').strip()
        if not url:
            return '—'
        secret_set = 'secret set' if cfg.get('secret') else 'no secret'
        return f'{url} ({secret_set})'
    return '—'


@admin.register(ActionRule)
class ActionRuleAdmin(admin.ModelAdmin):
    form = ActionRuleAdminForm
    list_display = (
        'name',
        'company',
        'event_type',
        'action_kind',
        'enabled',
        'config_summary_display',
        'updated_at',
    )
    list_filter = ('enabled', 'action_kind', 'event_type', 'company')
    search_fields = ('name', 'description', 'company__name', 'company__slug')
    autocomplete_fields = ('company',)
    readonly_fields = ('created_at', 'updated_at', 'masked_config_preview')

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
            'Email configuration',
            {
                'fields': ('email_recipients', 'email_include_payload_email'),
                'description': 'Used when action kind is Email.',
            },
        ),
        (
            'Webhook configuration',
            {
                'fields': (
                    'webhook_url',
                    'webhook_secret',
                    'webhook_authorization_header',
                    'webhook_allow_private_urls',
                ),
                'description': mark_safe(
                    'Used when action kind is Webhook. Secrets are write-only in this form '
                    '(leave blank to keep existing values). '
                    '<code>allow_private_urls</code> is honored only when saved by a superuser, '
                    'or set deployment-wide via <code>ACTIONS_WEBHOOK_ALLOW_PRIVATE</code>.'
                ),
            },
        ),
        (
            'Stored config (preview)',
            {'fields': ('masked_config_preview',)},
        ),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )

    def get_form(self, request, obj=None, **kwargs):
        base_form = super().get_form(request, obj, **kwargs)

        class RequestForm(base_form):
            is_superuser = request.user.is_superuser

        return RequestForm

    @admin.display(description='Config')
    def config_summary_display(self, obj: ActionRule) -> str:
        return _config_summary(obj)

    @admin.display(description='Config preview (secrets redacted)')
    def masked_config_preview(self, obj: ActionRule) -> str:
        cfg = dict(obj.config or {})
        if cfg.get('secret'):
            cfg['secret'] = '••••••••'
        if cfg.get('authorization_header'):
            cfg['authorization_header'] = '••••••••'
        return format_html('<pre style="margin:0">{}</pre>', cfg)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        try:
            event = get_event_type(obj.event_type)
        except ValueError:
            event = None
        if event is not None and not event.emit_by_default:
            messages.warning(
                request,
                f"'{event.label}' is registered but not emitted by any code path yet "
                '(rules will not fire until emit_event is wired).',
            )
        if obj.action_kind == ActionRule.ACTION_WEBHOOK:
            cfg = obj.config or {}
            if not cfg.get('url') or not cfg.get('secret'):
                messages.warning(
                    request,
                    'Webhook rules need both URL and signing secret before delivery succeeds.',
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

    @admin.action(description='Re-queue selected outbox rows for delivery')
    def retry_selected_deliveries(self, request, queryset):
        updated = queryset.update(
            status=ActionOutbox.STATUS_PENDING,
            next_attempt_at=None,
            last_error='',
        )
        messages.success(
            request,
            f'Re-queued {updated} outbox row(s). Run manage.py drain_action_outbox to deliver.',
        )

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
