from __future__ import annotations

import json

from django.contrib import admin, messages
from django.urls import reverse
from django.utils.html import escape, format_html
from django.utils.safestring import mark_safe

from apps.actions.admin_forms import ActionRuleAdminForm
from apps.actions.models import ActionOutbox, ActionRule, DeliveryAttempt
from apps.actions.registry import get_event_type

_RECENT_DELIVERIES_INLINE_LIMIT = 20
_SHORT_TEXT_MAX = 80


def _short_text(text: str | None, max_len: int = _SHORT_TEXT_MAX) -> str:
    cleaned = (text or '').strip()
    if len(cleaned) <= max_len:
        return cleaned
    return f'{cleaned[: max_len - 1]}…'


def _config_summary(obj: ActionRule) -> str:
    cfg = obj.config or {}
    if obj.action_kind == ActionRule.ACTION_EMAIL:
        count = len(cfg.get('recipients') or [])
        parts = [f'{count} fixed recipient(s)']
        if cfg.get('include_payload_email'):
            parts.append('+ payload email')
        return ' '.join(parts)
    if obj.action_kind == ActionRule.ACTION_WEBHOOK:
        url = (cfg.get('url') or '').strip()
        if not url:
            return '—'
        secret_set = 'secret set' if cfg.get('secret') else 'no secret'
        return f'{url} ({secret_set})'
    return '—'


class DeliveryAttemptInline(admin.TabularInline):
    model = DeliveryAttempt
    fk_name = 'outbox'
    extra = 0
    can_delete = False
    show_change_link = False
    ordering = ('-created_at',)
    fields = (
        'attempt_number',
        'status',
        'http_status',
        'duration_ms',
        'error_message_short',
        'created_at',
    )
    readonly_fields = fields
    verbose_name = 'Delivery attempt'
    verbose_name_plural = 'Delivery attempts (newest first)'

    @admin.display(description='Error')
    def error_message_short(self, obj: DeliveryAttempt) -> str:
        return _short_text(obj.error_message)

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False


class ActionOutboxRecentInline(admin.TabularInline):
    model = ActionOutbox
    fk_name = 'action_rule'
    extra = 0
    can_delete = False
    show_change_link = True
    verbose_name = 'Recent delivery'
    verbose_name_plural = f'Recent deliveries (latest {_RECENT_DELIVERIES_INLINE_LIMIT})'
    fields = (
        'created_at',
        'event_type',
        'status',
        'attempt_count',
        'delivered_at',
        'last_error_short',
    )
    readonly_fields = fields

    def get_queryset(self, request):
        qs = super().get_queryset(request).order_by('-created_at')
        ids = list(qs.values_list('pk', flat=True)[:_RECENT_DELIVERIES_INLINE_LIMIT])
        return qs.filter(pk__in=ids).order_by('-created_at')

    @admin.display(description='Last error')
    def last_error_short(self, obj: ActionOutbox) -> str:
        return _short_text(obj.last_error)

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False


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
    inlines = (ActionOutboxRecentInline,)

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
                'fields': ('email_include_payload_email', 'email_recipients'),
                'description': (
                    'Used when action kind is Email. For user and SCIM user events, '
                    'enable “Also send to email from event payload” to notify the subject user.'
                ),
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
    list_display = (
        'id',
        'company',
        'action_rule_link',
        'action_kind_display',
        'event_type',
        'status',
        'attempt_count',
        'delivered_at',
        'created_at',
        'last_error_short',
    )
    list_filter = (
        'status',
        'event_type',
        'company',
        'action_rule__action_kind',
        ('created_at', admin.DateFieldListFilter),
    )
    search_fields = (
        'id',
        'event_type',
        'company__slug',
        'company__name',
        'action_rule__name',
        'last_error',
    )
    list_select_related = ('company', 'action_rule')
    ordering = ('-created_at',)
    readonly_fields = (
        'company',
        'action_rule_link',
        'event_type',
        'envelope_display',
        'status',
        'attempt_count',
        'next_attempt_at',
        'last_error',
        'created_at',
        'updated_at',
        'delivered_at',
    )
    inlines = (DeliveryAttemptInline,)
    actions = ['retry_selected_deliveries']
    fieldsets = (
        (
            None,
            {
                'fields': (
                    'company',
                    'action_rule_link',
                    'event_type',
                    'status',
                    'attempt_count',
                    'next_attempt_at',
                    'delivered_at',
                    'last_error',
                )
            },
        ),
        ('Payload', {'fields': ('envelope_display',)}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )

    @admin.display(description='Action rule', ordering='action_rule__name')
    def action_rule_link(self, obj: ActionOutbox) -> str:
        url = reverse('admin:actions_actionrule_change', args=[obj.action_rule_id])
        label = escape(obj.action_rule.name)
        return format_html('<a href="{}">{}</a>', url, label)

    @admin.display(description='Kind', ordering='action_rule__action_kind')
    def action_kind_display(self, obj: ActionOutbox) -> str:
        return obj.action_rule.get_action_kind_display()

    @admin.display(description='Last error')
    def last_error_short(self, obj: ActionOutbox) -> str:
        return _short_text(obj.last_error)

    @admin.display(description='Envelope')
    def envelope_display(self, obj: ActionOutbox) -> str:
        if not obj or not obj.envelope:
            return '-'
        text = json.dumps(obj.envelope, indent=2, sort_keys=True, ensure_ascii=False)
        return format_html(
            '<details open><summary>Envelope JSON ({} characters)</summary>'
            '<pre style="margin:0.5rem 0 0;max-height:28rem;overflow:auto;white-space:pre-wrap">'
            '{}</pre></details>',
            len(text),
            escape(text),
        )

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

    def has_view_permission(self, request, obj=None):
        return request.user.is_active and request.user.is_staff


@admin.register(DeliveryAttempt)
class DeliveryAttemptAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'outbox_link',
        'company_display',
        'event_type_display',
        'status',
        'http_status',
        'attempt_number',
        'duration_ms',
        'error_message_short',
        'created_at',
    )
    list_filter = (
        'status',
        ('created_at', admin.DateFieldListFilter),
    )
    search_fields = ('outbox__id', 'error_message')
    list_select_related = ('outbox', 'outbox__company', 'outbox__action_rule')
    ordering = ('-created_at',)
    readonly_fields = (
        'outbox_link',
        'status',
        'http_status',
        'error_message',
        'attempt_number',
        'duration_ms',
        'created_at',
    )

    @admin.display(description='Delivery')
    def outbox_link(self, obj: DeliveryAttempt) -> str:
        url = reverse('admin:actions_actionoutbox_change', args=[obj.outbox_id])
        return format_html('<a href="{}">{}</a>', url, obj.outbox_id)

    @admin.display(description='Company', ordering='outbox__company__name')
    def company_display(self, obj: DeliveryAttempt) -> str:
        return obj.outbox.company.slug

    @admin.display(description='Event', ordering='outbox__event_type')
    def event_type_display(self, obj: DeliveryAttempt) -> str:
        return obj.outbox.event_type

    @admin.display(description='Error')
    def error_message_short(self, obj: DeliveryAttempt) -> str:
        return _short_text(obj.error_message)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_view_permission(self, request, obj=None):
        return request.user.is_active and request.user.is_staff
