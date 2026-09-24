from __future__ import annotations

from django import forms

from apps.actions.models import ActionRule
from apps.actions.registry import get_event_type


_PAYLOAD_EMAIL_HELP = (
    'When checked, also send to the email address in the event payload (usually '
    'data.email for user lifecycle and SCIM access events). '
    'You can combine this with fixed recipients below. '
    'If the selected event type has no payload email field, this option has no effect.'
)

_PAYLOAD_EMAIL_HELP_ACTIVE = (
    'Recommended for this event type: also deliver to {field} from the event payload '
    'when present. Combine with fixed recipients or use alone if every event includes an email.'
)

_PAYLOAD_EMAIL_HELP_INACTIVE = (
    'The selected event type does not define a payload email field — '
    'leave this unchecked and use fixed recipients only.'
)


class ActionRuleAdminForm(forms.ModelForm):
    """Structured config editing; webhook secrets are write-only (blank = keep existing)."""

    is_superuser = False

    email_include_payload_email = forms.BooleanField(
        required=False,
        label='Also send to email from event payload',
        help_text=_PAYLOAD_EMAIL_HELP,
    )
    email_recipients = forms.CharField(
        required=False,
        label='Fixed email recipients (To:)',
        help_text=(
            'Comma-separated addresses always included when this rule fires. '
            'Optional if “Also send to email from event payload” is checked and the event '
            'type supplies an email (for example user events).'
        ),
        widget=forms.TextInput(attrs={'size': 60, 'placeholder': 'ops@example.com, security@example.com'}),
    )
    webhook_url = forms.URLField(
        required=False,
        label='Webhook URL',
        assume_scheme='https',
    )
    webhook_secret = forms.CharField(
        required=False,
        label='Webhook signing secret',
        widget=forms.PasswordInput(render_value=False),
        help_text='Leave blank when editing to keep the existing secret.',
    )
    webhook_authorization_header = forms.CharField(
        required=False,
        label='Webhook Authorization header',
        widget=forms.PasswordInput(render_value=False),
        help_text='Optional full Authorization value (e.g. Bearer …). Blank when editing = unchanged.',
    )
    webhook_allow_private_urls = forms.BooleanField(
        required=False,
        label='Allow private webhook URLs',
        help_text='Superuser only. Otherwise use ACTIONS_WEBHOOK_ALLOW_PRIVATE in settings.',
    )

    class Meta:
        model = ActionRule
        fields = (
            'company',
            'name',
            'description',
            'enabled',
            'event_type',
            'action_kind',
        )

    def _selected_event_type(self) -> str | None:
        if self.data:
            raw = self.data.get('event_type')
            if raw:
                return str(raw)
        if self.instance and self.instance.pk:
            return self.instance.event_type
        return self.initial.get('event_type')

    def _payload_email_field_for_event(self, event_type: str | None) -> str | None:
        if not event_type:
            return None
        try:
            return get_event_type(event_type).email_payload_email_field
        except ValueError:
            return None

    def __init__(self, *args, **kwargs):
        self.is_superuser = getattr(self.__class__, 'is_superuser', False)
        super().__init__(*args, **kwargs)
        if not self.is_superuser:
            self.fields.pop('webhook_allow_private_urls', None)
        cfg = (self.instance.config or {}) if self.instance and self.instance.pk else {}
        if self.instance and self.instance.pk:
            self.initial.setdefault(
                'email_recipients',
                ', '.join(cfg.get('recipients') or []),
            )
            self.initial.setdefault(
                'email_include_payload_email',
                bool(cfg.get('include_payload_email')),
            )
            self.initial.setdefault('webhook_url', cfg.get('url') or '')
            if cfg.get('secret'):
                self.fields['webhook_secret'].help_text = (
                    f'{self.fields["webhook_secret"].help_text} Currently set.'
                )
            if cfg.get('authorization_header'):
                self.fields['webhook_authorization_header'].help_text = (
                    f'{self.fields["webhook_authorization_header"].help_text} Currently set.'
                )
            if self.is_superuser:
                self.initial.setdefault(
                    'webhook_allow_private_urls',
                    bool(cfg.get('allow_private_urls')),
                )
        payload_field = self._payload_email_field_for_event(self._selected_event_type())
        include_field = self.fields['email_include_payload_email']
        if payload_field:
            include_field.help_text = _PAYLOAD_EMAIL_HELP_ACTIVE.format(field=payload_field)
            include_field.widget.attrs.setdefault('class', 'email-payload-toggle')
        else:
            include_field.help_text = _PAYLOAD_EMAIL_HELP_INACTIVE

    def clean(self):
        cleaned = super().clean()
        kind = cleaned.get('action_kind')
        if kind == ActionRule.ACTION_EMAIL:
            recipients = [
                part.strip()
                for part in (cleaned.get('email_recipients') or '').split(',')
                if part.strip()
            ]
            include_payload = bool(cleaned.get('email_include_payload_email'))
            payload_field = self._payload_email_field_for_event(cleaned.get('event_type'))
            if not recipients and not (include_payload and payload_field):
                self.add_error(
                    'email_recipients',
                    'Add at least one fixed recipient, or enable payload email for an event '
                    'type that provides an email address.',
                )
        elif kind == ActionRule.ACTION_WEBHOOK:
            if not (cleaned.get('webhook_url') or '').strip():
                self.add_error('webhook_url', 'Webhook URL is required.')
            existing = (self.instance.config or {}) if self.instance.pk else {}
            secret = (cleaned.get('webhook_secret') or '').strip()
            if not secret and not existing.get('secret'):
                self.add_error('webhook_secret', 'Signing secret is required for new webhook rules.')
        return cleaned

    def _build_config(self) -> dict:
        cleaned = self.cleaned_data
        kind = cleaned['action_kind']
        existing = (self.instance.config or {}) if self.instance.pk else {}
        if kind == ActionRule.ACTION_EMAIL:
            recipients = [
                part.strip()
                for part in (cleaned.get('email_recipients') or '').split(',')
                if part.strip()
            ]
            return {
                'recipients': recipients,
                'include_payload_email': bool(cleaned.get('email_include_payload_email')),
            }
        config: dict = {
            'url': (cleaned.get('webhook_url') or '').strip(),
        }
        secret = (cleaned.get('webhook_secret') or '').strip()
        if secret:
            config['secret'] = secret
        elif existing.get('secret'):
            config['secret'] = existing['secret']
        auth = (cleaned.get('webhook_authorization_header') or '').strip()
        if auth:
            config['authorization_header'] = auth
        elif existing.get('authorization_header'):
            config['authorization_header'] = existing['authorization_header']
        if self.is_superuser and cleaned.get('webhook_allow_private_urls'):
            config['allow_private_urls'] = True
        return config

    def save(self, commit=True):
        self.instance.config = self._build_config()
        return super().save(commit=commit)
