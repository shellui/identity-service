from __future__ import annotations

from django import forms

from apps.actions.models import ActionRule


class ActionRuleAdminForm(forms.ModelForm):
    """Structured webhook config; secrets are write-only (blank = keep existing)."""

    is_superuser = False

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

    def __init__(self, *args, **kwargs):
        self.is_superuser = getattr(self.__class__, 'is_superuser', False)
        super().__init__(*args, **kwargs)
        if not self.is_superuser:
            self.fields.pop('webhook_allow_private_urls', None)
        if 'action_kind' in self.fields:
            self.fields['action_kind'].initial = ActionRule.ACTION_WEBHOOK
        cfg = (self.instance.config or {}) if self.instance and self.instance.pk else {}
        if self.instance and self.instance.pk:
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

    def clean(self):
        cleaned = super().clean()
        cleaned['action_kind'] = ActionRule.ACTION_WEBHOOK
        if not (cleaned.get('webhook_url') or '').strip():
            self.add_error('webhook_url', 'Webhook URL is required.')
        existing = (self.instance.config or {}) if self.instance.pk else {}
        secret = (cleaned.get('webhook_secret') or '').strip()
        if not secret and not existing.get('secret'):
            from apps.actions.webhook_signing import generate_webhook_signing_secret

            cleaned['webhook_secret'] = generate_webhook_signing_secret()
        return cleaned

    def _build_config(self) -> dict:
        cleaned = self.cleaned_data
        existing = (self.instance.config or {}) if self.instance.pk else {}
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
        self.instance.action_kind = ActionRule.ACTION_WEBHOOK
        self.instance.config = self._build_config()
        return super().save(commit=commit)
