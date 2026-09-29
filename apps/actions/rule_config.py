"""Build and validate ActionRule.config for admin UI and REST API."""

from __future__ import annotations

from django.core.exceptions import ValidationError

from apps.actions.models import ActionRule
from apps.actions.webhook_signing import generate_webhook_signing_secret


def _secret_hint(secret: str) -> str | None:
    s = (secret or '').strip()
    if len(s) < 4:
        return None
    return s[-4:]


def build_webhook_config(
    *,
    existing: dict,
    url: str | None = None,
    secret: str | None = None,
    authorization_header: str | None = None,
    allow_private_urls: bool | None = None,
    is_superuser: bool,
    partial: bool,
    auto_generate_secret: bool = False,
) -> tuple[dict, str | None]:
    """
    Build webhook rule config.

    Returns ``(config, generated_secret)``. ``generated_secret`` is set when a new
    ``whsec_`` secret was created because none was provided on create.
    """
    cfg = dict(existing or {})
    generated_secret: str | None = None
    previous_url = (existing.get('url') or '').strip()
    url_changed = False
    if url is not None or not partial:
        new_url = (url if url is not None else cfg.get('url') or '').strip()
        url_changed = url is not None and new_url != previous_url
        cfg['url'] = new_url
    if not cfg.get('url'):
        raise ValidationError('Webhook url is required.')

    if secret is not None:
        secret_s = (secret or '').strip()
        if secret_s:
            cfg['secret'] = secret_s
        elif existing.get('secret'):
            cfg['secret'] = existing['secret']
        elif not partial and auto_generate_secret:
            generated_secret = generate_webhook_signing_secret()
            cfg['secret'] = generated_secret
        elif not partial:
            raise ValidationError('Webhook signing secret is required for new webhook rules.')
    elif not partial and not cfg.get('secret'):
        if auto_generate_secret:
            generated_secret = generate_webhook_signing_secret()
            cfg['secret'] = generated_secret
        else:
            raise ValidationError('Webhook signing secret is required for new webhook rules.')
    elif existing.get('secret'):
        cfg['secret'] = existing['secret']

    if authorization_header is not None:
        auth_s = (authorization_header or '').strip()
        if auth_s:
            cfg['authorization_header'] = auth_s
        else:
            cfg.pop('authorization_header', None)
    elif existing.get('authorization_header'):
        cfg['authorization_header'] = existing['authorization_header']

    if is_superuser:
        if allow_private_urls is True:
            cfg['allow_private_urls'] = True
        elif allow_private_urls is False:
            cfg.pop('allow_private_urls', None)
    elif url_changed:
        cfg.pop('allow_private_urls', None)
    elif not partial and existing.get('allow_private_urls'):
        cfg['allow_private_urls'] = True
    return cfg, generated_secret


def mask_config_for_response(config: dict, action_kind: str) -> dict:
    cfg = dict(config or {})
    if action_kind == ActionRule.ACTION_WEBHOOK:
        raw_secret = (config or {}).get('secret') or ''
        cfg.pop('secret', None)
        cfg.pop('authorization_header', None)
        cfg['has_secret'] = bool(raw_secret)
        hint = _secret_hint(str(raw_secret))
        if hint:
            cfg['secret_hint'] = hint
        cfg['authorization_header_set'] = bool((config or {}).get('authorization_header'))
    return cfg
