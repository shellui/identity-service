from __future__ import annotations

import json
import time

import requests
from django.conf import settings

from apps.actions.ssrf import SSRFError, validate_webhook_url
from apps.actions.webhook_signing import sign_webhook_body


class WebhookDeliveryError(Exception):
    def __init__(self, message: str, *, http_status: int | None = None) -> None:
        super().__init__(message)
        self.http_status = http_status


def deliver_webhook_action(*, config: dict, envelope: dict) -> None:
    url = (config.get('url') or '').strip()
    if not url:
        raise WebhookDeliveryError('Webhook URL is not configured.')
    secret = (config.get('secret') or '').strip()
    if not secret:
        raise WebhookDeliveryError('Webhook signing secret is not configured.')
    allow_private = bool(config.get('allow_private_urls')) or getattr(
        settings,
        'ACTIONS_WEBHOOK_ALLOW_PRIVATE',
        False,
    )
    try:
        validate_webhook_url(url, allow_private=allow_private)
    except SSRFError as exc:
        raise WebhookDeliveryError(str(exc)) from exc

    body = json.dumps(envelope, separators=(',', ':'), sort_keys=True).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'shellui-identity-actions/1.0',
        **sign_webhook_body(secret=secret, body=body, webhook_id=envelope.get('id')),
    }
    auth_header = (config.get('authorization_header') or '').strip()
    if auth_header:
        headers['Authorization'] = auth_header

    timeout = getattr(settings, 'ACTIONS_WEBHOOK_TIMEOUT_SECONDS', 10.0)
    started = time.monotonic()
    try:
        response = requests.post(url, data=body, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        raise WebhookDeliveryError(str(exc)) from exc
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if response.status_code >= 400:
        raise WebhookDeliveryError(
            f'Webhook returned HTTP {response.status_code}',
            http_status=response.status_code,
        )
    _ = elapsed_ms
