"""Signed OAuth state for identity-owned provider callbacks."""

from __future__ import annotations

from django.core import signing

OAUTH_STATE_SALT = 'shellui.oauth.authorize.v1'
OAUTH_STATE_MAX_AGE_SECONDS = 15 * 60


def build_oauth_state(
    *,
    provider: str,
    redirect_to: str,
    company_id: int,
    company_oauth_client_id: int | None = None,
    client_timezone: str | None = None,
    client_device_id: str | None = None,
) -> str:
    payload: dict = {
        'provider': str(provider).strip().lower(),
        'redirect_to': str(redirect_to).strip(),
        'company_id': int(company_id),
    }
    if company_oauth_client_id is not None:
        payload['company_oauth_client_id'] = int(company_oauth_client_id)
    tz = (client_timezone or '').strip()
    if tz:
        payload['client_timezone'] = tz[:64]
    dev = (client_device_id or '').strip()
    if dev:
        payload['client_device_id'] = dev[:128]
    return signing.dumps(payload, salt=OAUTH_STATE_SALT)


def parse_oauth_state(state: str | None) -> tuple[dict | None, str | None]:
    """
    Returns (payload, None) or (None, error_message).
    """
    raw = (state or '').strip()
    if not raw:
        return None, 'Missing OAuth state.'
    try:
        payload = signing.loads(raw, salt=OAUTH_STATE_SALT, max_age=OAUTH_STATE_MAX_AGE_SECONDS)
    except signing.SignatureExpired:
        return None, 'OAuth state expired.'
    except signing.BadSignature:
        return None, 'Invalid OAuth state.'
    if not isinstance(payload, dict):
        return None, 'Invalid OAuth state.'
    provider = str(payload.get('provider') or '').strip().lower()
    redirect_to = str(payload.get('redirect_to') or '').strip()
    try:
        company_id = int(payload.get('company_id'))
    except (TypeError, ValueError):
        return None, 'Invalid OAuth state company_id.'
    if not provider or not redirect_to or company_id <= 0:
        return None, 'Invalid OAuth state payload.'
    out: dict = {
        'provider': provider,
        'redirect_to': redirect_to,
        'company_id': company_id,
    }
    raw_client = payload.get('company_oauth_client_id')
    if raw_client is not None and str(raw_client).strip() != '':
        try:
            cid = int(raw_client)
        except (TypeError, ValueError):
            return None, 'Invalid OAuth state company_oauth_client_id.'
        if cid > 0:
            out['company_oauth_client_id'] = cid
    tz = str(payload.get('client_timezone') or '').strip()
    if tz:
        out['client_timezone'] = tz[:64]
    dev = str(payload.get('client_device_id') or '').strip()
    if dev:
        out['client_device_id'] = dev[:128]
    return out, None
