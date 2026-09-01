"""Signed pending OAuth confirmation (account picker before issuing JWTs)."""

from __future__ import annotations

from django.core import signing

OAUTH_CONFIRM_SALT = 'shellui.oauth.confirm.v1'
OAUTH_CONFIRM_MAX_AGE_SECONDS = 5 * 60


def build_oauth_confirm_token(
    *,
    user_id: int,
    company_id: int,
    provider: str,
    redirect_to: str,
    avatar_url: str | None = None,
    company_oauth_client_id: int | None = None,
    client_timezone: str | None = None,
    client_device_id: str | None = None,
) -> str:
    payload: dict = {
        'user_id': int(user_id),
        'company_id': int(company_id),
        'provider': str(provider).strip().lower(),
        'redirect_to': str(redirect_to).strip(),
    }
    avatar = (avatar_url or '').strip()
    if avatar:
        payload['avatar_url'] = avatar[:500]
    if company_oauth_client_id is not None:
        payload['company_oauth_client_id'] = int(company_oauth_client_id)
    tz = (client_timezone or '').strip()
    if tz:
        payload['client_timezone'] = tz[:64]
    dev = (client_device_id or '').strip()
    if dev:
        payload['client_device_id'] = dev[:128]
    return signing.dumps(payload, salt=OAUTH_CONFIRM_SALT)


def parse_oauth_confirm_token(token: str | None) -> tuple[dict | None, str | None]:
    raw = (token or '').strip()
    if not raw:
        return None, 'Missing confirmation token.'
    try:
        payload = signing.loads(raw, salt=OAUTH_CONFIRM_SALT, max_age=OAUTH_CONFIRM_MAX_AGE_SECONDS)
    except signing.SignatureExpired:
        return None, 'Confirmation expired. Start sign-in again.'
    except signing.BadSignature:
        return None, 'Invalid confirmation token.'
    if not isinstance(payload, dict):
        return None, 'Invalid confirmation token.'
    try:
        user_id = int(payload.get('user_id'))
        company_id = int(payload.get('company_id'))
    except (TypeError, ValueError):
        return None, 'Invalid confirmation payload.'
    provider = str(payload.get('provider') or '').strip().lower()
    redirect_to = str(payload.get('redirect_to') or '').strip()
    if user_id <= 0 or company_id <= 0 or not provider or not redirect_to:
        return None, 'Invalid confirmation payload.'
    out: dict = {
        'user_id': user_id,
        'company_id': company_id,
        'provider': provider,
        'redirect_to': redirect_to,
    }
    avatar = str(payload.get('avatar_url') or '').strip()
    if avatar:
        out['avatar_url'] = avatar
    raw_client = payload.get('company_oauth_client_id')
    if raw_client is not None and str(raw_client).strip() != '':
        try:
            cid = int(raw_client)
        except (TypeError, ValueError):
            return None, 'Invalid confirmation company_oauth_client_id.'
        if cid > 0:
            out['company_oauth_client_id'] = cid
    tz = str(payload.get('client_timezone') or '').strip()
    if tz:
        out['client_timezone'] = tz[:64]
    dev = str(payload.get('client_device_id') or '').strip()
    if dev:
        out['client_device_id'] = dev[:128]
    return out, None
