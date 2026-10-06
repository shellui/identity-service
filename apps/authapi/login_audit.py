"""
Login audit helpers: privacy-oriented fields (hashed IP, truncated UA) and event recording.

Timezone: the server does not know the user's IANA timezone unless the client sends it
(`client_timezone` query param on /authorize, or JSON on social login). Browser JS can use
`Intl.DateTimeFormat().resolvedOptions().timeZone` and pass that value — it is a coarse hint,
not precise geolocation, and is optional.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path
from typing import TYPE_CHECKING

from django.conf import settings

from apps.actions.event_log import record_event
from apps.actions.models import EventLog
from apps.actions.registry import get_event_type

if TYPE_CHECKING:
    from apps.companies.models import Company
    from django.contrib.auth.base_user import AbstractBaseUser
    from django.http import HttpRequest

_IP_HASH_SALT = 'login_audit.ip'
_DEVICE_HASH_SALT = 'login_audit.device'


class LoginOutcome:
    SUCCESS = 'success'
    FAILURE = 'failure'


LOGIN_EVENT_TYPES = {
    LoginOutcome.SUCCESS: 'identity.auth.login.succeeded',
    LoginOutcome.FAILURE: 'identity.auth.login.failed',
}


def _parse_ip_hop(hop: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Strip ports or brackets from an X-Forwarded-For hop; return None if not a valid IP."""
    raw = hop.strip()
    if not raw:
        return None
    if raw.startswith('['):
        end = raw.find(']')
        if end == -1:
            return None
        candidate = raw[1:end].strip()
    elif raw.count(':') == 1 and '.' in raw:
        candidate, _, _port = raw.partition(':')
        candidate = candidate.strip()
    else:
        candidate = raw
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def _addr_for_trusted_match(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _ip_in_trusted_proxies(ip: str, trusted: tuple[str, ...]) -> bool:
    parsed = _parse_ip_hop(ip)
    if parsed is None:
        return False
    addr = _addr_for_trusted_match(parsed)
    for entry in trusted:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if '/' in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def _xff_hops(xff: str) -> list[str]:
    return [part.strip() for part in xff.split(',') if part.strip()]


def _client_ip_from_xff(xff: str, trusted: tuple[str, ...]) -> str | None:
    """
    Walk ``X-Forwarded-For`` from the right (closest to this server).

    Skip hops listed in ``trusted``; return the first untrusted address (the client).
    Invalid hops are skipped. Hops may include IPv4 ports or bracketed IPv6.
    """
    hops = _xff_hops(xff)
    if not hops:
        return None
    for hop in reversed(hops):
        parsed = _parse_ip_hop(hop)
        if parsed is None:
            continue
        if _ip_in_trusted_proxies(hop, trusted):
            continue
        return str(parsed)
    return None


def client_ip_rate_limit_key(ip: str | None) -> str:
    """
    Stable rate-limit bucket for a client IP.

    IPv6 addresses are grouped by /64 prefix so a single subnet cannot exhaust
    distinct buckets. Audit logging should use the full address from ``get_client_ip``.
    """
    if not ip or not str(ip).strip():
        return 'unknown'
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return str(ip).strip()
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if isinstance(addr, ipaddress.IPv6Address):
        prefix = ipaddress.IPv6Network(f'{addr}/64', strict=False)
        return f'{prefix.network_address}/64'
    return str(addr)


def get_client_ip(request: HttpRequest) -> str | None:
    """
    Best-effort client IP for audit and rate limiting.

    When ``REMOTE_ADDR`` is listed in ``settings.TRUSTED_PROXY_IPS``, parse
    ``X-Forwarded-For`` from the right and use the first hop that is not a trusted
    proxy (supports comma-separated chains and CIDR entries in ``TRUSTED_PROXY_IPS``).
    Otherwise return ``REMOTE_ADDR`` so clients cannot spoof audit IPs by sending
    ``X-Forwarded-For`` directly to the app.
    """
    remote = request.META.get('REMOTE_ADDR')
    remote_parsed = _parse_ip_hop(remote) if isinstance(remote, str) else None
    remote_addr = str(remote_parsed) if remote_parsed is not None else None
    if remote_addr is None and isinstance(remote, str) and remote.strip():
        remote_addr = remote.strip()
    trusted = tuple(getattr(settings, 'TRUSTED_PROXY_IPS', ()) or ())
    if remote_addr and trusted and _ip_in_trusted_proxies(remote_addr, trusted):
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        if isinstance(xff, str) and xff.strip():
            from_xff = _client_ip_from_xff(xff.strip(), trusted)
            if from_xff:
                return from_xff
    if remote_addr:
        return remote_addr
    return None


def hash_ip(ip: str | None) -> str | None:
    """One-way hash of IP for correlation without storing raw addresses (GDPR-friendly)."""
    if not ip or not str(ip).strip():
        return None
    digest = hashlib.sha256(
        f'{_IP_HASH_SALT}:{settings.SECRET_KEY}:{ip.strip()}'.encode('utf-8')
    ).hexdigest()
    return digest


def hash_client_device_id(device_id: str | None) -> str | None:
    """Hash optional first-party device id from client storage (never store raw)."""
    if not device_id or not str(device_id).strip():
        return None
    raw = str(device_id).strip()
    if len(raw) > 128:
        return None
    return hashlib.sha256(
        f'{_DEVICE_HASH_SALT}:{settings.SECRET_KEY}:{raw}'.encode('utf-8')
    ).hexdigest()


_IANA_TZ_RE = re.compile(r'^[A-Za-z0-9_+/\-]{1,64}$')


def normalize_client_timezone(value: str | None) -> str:
    """Validate IANA-like timezone strings from the client; return '' if invalid."""
    if not value or not isinstance(value, str):
        return ''
    s = value.strip()
    if not s or len(s) > 64:
        return ''
    if not _IANA_TZ_RE.match(s):
        return ''
    return s


def truncate_user_agent(ua: str | None, max_length: int = 512) -> str:
    if not ua or not isinstance(ua, str):
        return ''
    return ua.strip()[:max_length]


def sanitize_failure_reason(message: str | None, max_length: int = 255) -> str:
    if not message:
        return ''
    s = str(message).replace('\n', ' ').replace('\r', '').strip()
    return s[:max_length]


def _sanitize_geo_field(value: str | None, max_length: int) -> str:
    if not value or not isinstance(value, str):
        return ''
    return value.strip()[:max_length]


def resolve_client_geo(request: HttpRequest) -> tuple[str, str]:
    """
    Best-effort (country, city) from GeoIP using the client IP.

    Uses ``settings.SHELLUI_GEOIP_DATABASE_PATH`` to a MaxMind GeoLite2/GeoIP2 City ``.mmdb``
    file and the optional ``geoip2`` package. Returns ('', '') when the path is unset, the file
    is missing, the library is not installed, or lookup fails (e.g. private IP).
    """
    db_path = getattr(settings, 'SHELLUI_GEOIP_DATABASE_PATH', '') or ''
    if not db_path or not Path(db_path).is_file():
        return '', ''

    ip = get_client_ip(request)
    if not ip:
        return '', ''

    try:
        import geoip2.database
        from geoip2.errors import AddressNotFoundError, GeoIP2Error
    except ImportError:
        return '', ''

    try:
        with geoip2.database.Reader(db_path) as reader:
            rec = reader.city(ip)
    except (OSError, ValueError, AddressNotFoundError, GeoIP2Error):
        return '', ''

    country = rec.country.iso_code or rec.country.name or ''
    city = rec.city.name or ''
    return _sanitize_geo_field(country, 64), _sanitize_geo_field(city, 128)


def record_login_event(
    *,
    request: HttpRequest,
    outcome: str,
    provider: str,
    user: AbstractBaseUser | None = None,
    company: Company | None = None,
    failure_reason: str | None = None,
    client_timezone: str = '',
    client_device_id: str | None = None,
    client_country: str | None = None,
    client_city: str | None = None,
) -> EventLog:
    """Record a sign-in attempt (``outcome`` is ``LoginOutcome.SUCCESS`` or ``FAILURE``) in the event log."""
    ip = get_client_ip(request)
    ua = truncate_user_agent(request.META.get('HTTP_USER_AGENT'))
    tz = normalize_client_timezone(client_timezone) or normalize_client_timezone(
        request.META.get('HTTP_X_CLIENT_TIMEZONE') or request.META.get('HTTP_X_SHELLUI_CLIENT_TIMEZONE')
    )
    device_hash = hash_client_device_id(client_device_id)
    is_staff = bool(getattr(user, 'is_staff', False)) if user is not None else False

    geo_country, geo_city = resolve_client_geo(request)
    country = _sanitize_geo_field(
        geo_country if client_country is None else client_country,
        64,
    )
    city = _sanitize_geo_field(geo_city if client_city is None else client_city, 128)

    return record_event(
        get_event_type(LOGIN_EVENT_TYPES[outcome]),
        company,
        {
            'provider': str(provider).lower()[:32] if provider else 'unknown',
            'failure_reason': sanitize_failure_reason(failure_reason),
            'is_staff_at_event': is_staff,
            'ip_hash': hash_ip(ip),
            'user_agent': ua,
            'client_timezone': tz,
            'client_device_id_hash': device_hash,
            'client_country': country,
            'client_city': city,
        },
        user=user,
    )


def oauth_provider_redirect_uri(request: HttpRequest) -> str:
    """
    Stable provider redirect_uri (no query). Must match OAuth app registration
    and the value used in the token exchange.
    """
    return f'{request.scheme}://{request.get_host()}/api/v1/oauth/callback'


def oauth_callback_query_string(
    *,
    provider: str,
    redirect_to: str,
    company_id: str | None = None,
    company_oauth_client_id: str | None = None,
    client_timezone: str | None = None,
    client_device_id: str | None = None,
) -> str:
    """Legacy query string builder (prefer signed state + oauth_provider_redirect_uri)."""
    from urllib.parse import urlencode

    params: dict[str, str] = {
        'provider': provider,
        'redirect_to': redirect_to,
    }
    if company_id and str(company_id).strip():
        params['company_id'] = str(company_id).strip()
    if company_oauth_client_id and str(company_oauth_client_id).strip():
        params['company_oauth_client_id'] = str(company_oauth_client_id).strip()
    tz = normalize_client_timezone(client_timezone)
    if tz:
        params['client_timezone'] = tz
    if client_device_id and str(client_device_id).strip():
        d = str(client_device_id).strip()
        if len(d) <= 128:
            params['client_device_id'] = d
    return urlencode(params)


def oauth_callback_url(request: HttpRequest, provider: str, redirect_to: str) -> str:
    """
    Legacy redirect_uri with query params. Prefer oauth_provider_redirect_uri + signed state.
    Kept for any callers that still encode context in the redirect_uri.
    """
    tz = request.GET.get('client_timezone', '') if hasattr(request, 'GET') else ''
    dev = request.GET.get('client_device_id', '') if hasattr(request, 'GET') else ''
    company_id = request.GET.get('company_id', '') if hasattr(request, 'GET') else ''
    company_oauth_client_id = request.GET.get('company_oauth_client_id', '') if hasattr(request, 'GET') else ''
    qs = oauth_callback_query_string(
        provider=provider,
        redirect_to=redirect_to,
        company_id=company_id or None,
        company_oauth_client_id=company_oauth_client_id or None,
        client_timezone=tz or None,
        client_device_id=dev or None,
    )
    return f'{oauth_provider_redirect_uri(request)}?{qs}'
