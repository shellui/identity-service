"""OAuth redirect target helpers for frontend callback flows."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from django.db.utils import OperationalError, ProgrammingError
from django.http import HttpRequest

from .models import Company, CompanyOAuthRedirect

DEFAULT_LOGIN_CALLBACK_PATH = '/login/callback'

SHELLUI_OAUTH_ERROR_PARAM = 'shellui_oauth_error'
SHELLUI_OAUTH_ERROR_CODE_PARAM = 'shellui_oauth_error_code'


def append_oauth_error_params(redirect_to: str, message: str, error_code: str) -> str:
    """Attach shellui_oauth_error(+_code) query params to an absolute redirect URL."""
    p = urlsplit((redirect_to or '').strip())
    pairs = [
        (k, v)
        for k, v in parse_qsl(p.query, keep_blank_values=True)
        if not k.startswith('shellui_oauth_')
    ]
    safe_msg = (message or '').replace('\r', ' ').replace('\n', ' ').strip()[:500]
    pairs.append((SHELLUI_OAUTH_ERROR_PARAM, safe_msg if safe_msg else 'OAuth request failed.'))
    code = (error_code or '').strip()[:64] or 'oauth_authorize_failed'
    pairs.append((SHELLUI_OAUTH_ERROR_CODE_PARAM, code))
    new_query = urlencode(pairs)
    return urlunsplit((p.scheme, p.netloc, p.path or '', new_query, ''))


def _lower_netloc(netloc: str) -> str:
    if not netloc or '@' in netloc:
        return netloc
    host, sep, port = netloc.partition(':')
    return f'{host.lower()}{sep}{port}'


def canonical_url_no_fragment(url: str) -> str:
    p = urlsplit((url or '').strip())
    scheme = (p.scheme or '').lower()
    netloc = _lower_netloc(p.netloc)
    path = p.path or ''
    query = p.query or ''
    return urlunsplit((scheme, netloc, path, query, ''))


def origin_of_url(url: str) -> str:
    """Return scheme://netloc for an absolute URL (no path/query/fragment)."""
    p = urlsplit(canonical_url_no_fragment(url))
    if not p.scheme or not p.netloc:
        return ''
    return f'{p.scheme}://{p.netloc}'


def normalize_allowlist_origin(raw: str) -> tuple[str | None, str | None]:
    """
    Normalize an allowlist entry to a canonical origin.
    Returns (origin, None) or (None, error_message).
    """
    s = (raw or '').strip()
    if not s:
        return None, 'Empty base_url.'
    if s.startswith('//') or s.startswith('/'):
        return None, 'base_url must be an absolute http(s) origin.'
    p = urlsplit(s)
    if p.scheme not in ('http', 'https'):
        return None, 'base_url must use http or https.'
    if not p.netloc:
        return None, 'Invalid base_url.'
    origin = origin_of_url(s)
    if not origin:
        return None, 'Invalid base_url.'
    return origin, None


def server_default_redirect_url(request: HttpRequest) -> str:
    return canonical_url_no_fragment(
        f'{request.scheme}://{request.get_host()}{DEFAULT_LOGIN_CALLBACK_PATH}',
    )


def normalize_client_redirect_url(request: HttpRequest, raw: str) -> tuple[str | None, str | None]:
    """
    Turn client `redirect_to` into an absolute URL without fragment.
    Returns (url, None) or (None, error_message).
    """
    s = (raw or '').strip()
    if not s:
        return None, 'Empty redirect_to.'
    if s.startswith('//'):
        return None, 'Invalid redirect_to.'
    if s.startswith('/'):
        if '\n' in s or '\r' in s or '\0' in s:
            return None, 'Invalid redirect_to.'
        joined = f'{request.scheme}://{request.get_host()}{s}'
        return canonical_url_no_fragment(joined), None
    p = urlsplit(s)
    if p.scheme not in ('http', 'https'):
        return None, 'redirect_to must use http or https.'
    if not p.netloc:
        return None, 'Invalid redirect_to.'
    return canonical_url_no_fragment(s), None


def _hostname_is_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False
    h = hostname.lower().strip('[]')
    return h in ('localhost', '127.0.0.1', '::1')


def is_loopback_redirect_url(absolute_url: str) -> bool:
    """True when the URL host is localhost / 127.0.0.1 / ::1."""
    return _hostname_is_loopback(urlsplit(canonical_url_no_fragment(absolute_url)).hostname)


def redirect_url_allowed_for_company(company: Company, absolute_url: str, request: HttpRequest) -> bool:
    """
    Allow loopback always. Otherwise require an active company allowlist origin match.
    Empty allowlist denies non-loopback (operators must add shell origins).
    """
    _ = request
    candidate = canonical_url_no_fragment(absolute_url)
    if not candidate:
        return False
    if is_loopback_redirect_url(candidate):
        return True
    candidate_origin = origin_of_url(candidate)
    if not candidate_origin:
        return False
    try:
        rows = CompanyOAuthRedirect.objects.filter(company_id=company.id, is_active=True)
        for row in rows:
            allowed = origin_of_url(row.base_url) or canonical_url_no_fragment(row.base_url)
            if not allowed:
                continue
            # Origin equality, or candidate starts with allowed prefix (trailing slash tolerant).
            if candidate_origin == allowed or candidate.startswith(allowed.rstrip('/') + '/'):
                return True
            if candidate == allowed:
                return True
    except (OperationalError, ProgrammingError):
        return False
    return False


def loopback_client_bounce_url_for_oauth_error(
    request: HttpRequest,
    redirect_to_raw: str | None,
    error_message: str,
    *,
    error_code: str = 'oauth_authorize_failed',
) -> str | None:
    """
    When browser OAuth fails before leaving the auth host, send loopback dev clients back to their
    app with query params instead of a JSON error page (so the Shell UI stays visible).
    """
    raw = (redirect_to_raw or '').strip()
    if not raw:
        return None
    url, err = normalize_client_redirect_url(request, raw)
    if err or not url:
        return None
    host = urlsplit(url).hostname
    if not _hostname_is_loopback(host):
        return None
    return append_oauth_error_params(url, error_message, error_code)


def validate_redirect_to_for_company(
    *,
    company: Company,
    request: HttpRequest,
    redirect_to_raw: str | None,
) -> tuple[str | None, str | None]:
    """
    Resolve client `redirect_to` and validate URL shape + allowlist.
    Returns (absolute_url_without_fragment, error_message).
    """
    raw = (redirect_to_raw or '').strip()
    if not raw:
        return None, 'Missing redirect_to.'
    url, err = normalize_client_redirect_url(request, raw)
    if err:
        return None, err
    if not redirect_url_allowed_for_company(company, url, request):
        return None, 'redirect_to is not allowed for this company.'
    return url, None
