"""OAuth redirect target helpers for frontend callback flows."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from django.conf import settings
from django.db.utils import OperationalError, ProgrammingError
from django.http import HttpRequest

from .models import Company, CompanyOAuthRedirect

# Schemes that must never be a desktop redirect, even when the shape looks like an app id.
_DENIED_REDIRECT_SCHEMES = frozenset(
    {
        'http',
        'https',
        'javascript',
        'data',
        'file',
        'vbscript',
        'about',
        'blob',
        'ftp',
        'ftps',
        'ws',
        'wss',
        'mailto',
        'tel',
        'sms',
        'ssh',
        'sftp',
        'ldap',
        'ldaps',
        'chrome',
        'chrome-extension',
        'moz-extension',
        'ms-appx',
        'ms-appx-web',
        'intent',
        'market',
        'content',
        'android-app',
        'view-source',
        'filesystem',
        'jar',
        'nfs',
        'tftp',
        'gopher',
        'news',
        'nntp',
        'irc',
        'ircs',
        'magnet',
        'cid',
        'mid',
        'mms',
        'mmsto',
        'ms-help',
        'res',
        'mk',
        'mhtml',
        'webcal',
        'feed',
        'git',
        'svn',
        'dict',
        'wais',
        'shttp',
        'urn',
        'uuid',
        'geo',
        'telnet',
        'rtsp',
        'rtspu',
        'sip',
        'sips',
        'xmpp',
        'callto',
        'facetime',
        'facetime-audio',
        'maps',
        'ms-settings',
        'microsoft-edge',
        'chrome-error',
        'chrome-devtools',
        'resource',
        'android',
        'dns',
        'ipp',
        'ipps',
        'dav',
        'imap',
        'pop',
        'smtp',
    }
)

# RFC 3986: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ). Stored lowercase.
_RFC3986_SCHEME_RE = re.compile(r'^[a-z][a-z0-9+.-]*$')
_DESKTOP_URI_CONTROL_RE = re.compile(r'[\x00-\x20\x7f\\]')
_ERROR_CODE_RE = re.compile(r'^[a-z][a-z0-9_]{0,63}$')
UNREGISTERED_SCHEME_MESSAGE = 'Sign-in scheme is not registered for this company.'
# `shellui start --app` signs in with `<scheme>-dev`. Accepted only when DEBUG is on.
DESKTOP_DEV_SCHEME_SUFFIX = '-dev'

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


def is_allowed_app_scheme(scheme: str) -> bool:
    """True for a lowercase RFC 3986 scheme that is not a browser or network scheme."""
    value = (scheme or '').strip().lower()
    if (
        not value
        or len(value) > 64
        or value in _DENIED_REDIRECT_SCHEMES
        or value.startswith('web+')
        or _RFC3986_SCHEME_RE.fullmatch(value) is None
    ):
        return False
    return True


def normalize_registered_scheme(raw: str) -> tuple[str | None, str | None]:
    """One scheme stored on the company. An empty value is skipped."""
    s = (raw or '').strip()
    if not s:
        return '', None
    if s != s.lower():
        return None, 'Scheme must be lowercase.'
    if len(s) > 64 or _RFC3986_SCHEME_RE.fullmatch(s) is None:
        return None, (
            'Scheme must be an RFC 3986 scheme: a letter, then letters, digits, plus, hyphen, or dot.'
        )
    if s in _DENIED_REDIRECT_SCHEMES or s.startswith('web+'):
        return None, 'This scheme is not allowed.'
    return s, None


def normalize_registered_schemes(raw) -> tuple[list[str] | None, str | None]:
    """Allowlist stored on the company. An empty list turns desktop sign-in off."""
    if raw is None:
        return [], None
    if isinstance(raw, str):
        text = raw.strip()
        parts = [] if not text else [part.strip() for part in text.split(',')]
    elif isinstance(raw, list):
        parts = raw
    else:
        return None, 'desktop_redirect_schemes must be a list of schemes.'
    schemes: list[str] = []
    seen: set[str] = set()
    for part in parts:
        if not isinstance(part, str):
            return None, 'Each scheme must be a string.'
        scheme, err = normalize_registered_scheme(part)
        if err:
            return None, err
        if not scheme or scheme in seen:
            continue
        seen.add(scheme)
        schemes.append(scheme)
    return schemes, None


def company_desktop_schemes(company: Company) -> set[str]:
    """Lowercase schemes this company accepts. Empty means desktop sign-in is off."""
    raw = getattr(company, 'desktop_redirect_schemes', None) or []
    schemes, err = normalize_registered_schemes(raw if isinstance(raw, list) else [])
    if err or not schemes:
        return set()
    return set(schemes)


def is_custom_scheme_redirect(url: str) -> bool:
    """True when ``url`` uses an allowed desktop app scheme."""
    return is_allowed_app_scheme(urlsplit((url or '').strip()).scheme)


def normalize_desktop_redirect_uri(raw: str) -> tuple[str | None, str | None]:
    """
    Canonical exact custom-scheme URI.
    Returns (uri, None) or (None, error_message).
    """
    s = (raw or '').strip()
    if not s:
        return None, 'Empty base_url.'
    lowered = s.lower()
    if (
        _DESKTOP_URI_CONTROL_RE.search(s)
        or '%00' in lowered
        or '%0a' in lowered
        or '%0d' in lowered
    ):
        return None, 'Invalid desktop redirect.'
    if '#' in s:
        return None, 'Desktop redirect must not include a fragment.'
    if '://' not in s:
        return None, 'Desktop redirect must be an exact custom-scheme URI.'
    try:
        parsed = urlsplit(s)
    except ValueError:
        return None, 'Invalid desktop redirect.'
    scheme = (parsed.scheme or '').lower()
    if scheme in _DENIED_REDIRECT_SCHEMES:
        return None, 'Desktop redirect scheme is not allowed.'
    if not is_allowed_app_scheme(scheme):
        return None, 'Desktop redirect must be an exact custom-scheme URI.'
    if '@' in parsed.netloc or '%' in parsed.netloc or parsed.username or parsed.password:
        return None, 'Desktop redirect must not include userinfo.'
    try:
        port = parsed.port
    except ValueError:
        return None, 'Invalid desktop redirect.'
    if port is not None and not 1 <= port <= 65535:
        return None, 'Invalid desktop redirect.'
    if not parsed.netloc and not parsed.path:
        return None, 'Invalid desktop redirect.'
    if parsed.fragment:
        return None, 'Desktop redirect must not include a fragment.'
    canonical = canonical_url_no_fragment(s)
    if not canonical or len(canonical) > 500 or not is_custom_scheme_redirect(canonical):
        return None, 'Invalid desktop redirect.'
    return canonical, None


def client_redirect_error_code(message: str | None) -> str:
    """Stable code for a redirect validation message."""
    text = message or ''
    if 'not registered' in text:
        return 'unregistered_scheme'
    if 'not allowed' in text or 'Invalid redirect' in text:
        return 'redirect_not_allowed'
    return 'invalid_redirect'


def desktop_error_deep_link(redirect_to: str, error_code: str) -> str | None:
    """``scheme://host/path?error=<code>`` for a validated custom-scheme redirect.

    The query is only ``error``. No token, auth code, or verifier is copied.
    """
    canonical, err = normalize_desktop_redirect_uri(redirect_to)
    if err or not canonical or not is_custom_scheme_redirect(canonical):
        return None
    parsed = urlsplit(canonical)
    code = (error_code or '').strip().lower()
    if _ERROR_CODE_RE.fullmatch(code) is None:
        code = 'signin_failed'
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '', urlencode([('error', code)]), ''))


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
    if p.scheme in ('http', 'https'):
        if not p.netloc:
            return None, 'Invalid redirect_to.'
        return canonical_url_no_fragment(s), None
    if is_allowed_app_scheme(p.scheme):
        uri, err = normalize_desktop_redirect_uri(s)
        if err or not uri:
            if err and 'fragment' in err:
                return None, 'redirect_to must not include a fragment.'
            return None, 'Invalid redirect_to.'
        return uri, None
    return None, 'redirect_to must use http or https.'


def _hostname_is_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False
    h = hostname.lower().strip('[]')
    return h in ('localhost', '127.0.0.1', '::1')


def is_loopback_redirect_url(absolute_url: str) -> bool:
    """True when the URL host is localhost / 127.0.0.1 / ::1."""
    return _hostname_is_loopback(urlsplit(canonical_url_no_fragment(absolute_url)).hostname)


def loopback_oauth_redirects_allowed() -> bool:
    """True when loopback OAuth bounce targets are permitted (DEBUG or explicit env)."""
    return bool(getattr(settings, 'OAUTH_ALLOW_LOOPBACK_REDIRECTS', settings.DEBUG))


def redirect_url_allowed_for_company(company: Company, absolute_url: str, request: HttpRequest) -> bool:
    """
    Allow loopback when ``OAUTH_ALLOW_LOOPBACK_REDIRECTS`` (default: DEBUG). Otherwise require
    an active company allowlist origin match. Empty allowlist denies non-loopback.
    A custom scheme must be listed on the company. An empty list denies every custom scheme.
    """
    del request
    candidate = canonical_url_no_fragment(absolute_url)
    if not candidate:
        return False
    if is_custom_scheme_redirect(candidate):
        return _desktop_redirect_scheme_match(company, candidate)
    if is_loopback_redirect_url(candidate):
        return loopback_oauth_redirects_allowed()
    candidate_origin = origin_of_url(candidate)
    if not candidate_origin:
        return False
    try:
        rows = CompanyOAuthRedirect.objects.filter(
            company_id=company.id,
            is_active=True,
        )
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


def desktop_dev_schemes_allowed() -> bool:
    """Implicit `<scheme>-dev` redirects are only for a local identity-service (`DEBUG=true`)."""
    return bool(settings.DEBUG)


def desktop_scheme_registered(scheme: str, registered: set[str]) -> bool:
    """True for a registered scheme, or its `-dev` variant when `DEBUG` is on.

    A scheme listed as-is is accepted in every environment, including one that ends in `-dev`.
    """
    if scheme in registered:
        return True
    if not desktop_dev_schemes_allowed():
        return False
    base = scheme.removesuffix(DESKTOP_DEV_SCHEME_SUFFIX)
    return base != scheme and base in registered


def _desktop_redirect_scheme_match(company: Company, candidate: str) -> bool:
    """True when the URI scheme is on the company allowlist.

    With `DEBUG=true`, the scheme without a trailing `-dev` is enough.
    """
    exact, err = normalize_desktop_redirect_uri(candidate)
    if err or not exact:
        return False
    return desktop_scheme_registered(urlsplit(exact).scheme, company_desktop_schemes(company))


def loopback_client_bounce_url_for_oauth_error(
    request: HttpRequest,
    redirect_to_raw: str | None,
    error_message: str,
    *,
    error_code: str = 'oauth_authorize_failed',
) -> str | None:
    """
    When browser OAuth fails before leaving the auth host, send loopback dev clients back to their
    app with query params instead of a JSON error page (so the Shellui app stays visible).
    """
    raw = (redirect_to_raw or '').strip()
    if not raw:
        return None
    url, err = normalize_client_redirect_url(request, raw)
    if err or not url:
        return None
    host = urlsplit(url).hostname
    if not _hostname_is_loopback(host) or not loopback_oauth_redirects_allowed():
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
        if is_custom_scheme_redirect(url):
            return None, UNREGISTERED_SCHEME_MESSAGE
        return None, 'redirect_to is not allowed for this company.'
    return url, None


def validate_redirect_uri_for_company(
    *,
    company: Company,
    request: HttpRequest,
    redirect_uri_raw: str | None,
) -> tuple[str | None, str | None]:
    """
    Resolve legacy client `redirect_uri` and validate URL shape + allowlist.
    Same rules as validate_redirect_to_for_company (loopback + CompanyOAuthRedirect).
    Returns (absolute_url_without_fragment, error_message).
    """
    raw = (redirect_uri_raw or '').strip()
    if not raw:
        return None, 'Missing redirect_uri.'
    url, err = normalize_client_redirect_url(request, raw)
    if err:
        if err and 'redirect_to' in err:
            err = err.replace('redirect_to', 'redirect_uri')
        return None, err
    if not redirect_url_allowed_for_company(company, url, request):
        if is_custom_scheme_redirect(url):
            return None, UNREGISTERED_SCHEME_MESSAGE
        return None, 'redirect_uri is not allowed for this company.'
    return url, None
