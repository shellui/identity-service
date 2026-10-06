"""Keep one-time secrets out of Sentry events and breadcrumbs.

Query strings, request bodies and the Referer can carry magic-link tokens, OAuth
``code`` and ``state``, ``confirm_token``, ``setup_token`` and ``shellui_auth_code``.
Frame locals can hold the raw magic-link token, PKCE verifiers and issued JWTs.
"""

from __future__ import annotations

from typing import Any

from config.request_context import url_without_query

FILTERED = '[Filtered]'

# Added to sentry_sdk's DEFAULT_DENYLIST (which already covers token, secret, password,
# authorization, cookies, ...). Matched case-insensitively against dict keys, including
# frame local variable names.
EXTRA_DENYLIST = [
    'raw_token',
    'raw_code',
    'magic_link_url',
    'confirm_token',
    'setup_token',
    'bridge_token',
    'shellui_auth_code',
    'code',
    'state',
    'state_raw',
    'verifier',
    'code_verifier',
    'access',
    'refresh',
    'access_token',
    'refresh_token',
    'id_token',
    'token_payload',
    'payload',
    'samlresponse',
    'referer',
    'http_referer',
    'query_string',
]

_DROPPED_HEADERS = {'referer', 'cookie', 'authorization', 'x-setup-token'}


def _scrub_url(value: Any) -> Any:
    return url_without_query(value) if isinstance(value, str) else value


def _scrub_request(request: dict) -> None:
    if 'url' in request:
        request['url'] = _scrub_url(request['url'])
    if request.get('query_string'):
        request['query_string'] = FILTERED
    if request.get('data'):
        request['data'] = FILTERED
    headers = request.get('headers')
    if isinstance(headers, dict):
        for name in list(headers):
            if name.lower() in _DROPPED_HEADERS:
                headers[name] = FILTERED


def _scrub_breadcrumb(crumb: dict) -> dict:
    data = crumb.get('data')
    if isinstance(data, dict):
        for key in ('url', 'to', 'from'):
            if key in data:
                data[key] = _scrub_url(data[key])
        for key in ('http.query', 'http.fragment'):
            data.pop(key, None)
    return crumb


def before_send(event: dict, hint: dict | None = None) -> dict:
    request = event.get('request')
    if isinstance(request, dict):
        _scrub_request(request)
    breadcrumbs = event.get('breadcrumbs')
    values = breadcrumbs.get('values') if isinstance(breadcrumbs, dict) else breadcrumbs
    if isinstance(values, list):
        for crumb in values:
            if isinstance(crumb, dict):
                _scrub_breadcrumb(crumb)
    return event


def before_breadcrumb(crumb: dict, hint: dict | None = None) -> dict:
    return _scrub_breadcrumb(crumb)


def event_scrubber():
    from sentry_sdk.scrubber import DEFAULT_DENYLIST, EventScrubber

    return EventScrubber(denylist=[*DEFAULT_DENYLIST, *EXTRA_DENYLIST], recursive=True)
