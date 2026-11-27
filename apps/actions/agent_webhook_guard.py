"""Limits on the webhook fields an agent may send, and how a webhook destination is shown to a person."""

from __future__ import annotations

import re
import unicodedata

MAX_AGENT_URL_LENGTH = 2048
MAX_AGENT_DESCRIPTION_LENGTH = 500


_EVENT_TYPE = re.compile(r'[A-Za-z0-9_.:-]{1,128}')
_WEBHOOK_TOOLS = {'identity_create_action_rules': True, 'identity_update_action_rules': False}


def has_control_or_format_char(text: str) -> bool:
    """True for any Unicode control (Cc) or format (Cf) character: newlines, zero-width, right-to-left override."""
    return any(unicodedata.category(ch) in ('Cc', 'Cf') for ch in text)


def _without_control_chars(text: str) -> str:
    return ''.join(ch for ch in text if unicodedata.category(ch) not in ('Cc', 'Cf'))


def _ascii_host(hostport: str) -> str:
    """A host that is safe to show: non-ASCII names appear in their ``xn--`` form."""
    if hostport.isascii():
        return hostport
    try:
        return hostport.encode('idna').decode('ascii')
    except UnicodeError:
        return hostport.encode('ascii', 'backslashreplace').decode('ascii')


def _authority_and_rest(url: str) -> tuple[str, str, str]:
    """Split ``scheme://authority/rest`` without parsing, so a padded or odd URL cannot raise."""
    scheme, sep, remainder = url.partition('://')
    if not sep:
        return '', url, ''
    cut = len(remainder)
    for ch in '/?#':
        found = remainder.find(ch)
        if found != -1:
            cut = min(cut, found)
    return scheme, remainder[:cut], remainder[cut:]


def url_has_userinfo(url: str) -> bool:
    """True for ``user:pass@host`` style URLs. The text before ``@`` can hide the real host."""
    _scheme, authority, _rest = _authority_and_rest(str(url or '').strip())
    return '@' in authority


def webhook_destination(url: str) -> tuple[str, str]:
    """The real ``host[:port]`` of a URL and the URL as shown to a person.

    Userinfo is replaced by ``***@``, control and format characters are dropped, and a non-ASCII
    host appears in its ``xn--`` form, so what is shown is what the request connects to.
    """
    url = _without_control_chars(str(url or '')).strip()
    scheme, authority, rest = _authority_and_rest(url)
    if not scheme:
        return '', url
    hostport = _ascii_host(authority.rsplit('@', 1)[-1])
    prefix = '***@' if '@' in authority else ''
    return hostport, f'{scheme}://{prefix}{hostport}{rest}'


def webhook_approval_summary(url: str, event_type: str = '') -> str:
    """Event type, destination host, then the full URL, so padding cannot push the host out of view."""
    hostport, display = webhook_destination(url)
    if not hostport:
        return 'Create a webhook rule'
    event = str(event_type or '').strip()
    label = f' for {event}' if _EVENT_TYPE.fullmatch(event) else ''
    return f'Create a webhook{label} that posts to {hostport}: {display}'[:500]


def url_host_is_ascii(url: str) -> bool:
    _scheme, authority, _rest = _authority_and_rest(str(url or '').strip())
    return authority.rsplit('@', 1)[-1].isascii()


def agent_webhook_value_problem(data: dict) -> str | None:
    """Why an agent's webhook fields are refused, or ``None``. Applies to create and update."""
    url = str(data.get('url') or '').strip()
    description = str(data.get('description') or '')
    if has_control_or_format_char(str(data.get('url') or '')) or has_control_or_format_char(description):
        return 'Agents cannot use control or invisible characters in a webhook URL or description.'
    if url and url_has_userinfo(url):
        return 'Agents cannot use a webhook URL that contains user information before the host.'
    if url and not url_host_is_ascii(url):
        return 'Agents cannot use a webhook URL whose host has non-ASCII characters. Use the ASCII (xn--) form.'
    if len(url) > MAX_AGENT_URL_LENGTH:
        return f'Agents cannot use a webhook URL longer than {MAX_AGENT_URL_LENGTH} characters.'
    if len(description) > MAX_AGENT_DESCRIPTION_LENGTH:
        return f'Agents cannot use a webhook description longer than {MAX_AGENT_DESCRIPTION_LENGTH} characters.'
    return None


def agent_webhook_call_problem(arguments: dict, meta: dict) -> str | None:
    """Refusal text for an agent's webhook create or update, checked before any approval exists.

    Runs the value checks and the same field validation the view applies, so a bad call fails at
    once and no approval row is made for it. Returns ``None`` for any other tool.
    """
    from apps.actions.serializers import ActionRuleCreateSerializer, ActionRuleUpdateSerializer

    tool = str(meta.get('operationId') or '')
    if tool not in _WEBHOOK_TOOLS:
        return None
    body = arguments.get('body') if isinstance(arguments, dict) else None
    body = body if isinstance(body, dict) else {}
    problem = agent_webhook_value_problem(body)
    if problem:
        return f'agent_webhook_value_refused: {problem}'
    serializer_class = ActionRuleCreateSerializer if _WEBHOOK_TOOLS[tool] else ActionRuleUpdateSerializer
    serializer = serializer_class(data=body, partial=not _WEBHOOK_TOOLS[tool])
    if not serializer.is_valid():
        return f'invalid_webhook_arguments: {dict(serializer.errors)}'
    return None
