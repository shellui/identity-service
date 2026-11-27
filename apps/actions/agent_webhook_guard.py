"""Limits on the webhook fields an agent may send, and how a webhook destination is shown to a person."""

from __future__ import annotations

MAX_AGENT_URL_LENGTH = 2048
MAX_AGENT_DESCRIPTION_LENGTH = 500


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
    """The real ``host[:port]`` of a URL and the URL with any userinfo replaced by ``***@``."""
    url = str(url or '').strip()
    scheme, authority, rest = _authority_and_rest(url)
    if not scheme:
        return '', url
    hostport = authority.rsplit('@', 1)[-1]
    prefix = '***@' if '@' in authority else ''
    return hostport, f'{scheme}://{prefix}{hostport}{rest}'


def webhook_approval_summary(url: str) -> str:
    """Destination host first, then the full URL, so padding cannot push the host out of view."""
    hostport, display = webhook_destination(url)
    if not hostport:
        return 'Create a webhook rule'
    return f'Create a webhook that posts to {hostport}: {display}'[:500]


def agent_webhook_value_problem(data: dict) -> str | None:
    """Why an agent's webhook fields are refused, or ``None``. Applies to create and update."""
    url = str(data.get('url') or '').strip()
    if url and url_has_userinfo(url):
        return 'Agents cannot use a webhook URL that contains user information before the host.'
    if len(url) > MAX_AGENT_URL_LENGTH:
        return f'Agents cannot use a webhook URL longer than {MAX_AGENT_URL_LENGTH} characters.'
    if len(str(data.get('description') or '')) > MAX_AGENT_DESCRIPTION_LENGTH:
        return f'Agents cannot use a webhook description longer than {MAX_AGENT_DESCRIPTION_LENGTH} characters.'
    return None
