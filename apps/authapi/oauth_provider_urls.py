"""Company-configured base URLs for OAuth providers that run on a company-chosen host."""

from __future__ import annotations

from urllib.parse import urlparse

from allauth.socialaccount.models import SocialApp

GITLAB_COM_URL = 'https://gitlab.com'


def _settings(social_app: SocialApp) -> dict:
    raw = getattr(social_app, 'settings', None)
    return raw if isinstance(raw, dict) else {}


def gitlab_base_url(social_app: SocialApp) -> str:
    return str(_settings(social_app).get('gitlab_url') or GITLAB_COM_URL).strip().rstrip('/')


def is_self_hosted_gitlab(social_app: SocialApp | None) -> bool:
    """True for any GitLab host other than https://gitlab.com (no port, no path)."""
    if social_app is None:
        return False
    parsed = urlparse(gitlab_base_url(social_app))
    host = (parsed.hostname or '').lower()
    path = (parsed.path or '').rstrip('/')
    return not (parsed.scheme.lower() == 'https' and host == 'gitlab.com' and not parsed.port and not path)
