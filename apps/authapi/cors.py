"""CORS helpers: allow browser origins that are on the OAuth redirect allowlist."""

from __future__ import annotations

from django.db.utils import OperationalError, ProgrammingError

from apps.companies.models import CompanyOAuthRedirect
from apps.companies.redirect_allowlist import origin_of_url
from corsheaders.middleware import CorsMiddleware


def oauth_redirect_origin_allowed(origin: str) -> bool:
    """True when ``origin`` matches an active CompanyOAuthRedirect.base_url."""
    candidate = origin_of_url(origin) or (origin or '').strip().rstrip('/')
    if not candidate:
        return False
    try:
        return CompanyOAuthRedirect.objects.filter(
            base_url=candidate,
            is_active=True,
        ).exists()
    except (OperationalError, ProgrammingError):
        return False


class ShelluiCorsMiddleware(CorsMiddleware):
    """Extend django-cors-headers to honor OAuth redirect allowlist origins."""

    def origin_found_in_white_lists(self, origin, url) -> bool:
        if super().origin_found_in_white_lists(origin, url):
            return True
        return oauth_redirect_origin_allowed(origin)
