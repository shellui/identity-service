from __future__ import annotations

import re

from django.conf import settings
from django.http import HttpResponse
from django.utils import timezone

from apps.companies.models import Company
from apps.scim.models import CompanyScimToken
from apps.scim.provisioner import get_scim_provisioner_user
from apps.scim.tokens import hash_scim_token

_SCIM_PATH_RE = re.compile(r'^/api/v1/companies/(?P<slug>[^/]+)/scim/v2/')


class ScimBearerAuthMiddleware:
    """
    Authenticate SCIM calls with ``Authorization: Bearer <company-scim-token>``.

    The URL slug must match the token's company. Sets ``request.scim_company`` and a
    non-interactive ``request.user`` for django-scim2's auth middleware.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        match = _SCIM_PATH_RE.match(request.path)
        if not match:
            return self.get_response(request)

        if not getattr(settings, 'SCIM_ENABLED', False):
            return HttpResponse(status=404)

        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            return self._unauthorized()

        raw_token = auth_header[7:].strip()
        if not raw_token:
            return self._unauthorized()

        token_hash = hash_scim_token(raw_token)
        try:
            row = CompanyScimToken.objects.select_related('company').get(
                token_hash=token_hash,
                revoked_at__isnull=True,
            )
        except CompanyScimToken.DoesNotExist:
            return self._unauthorized()

        slug = match.group('slug')
        if row.company.slug != slug:
            return self._unauthorized()

        CompanyScimToken.objects.filter(pk=row.pk).update(last_used_at=timezone.now())
        request.scim_company = row.company
        request.user = get_scim_provisioner_user()
        return self.get_response(request)

    @staticmethod
    def _unauthorized():
        response = HttpResponse(status=401)
        response['WWW-Authenticate'] = 'Bearer realm="Shellui SCIM"'
        return response
