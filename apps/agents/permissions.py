"""Company owner / staff checks for MCP admin APIs."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response

def require_company_admin(request):
    from apps.authapi.views import _require_staff_or_company_owner

    return _require_staff_or_company_owner(request)
