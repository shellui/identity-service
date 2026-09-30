"""SAML endpoint error responses (machine codes only)."""

from __future__ import annotations

from django.http import HttpResponse, JsonResponse


def saml_http_error(*, error_code: str, status: int = 400) -> HttpResponse:
    return HttpResponse(error_code, status=status, content_type='text/plain')


def saml_json_error(*, error_code: str, status: int = 400, **extra) -> JsonResponse:
    body = {'error_code': error_code}
    body.update(extra)
    return JsonResponse(body, status=status)
