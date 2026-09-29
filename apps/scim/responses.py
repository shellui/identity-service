from __future__ import annotations

import json

from django.http import HttpResponse
from django_scim.constants import SCIM_CONTENT_TYPE
from django_scim.exceptions import AuthorizationError


def scim_unauthorized_response(*, www_authenticate: str | None = None) -> HttpResponse:
    """401 with the SCIM Error message schema (RFC 7644)."""
    err = AuthorizationError('Authentication required.')
    response = HttpResponse(
        json.dumps(err.to_dict()),
        content_type=SCIM_CONTENT_TYPE,
        status=401,
    )
    response['WWW-Authenticate'] = www_authenticate or 'Bearer realm="Shellui SCIM"'
    return response
