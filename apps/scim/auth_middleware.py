from django.http.response import HttpResponse
from django_scim.middleware import SCIMAuthCheckMiddleware
from django_scim.settings import scim_settings
from django_scim.utils import get_is_authenticated_predicate

_SCIM_SEGMENT = '/scim/v2/'


class ShelluiSCIMAuthCheckMiddleware(SCIMAuthCheckMiddleware):
    """django-scim2 auth check for company-prefixed SCIM URLs (no ``scim:root`` reverse)."""

    def should_log_request(self, request):
        return _SCIM_SEGMENT in request.path

    def process_request(self, request):
        if self.should_log_request(request):
            self.log_request(request)
        if self.should_log_request(request) and not get_is_authenticated_predicate()(request.user):
            response = HttpResponse(status=401)
            response['WWW-Authenticate'] = scim_settings.WWW_AUTHENTICATE_HEADER
            return response
