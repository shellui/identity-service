from urllib.parse import urljoin

from django.urls import reverse

from django_scim.models import SCIMServiceProviderConfig
from django_scim.utils import get_base_scim_location_getter

from apps.scim.context import get_scim_company


class ShellUIServiceProviderConfig(SCIMServiceProviderConfig):
    """Service provider metadata for Shellui (Users and Groups)."""

    @property
    def location(self):
        company = get_scim_company(self.request)
        kwargs = {'company_slug': company.slug} if company else {}
        path = reverse('scim:service-provider-config', kwargs=kwargs)
        return urljoin(get_base_scim_location_getter()(self.request), path)

    def to_dict(self):
        d = super().to_dict()
        d['documentationUri'] = (
            d.get('documentationUri')
            or 'https://github.com/shellui/identity-service/blob/main/docs/scim.md'
        )
        return d
