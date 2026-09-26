from django_scim.views import ResourceTypesView as DjangoResourceTypesView
from django_scim.views import ServiceProviderConfigView as DjangoServiceProviderConfigView
from django_scim.utils import get_group_adapter, get_user_adapter


class ShellUIServiceProviderConfigView(DjangoServiceProviderConfigView):
    """ServiceProviderConfig for the company id in the SCIM URL include."""

    def get(self, request, company_id=None, *args, **kwargs):
        return super().get(request)


class ShellUIResourceTypesView(DjangoResourceTypesView):
    """Expose User and Group resource types for this company-scoped SCIM app."""

    def type_dict_by_type_id(self, request):
        type_dicts = [
            get_user_adapter().resource_type_dict(request),
            get_group_adapter().resource_type_dict(request),
        ]
        return {d['id']: d for d in type_dicts}
