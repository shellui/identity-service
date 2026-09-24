from django_scim.utils import get_group_adapter, get_user_adapter
from django_scim.views import ResourceTypesView as DjangoResourceTypesView


class ShellUIResourceTypesView(DjangoResourceTypesView):
    """Expose User and Group resource types for this company-scoped SCIM app."""

    def type_dict_by_type_id(self, request):
        type_dicts = [
            get_user_adapter().resource_type_dict(request),
            get_group_adapter().resource_type_dict(request),
        ]
        return {d['id']: d for d in type_dicts}
