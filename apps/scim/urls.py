from django.urls import re_path
from django_scim import views as django_scim_views

from . import views as shellui_scim_views

app_name = 'scim'

urlpatterns = [
    re_path(
        r'^$',
        django_scim_views.SCIMView.as_view(implemented=False),
        name='root',
    ),
    re_path(
        r'^\.search$',
        django_scim_views.SCIMView.as_view(implemented=False),
        name='search',
    ),
    re_path(
        r'^Users/\.search$',
        django_scim_views.UserSearchView.as_view(),
        name='users-search',
    ),
    re_path(
        r'^Users(?:/(?P<uuid>[^/]+))?$',
        django_scim_views.UsersView.as_view(),
        name='users',
    ),
    re_path(
        r'^Groups/\.search$',
        django_scim_views.GroupSearchView.as_view(),
        name='groups-search',
    ),
    re_path(
        r'^Groups(?:/(?P<uuid>[^/]+))?$',
        django_scim_views.GroupsView.as_view(),
        name='groups',
    ),
    re_path(
        r'^Me$',
        django_scim_views.SCIMView.as_view(implemented=False),
        name='me',
    ),
    re_path(
        r'^ServiceProviderConfig$',
        shellui_scim_views.ShellUIServiceProviderConfigView.as_view(),
        name='service-provider-config',
    ),
    re_path(
        r'^ResourceTypes(?:/(?P<uuid>[^/]+))?$',
        shellui_scim_views.ShellUIResourceTypesView.as_view(),
        name='resource-types',
    ),
    re_path(
        r'^Schemas(?:/(?P<uuid>[^/]+))?$',
        django_scim_views.SchemasView.as_view(),
        name='schemas',
    ),
    re_path(
        r'^Bulk$',
        django_scim_views.SCIMView.as_view(implemented=False),
        name='bulk',
    ),
]
