"""SCIM_SERVICE_PROVIDER dict when ``SCIM_ENABLED`` is true."""

SCIM_SERVICE_PROVIDER = {
    'USER_ADAPTER': 'apps.scim.adapters.ShellUIScimUser',
    'USER_FILTER_PARSER': 'apps.scim.filters.ShellUIUserFilterQuery',
    'GROUP_MODEL': 'apps.companies.models.CompanyGroup',
    'GROUP_ADAPTER': 'apps.scim.adapters.ShellUIScimGroup',
    'GROUP_FILTER_PARSER': 'apps.scim.filters.ShellUIGroupFilterQuery',
    'SERVICE_PROVIDER_CONFIG_MODEL': 'apps.scim.service_provider.ShellUIServiceProviderConfig',
    'BASE_LOCATION_GETTER': 'apps.scim.hooks.shellui_base_scim_location',
    'GET_EXTRA_MODEL_FILTER_KWARGS_GETTER': 'apps.scim.hooks.shellui_model_filter_kwargs_getter',
    'GET_QUERYSET_POST_PROCESSOR_GETTER': 'apps.scim.hooks.shellui_model_queryset_post_processor_getter',
    'GET_OBJECT_POST_PROCESSOR_GETTER': 'apps.scim.hooks.shellui_model_object_post_processor_getter',
    'GET_IS_AUTHENTICATED_PREDICATE': 'apps.scim.hooks.shellui_is_scim_authenticated',
    'AUTH_CHECK_MIDDLEWARE': 'apps.scim.auth_middleware.ShelluiSCIMAuthCheckMiddleware',
    'NETLOC': 'localhost',
    'SCHEME': 'https',
    'AUTHENTICATION_SCHEMES': [
        {
            'type': 'oauthbearertoken',
            'name': 'OAuth Bearer Token',
            'description': 'Company-scoped SCIM bearer token (see docs/scim.md).',
        },
    ],
    'WWW_AUTHENTICATE_HEADER': 'Bearer realm="Shellui SCIM"',
}
