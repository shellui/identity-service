"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from django.views.decorators.clickjacking import xframe_options_exempt
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from apps.agents import mcp_views as agents_mcp_views
from apps.agents.oauth_views import (
    OAuthAuthorizationServerMetadataView,
    OAuthProtectedResourceMetadataView,
    mcp_authorize,
    mcp_register,
    mcp_token,
)
from apps.agents.unified_oauth_token import oauth_token_dispatch
from apps.authapi.jwks_views import ShellUIJwksView
from apps.federation.provider import OpenIdConfigurationView
from apps.federation.provisioning import CompanyPlanView
from apps.federation.urls import provisioning_urlpatterns, urlpatterns as oauth_urlpatterns

from . import views

from apps.agents.approval_fallback_views import mcp_approval_fallback  # noqa: E402
from apps.agents.mcp_saas_return import mcp_saas_return  # noqa: E402
from apps.agents.mcp_signin import mcp_signin, mcp_signin_complete  # noqa: E402

urlpatterns = [
    path('health/live', views.health_live, name='health-live'),
    path('', views.root, name='root'),
    path('admin/', admin.site.urls),
    path('.well-known/jwks.json', ShellUIJwksView.as_view(), name='jwks'),
    path(
        '.well-known/oauth-authorization-server',
        OAuthAuthorizationServerMetadataView.as_view(),
        name='mcp-oauth-authorization-server',
    ),
    path(
        '.well-known/oauth-protected-resource',
        OAuthProtectedResourceMetadataView.as_view(),
        name='mcp-oauth-protected-resource',
    ),
    path('mcp', agents_mcp_views.mcp_endpoint, name='mcp'),
    path(
        '.well-known/openid-configuration',
        OpenIdConfigurationView.as_view(),
        name='federation-openid-configuration',
    ),
    path('oauth/token', oauth_token_dispatch, name='oauth-token-dispatch'),
    path('oauth/', include(oauth_urlpatterns)),
    path('oauth/mcp/register', mcp_register, name='mcp-oauth-register'),
    path('oauth/mcp/authorize', mcp_authorize, name='mcp-oauth-authorize'),
    path('oauth/mcp/signin', mcp_signin, name='mcp-oauth-signin'),
    path('oauth/mcp/signin/complete', mcp_signin_complete, name='mcp-oauth-signin-complete'),
    path('oauth/mcp/saas-return', mcp_saas_return, name='mcp-oauth-saas-return'),
    path('oauth/mcp/token', mcp_token, name='mcp-oauth-token'),
    path('oauth/mcp/approval/<uuid:approval_id>', mcp_approval_fallback, name='mcp-oauth-approval-fallback'),
    path('api/v1/', include('apps.authapi.urls')),
    path('api/v1/mcp/', include('apps.agents.urls')),
    path(
        'api/v1/companies/<int:company_id>/plan',
        CompanyPlanView.as_view(),
        name='federation-company-plan',
    ),
    path('api/v1/companies/', include('apps.companies.urls')),
    path('api/v1/provisioning/', include(provisioning_urlpatterns)),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path(
        'api/docs/',
        xframe_options_exempt(SpectacularSwaggerView.as_view(url_name='schema')),
        name='swagger-ui',
    ),
    path(
        'api/docs/redoc/',
        xframe_options_exempt(SpectacularRedocView.as_view(url_name='schema')),
        name='redoc',
    ),
    path(
        'api/v1/companies/<int:company_id>/scim/v2/',
        include(('apps.scim.urls', 'scim'), namespace='scim'),
    ),
]

handler400 = 'config.errors.bad_request'
handler403 = 'config.errors.permission_denied'
handler404 = 'config.errors.page_not_found'
handler500 = 'config.errors.server_error'
