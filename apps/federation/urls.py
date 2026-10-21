from django.urls import path

from apps.federation.backchannel import BackchannelLogoutView
from apps.federation.provider import AuthorizeView, TokenView, UserInfoView
from apps.federation.provisioning import (
    ProvisioningCompaniesView,
    ProvisioningCompanyView,
    ProvisioningLimitsView,
)
from apps.federation.relying import SilentSignInView, UpstreamCallbackView

urlpatterns = [
    path('authorize', AuthorizeView.as_view(), name='federation-authorize'),
    path('token', TokenView.as_view(), name='federation-token'),
    path('userinfo', UserInfoView.as_view(), name='federation-userinfo'),
    path('backchannel-logout', BackchannelLogoutView.as_view(), name='federation-backchannel-logout'),
    path('silent-signin', SilentSignInView.as_view(), name='federation-silent-signin'),
    path('upstream-callback', UpstreamCallbackView.as_view(), name='federation-upstream-callback'),
]

provisioning_urlpatterns = [
    path('companies', ProvisioningCompaniesView.as_view(), name='federation-provisioning-companies'),
    path('companies/<int:company_id>', ProvisioningCompanyView.as_view(), name='federation-provisioning-company'),
    path(
        'companies/<int:company_id>/limits',
        ProvisioningLimitsView.as_view(),
        name='federation-provisioning-limits',
    ),
]
