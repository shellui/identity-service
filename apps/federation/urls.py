from django.urls import path

from apps.federation.backchannel import BackchannelLogoutView
from apps.federation.outbound import PlanOutboundView, ProvisionOutboundView
from apps.federation.provider import AuthorizeView, TokenView, UserInfoView
from apps.federation.provisioning import ProvisionCompanyView, ProvisionPlanView
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
    path('companies', ProvisionCompanyView.as_view(), name='federation-provision-company'),
    path('plans', ProvisionPlanView.as_view(), name='federation-provision-plan'),
]

outbound_urlpatterns = [
    path('provision', ProvisionOutboundView.as_view(), name='federation-provision-outbound'),
    path('plan', PlanOutboundView.as_view(), name='federation-plan-outbound'),
]
