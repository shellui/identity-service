from django.urls import path

from .views import SocialAuthorizeView, SocialLoginView

urlpatterns = [
    path('providers/<str:provider>/authorize/', SocialAuthorizeView.as_view(), name='social-authorize'),
    path('providers/<str:provider>/login/', SocialLoginView.as_view(), name='social-login'),
]
