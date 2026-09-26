from django.urls import path

from apps.actions.admin_api_views import (
    ShellUIAdminActionDeliveryDetailView,
    ShellUIAdminActionDeliveryListView,
    ShellUIAdminActionDeliveryRequeueView,
    ShellUIAdminActionEventEmailTemplateView,
    ShellUIAdminActionEventsView,
    ShellUIAdminActionRuleDetailView,
    ShellUIAdminActionRuleEmailTemplateView,
    ShellUIAdminActionRuleListCreateView,
)

urlpatterns = [
    path('events', ShellUIAdminActionEventsView.as_view(), name='shellui-admin-actions-events'),
    path(
        'events/<path:event_type>/email-template',
        ShellUIAdminActionEventEmailTemplateView.as_view(),
        name='shellui-admin-actions-event-email-template',
    ),
    path('rules', ShellUIAdminActionRuleListCreateView.as_view(), name='shellui-admin-actions-rules'),
    path(
        'rules/<int:pk>',
        ShellUIAdminActionRuleDetailView.as_view(),
        name='shellui-admin-actions-rule-detail',
    ),
    path(
        'rules/<int:pk>/email-template',
        ShellUIAdminActionRuleEmailTemplateView.as_view(),
        name='shellui-admin-actions-rule-email-template',
    ),
    path('deliveries', ShellUIAdminActionDeliveryListView.as_view(), name='shellui-admin-actions-deliveries'),
    path(
        'deliveries/<uuid:delivery_id>',
        ShellUIAdminActionDeliveryDetailView.as_view(),
        name='shellui-admin-actions-delivery-detail',
    ),
    path(
        'deliveries/<uuid:delivery_id>/requeue',
        ShellUIAdminActionDeliveryRequeueView.as_view(),
        name='shellui-admin-actions-delivery-requeue',
    ),
]
