from rest_framework import serializers

from apps.actions.models import ActionRule
from apps.actions.registry import is_registered_event


class ActionRuleWriteSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=200, required=False)
    description = serializers.CharField(required=False, allow_blank=True)
    event_type = serializers.CharField(max_length=128, required=False)
    enabled = serializers.BooleanField(required=False)
    action_kind = serializers.ChoiceField(choices=ActionRule.ACTION_KIND_CHOICES, required=False)

    recipients = serializers.JSONField(required=False)
    include_payload_email = serializers.BooleanField(required=False)
    email_templates = serializers.JSONField(required=False)

    url = serializers.URLField(required=False, allow_blank=True)
    secret = serializers.CharField(required=False, allow_blank=True, trim_whitespace=False)
    authorization_header = serializers.CharField(required=False, allow_blank=True, trim_whitespace=False)
    allow_private_urls = serializers.BooleanField(required=False)

    def validate_event_type(self, value):
        if value and not is_registered_event(value):
            raise serializers.ValidationError('Unknown event type.')
        return value


class ActionRuleCreateSerializer(ActionRuleWriteSerializer):
    name = serializers.CharField(max_length=200)
    event_type = serializers.CharField(max_length=128)
    action_kind = serializers.ChoiceField(choices=ActionRule.ACTION_KIND_CHOICES)

    def validate_event_type(self, value):
        if not is_registered_event(value):
            raise serializers.ValidationError('Unknown event type.')
        return value


class ActionRuleUpdateSerializer(ActionRuleWriteSerializer):
    pass
