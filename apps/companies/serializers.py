from rest_framework import serializers

from .access import normalize_allowed_domains
from .models import Company


class CompanySerializer(serializers.ModelSerializer):
    owners = serializers.PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta:
        model = Company
        fields = [
            'id',
            'name',
            'slug',
            'owners',
            'access_mode',
            'allowed_email_domains',
        ]


class CompanyUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(required=False, allow_blank=False, max_length=255)
    owner_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        required=False,
        allow_empty=True,
    )
    access_mode = serializers.ChoiceField(
        choices=[c[0] for c in Company.ACCESS_MODE_CHOICES],
        required=False,
    )
    allowed_email_domains = serializers.ListField(
        child=serializers.CharField(allow_blank=False, max_length=253),
        required=False,
        allow_empty=True,
    )

    def validate_allowed_email_domains(self, value):
        return normalize_allowed_domains(value)
