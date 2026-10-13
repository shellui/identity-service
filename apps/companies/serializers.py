from rest_framework import serializers

from .access import normalize_allowed_domains
from .models import Company
from .redirect_allowlist import normalize_registered_scheme


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
            'desktop_redirect_scheme',
            'data_retention_days',
        ]
        read_only_fields = ['data_retention_days']

    def validate_desktop_redirect_scheme(self, value):
        scheme, err = normalize_registered_scheme(value or '')
        if err:
            raise serializers.ValidationError(err)
        return scheme or ''


class CompanyUpdateSerializer(serializers.Serializer):
    """
    Company owner settings API. ``verified_email_domains`` and ``data_retention_days`` are
    intentionally omitted; only platform operators set them in Django admin.
    """

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
    desktop_redirect_scheme = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=64,
    )

    def validate_allowed_email_domains(self, value):
        return normalize_allowed_domains(value)

    def validate_desktop_redirect_scheme(self, value):
        scheme, err = normalize_registered_scheme(value or '')
        if err:
            raise serializers.ValidationError(err)
        return scheme or ''
