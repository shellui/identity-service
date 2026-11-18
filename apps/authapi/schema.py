"""OpenAPI shapes for identity admin APIs (documentation-only serializers)."""

from __future__ import annotations

from rest_framework import serializers


class ErrorSerializer(serializers.Serializer):
    error_code = serializers.CharField(
        help_text=(
            'Stable machine code (for example `validation_failed`, `not_found`, `forbidden`). '
            'Never a translated sentence.'
        ),
    )
    error = serializers.CharField(
        required=False,
        help_text='Optional human-readable detail (legacy responses may use this instead of `detail`).',
    )
    detail = serializers.CharField(required=False, help_text='Optional human-readable detail.')
    field_errors = serializers.DictField(
        child=serializers.ListField(child=serializers.CharField()),
        required=False,
        help_text='Optional map of field names to lists of stable error tokens (for example `required`, `invalid`).',
    )
    request_id = serializers.CharField(
        required=False,
        help_text='Echo of the `X-Request-ID` header when present.',
    )
