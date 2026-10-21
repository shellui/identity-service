"""Shared API view base so OpenAPI can see these endpoints."""

from rest_framework import serializers
from rest_framework.views import APIView


class SchemaSerializer(serializers.Serializer):
    """Marker serializer. Request and response shapes are documented on the view."""


class FederationView(APIView):
    serializer_class = SchemaSerializer
