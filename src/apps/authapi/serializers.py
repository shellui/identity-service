from rest_framework import serializers


class ProviderAuthorizeSerializer(serializers.Serializer):
    redirect_uri = serializers.URLField()


class ProviderCallbackSerializer(serializers.Serializer):
    code = serializers.CharField()
    redirect_uri = serializers.URLField()
