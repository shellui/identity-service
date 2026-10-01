from rest_framework import serializers


class ShellUIOpenAPISerializer(serializers.Serializer):
    """Placeholder for APIView classes documented via @extend_schema_view."""


class ProviderAuthorizeSerializer(serializers.Serializer):
    redirect_uri = serializers.URLField()


class ProviderCallbackSerializer(serializers.Serializer):
    code = serializers.CharField()
    redirect_uri = serializers.URLField()
    client_timezone = serializers.CharField(required=False, allow_blank=True, max_length=64)
    client_device_id = serializers.CharField(required=False, allow_blank=True, max_length=128)


class ShellUIOAuthExchangeSerializer(serializers.Serializer):
    provider = serializers.CharField(max_length=64)
    code = serializers.CharField()
    redirect_uri = serializers.URLField()
    company_oauth_client_id = serializers.IntegerField(required=False, min_value=1)
    client_timezone = serializers.CharField(required=False, allow_blank=True, max_length=64)
    client_device_id = serializers.CharField(required=False, allow_blank=True, max_length=128)


class ShellUIRefreshTokenSerializer(serializers.Serializer):
    grant_type = serializers.CharField(required=False, allow_blank=False, default='refresh_token')
    refresh_token = serializers.CharField(required=True, allow_blank=False)


class ShellUIOAuthSessionExchangeSerializer(serializers.Serializer):
    auth_code = serializers.CharField(max_length=128)
    redirect_to = serializers.URLField(max_length=2048)


class ShellUIMagicLinkRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    redirect_to = serializers.URLField(max_length=2048)
    company_id = serializers.IntegerField(required=False, min_value=1)
    client_timezone = serializers.CharField(required=False, allow_blank=True, max_length=64)
    client_device_id = serializers.CharField(required=False, allow_blank=True, max_length=128)
    language = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=35,
        help_text='UI language of the requester (e.g. "fr" or "fr-FR"). Selects the email locale.',
    )


class ShellUIInvitationCreateSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    language = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=35,
        help_text='Invitation email language (en or fr; tags like "fr-FR" accepted). Defaults to en.',
    )
    app_url = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=2048,
        help_text=(
            'App URL linked from the email (usually the shell origin). Must match the company '
            'OAuth redirect allowlist. Omit to send the email without a link.'
        ),
    )

    def validate_language(self, value: str) -> str:
        from .magic_link import normalize_magic_link_language

        if not (value or '').strip():
            return 'en'
        normalized = normalize_magic_link_language(value)
        if not normalized:
            raise serializers.ValidationError('Unsupported language. Use en or fr.')
        return normalized


class ShellUIMagicLinkConsumeSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=128)
    company_id = serializers.IntegerField(min_value=1)


class ShellUIAdminAuthMethodsUpdateSerializer(serializers.Serializer):
    enable_magic_link = serializers.BooleanField(required=False)


class ShellUILogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=False, allow_blank=True, max_length=8192)


class ShellUIUserDeleteSerializer(serializers.Serializer):
    confirm = serializers.BooleanField(
        required=True,
        help_text='Must be true to permanently delete the authenticated user account.',
    )


class ShellUIUserProfileUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(
        required=True,
        allow_blank=False,
        max_length=150,
        help_text='Display name. Stored as first_name (first word) and last_name (the rest).',
    )

    def validate_name(self, value: str) -> str:
        collapsed = ' '.join(value.split())
        if not collapsed:
            raise serializers.ValidationError('Name cannot be blank.')
        return collapsed


class UserPreferenceSerializer(serializers.Serializer):
    themeName = serializers.CharField(required=False, allow_blank=False, max_length=100)
    language = serializers.ChoiceField(required=False, choices=['en', 'fr'])
    region = serializers.CharField(required=False, allow_blank=False, max_length=64)
    colorScheme = serializers.ChoiceField(required=False, choices=['light', 'dark', 'system'])


class ShellUIPersonalAccessTokenCreateSerializer(serializers.Serializer):
    read_only = serializers.BooleanField(required=False, default=False)
    access_global_metrics = serializers.BooleanField(required=False, default=False)
    name = serializers.CharField(required=False, allow_blank=True, max_length=200)


class ShellUIAdminScimTokenCreateSerializer(serializers.Serializer):
    name = serializers.CharField(required=False, allow_blank=True, max_length=200)


class ShellUIAdminUserUpdateSerializer(serializers.Serializer):
    """Partial update for Django user fields plus optional Shellui user_metadata merge (`data`).

    ``is_active`` enables/disables ``CompanyMembership`` for the current company only.
    """

    first_name = serializers.CharField(required=False, allow_blank=True, max_length=150)
    last_name = serializers.CharField(required=False, allow_blank=True, max_length=150)
    is_staff = serializers.BooleanField(required=False)
    is_active = serializers.BooleanField(required=False)
    data = serializers.JSONField(required=False)
    group_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        required=False,
        allow_empty=True,
    )


class ShellUIAdminGroupCreateSerializer(serializers.Serializer):
    display_name = serializers.CharField(max_length=150)


class ShellUIAdminGroupUpdateSerializer(serializers.Serializer):
    display_name = serializers.CharField(max_length=150)


class ShellUIAdminLoginEventSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    company_id = serializers.IntegerField(allow_null=True)
    created_at = serializers.DateTimeField()
    user_id = serializers.IntegerField(allow_null=True)
    user_email = serializers.EmailField(allow_null=True, required=False)
    outcome = serializers.CharField()
    provider = serializers.CharField()
    failure_reason = serializers.CharField(allow_blank=True)
    is_staff_at_event = serializers.BooleanField()
    ip_hash = serializers.CharField(allow_blank=True)
    user_agent = serializers.CharField(allow_blank=True)
    client_timezone = serializers.CharField(allow_blank=True)
    client_device_id_hash = serializers.CharField(allow_blank=True)
    client_country = serializers.CharField(allow_blank=True)
    client_city = serializers.CharField(allow_blank=True)


class ShellUIAdminOAuthClientCreateSerializer(serializers.Serializer):
    social_app_id = serializers.IntegerField(min_value=1)
    is_active = serializers.BooleanField(required=False, default=True)


class ShellUIAdminOAuthClientUpdateSerializer(serializers.Serializer):
    social_app_id = serializers.IntegerField(required=False, min_value=1)
    is_active = serializers.BooleanField(required=False)

    def validate(self, attrs: dict) -> dict:
        if not attrs:
            raise serializers.ValidationError(
                'Provide at least one of: social_app_id, is_active.'
            )
        return attrs


class ShellUIAdminOAuthSocialAppCreateSerializer(serializers.Serializer):
    docs_slug = serializers.CharField(required=False, allow_blank=True, max_length=128)
    provider = serializers.CharField(required=False, allow_blank=True, max_length=64)
    client_id = serializers.CharField(max_length=191)
    client_secret = serializers.CharField(max_length=191)
    tenant = serializers.CharField(required=False, allow_blank=True, max_length=255)
    extra_settings = serializers.DictField(required=False, allow_empty=True)

    def validate(self, attrs: dict) -> dict:
        slug = str(attrs.get('docs_slug') or attrs.get('provider') or '').strip().lower()
        if not slug:
            raise serializers.ValidationError('Provide docs_slug (preferred) or provider.')
        attrs['docs_slug'] = slug
        return attrs


class ShellUIAdminOAuthSocialAppUpdateSerializer(serializers.Serializer):
    client_id = serializers.CharField(required=False, allow_blank=False, max_length=191)
    client_secret = serializers.CharField(required=False, allow_blank=False, max_length=191)
    tenant = serializers.CharField(required=False, allow_blank=True, max_length=255)
    extra_settings = serializers.DictField(required=False, allow_empty=True)

    def validate(self, attrs: dict) -> dict:
        if not attrs:
            raise serializers.ValidationError(
                'Provide at least one of: client_id, client_secret, tenant, extra_settings.'
            )
        return attrs


class ShellUIAdminOAuthRedirectCreateSerializer(serializers.Serializer):
    base_url = serializers.CharField(max_length=500)
    label = serializers.CharField(required=False, allow_blank=True, max_length=150)
    is_active = serializers.BooleanField(required=False, default=True)
    source = serializers.ChoiceField(
        choices=['manual', 'hosting'],
        required=False,
        default='manual',
    )


class ShellUIAdminOAuthRedirectUpdateSerializer(serializers.Serializer):
    base_url = serializers.CharField(required=False, allow_blank=False, max_length=500)
    label = serializers.CharField(required=False, allow_blank=True, max_length=150)
    is_active = serializers.BooleanField(required=False)

    def validate(self, attrs: dict) -> dict:
        if not attrs:
            raise serializers.ValidationError('Provide at least one of: base_url, label, is_active.')
        return attrs


class ShellUIHostingOAuthRedirectSyncSerializer(serializers.Serializer):
    base_url = serializers.CharField(max_length=500)
    label = serializers.CharField(required=False, allow_blank=True, max_length=150)


class ShellUIHostingOAuthRedirectDeleteSerializer(serializers.Serializer):
    base_url = serializers.CharField(max_length=500)
