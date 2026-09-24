from django_scim.models import SCIMServiceProviderConfig


class ShellUIServiceProviderConfig(SCIMServiceProviderConfig):
    """Service provider metadata for Shellui (Users only for now)."""

    def to_dict(self):
        d = super().to_dict()
        d['documentationUri'] = d.get('documentationUri') or 'https://github.com/shellui/identity-service/blob/main/docs/scim.md'
        return d
