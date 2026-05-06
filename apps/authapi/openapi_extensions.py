"""drf-spectacular: map ShellUI JWT authentication to OpenAPI ``bearerAuth``."""

from drf_spectacular.extensions import OpenApiAuthenticationExtension


class ShellUIJWTAuthenticationScheme(OpenApiAuthenticationExtension):
    """Registers Bearer JWT in Swagger UI (Authorize) for protected operations."""

    target_class = 'apps.authapi.authentication.ShellUIJWTAuthentication'
    name = 'bearerAuth'
    priority = 1

    def get_security_definition(self, auto_schema):
        return {
            'type': 'http',
            'scheme': 'bearer',
            'bearerFormat': 'JWT',
            'description': 'ShellUI access token or personal access token (PAT): Authorization: Bearer <token>',
        }
