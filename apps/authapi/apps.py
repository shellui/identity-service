from django.apps import AppConfig


class AuthApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.authapi'

    def ready(self) -> None:
        from . import checks  # noqa: F401
        from . import openapi_extensions  # noqa: F401
        from . import signals  # noqa: F401
