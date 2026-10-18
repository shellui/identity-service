from django.apps import AppConfig


class FederationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.federation'

    def ready(self) -> None:
        from . import checks  # noqa: F401
