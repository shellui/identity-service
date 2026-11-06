from django.apps import AppConfig


class CompaniesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.companies'

    def ready(self) -> None:
        # Register signals once Django loads apps.
        from apps.companies import signals  # noqa: F401
