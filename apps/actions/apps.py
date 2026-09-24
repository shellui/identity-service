from django.apps import AppConfig


class ActionsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.actions'
    verbose_name = 'Action triggers'

    def ready(self) -> None:
        from apps.actions import identity_events  # noqa: F401
