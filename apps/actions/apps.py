from django.apps import AppConfig


class ActionsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.actions'
    verbose_name = 'Action triggers'

    def ready(self) -> None:
        # Side-effect import: registers identity.* domain events in the global catalog.
        from apps.actions import identity_events  # noqa: F401
