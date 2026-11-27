from django.apps import AppConfig


class ConfigConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'config'

    def ready(self) -> None:
        from config.telemetry import register_metrics

        register_metrics()
