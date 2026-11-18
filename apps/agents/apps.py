from django.apps import AppConfig


class AgentsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.agents'
    verbose_name = 'MCP agents'

    def ready(self):
        from apps.agents import signals  # noqa: F401
