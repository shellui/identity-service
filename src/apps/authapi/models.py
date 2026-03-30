from django.conf import settings
from django.db import models


class UserPreference(models.Model):
    LANGUAGE_EN = 'en'
    LANGUAGE_FR = 'fr'
    LANGUAGE_CHOICES = [
        (LANGUAGE_EN, 'English'),
        (LANGUAGE_FR, 'French'),
    ]

    COLOR_SCHEME_LIGHT = 'light'
    COLOR_SCHEME_DARK = 'dark'
    COLOR_SCHEME_SYSTEM = 'system'
    COLOR_SCHEME_CHOICES = [
        (COLOR_SCHEME_LIGHT, 'Light'),
        (COLOR_SCHEME_DARK, 'Dark'),
        (COLOR_SCHEME_SYSTEM, 'System'),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name='preference',
        on_delete=models.CASCADE,
    )
    theme_name = models.CharField(max_length=100, default='default')
    language = models.CharField(max_length=8, choices=LANGUAGE_CHOICES, default=LANGUAGE_EN)
    region = models.CharField(max_length=64, default='UTC')
    color_scheme = models.CharField(
        max_length=16,
        choices=COLOR_SCHEME_CHOICES,
        default=COLOR_SCHEME_SYSTEM,
    )
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['user_id']

    def __str__(self) -> str:
        return f'UserPreference(user_id={self.user_id})'
