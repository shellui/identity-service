from django.contrib import admin

from .models import UserPreference


@admin.register(UserPreference)
class UserPreferenceAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'user',
        'language',
        'color_scheme',
        'theme_name',
        'region',
        'updated_at',
    )
    list_select_related = ('user',)
    list_filter = ('language', 'color_scheme')
    search_fields = ('user__username', 'user__email', 'theme_name', 'region')
    ordering = ('user_id',)
    readonly_fields = ('created_at', 'updated_at')
