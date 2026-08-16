from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import LoginEvent, PersonalAccessToken, UserActivity, UserPreference

User = get_user_model()


# Extend stock User admin: show company membership (access is per-company).
if admin.site.is_registered(User):
    admin.site.unregister(User)


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    list_display = (
        'username',
        'email',
        'first_name',
        'last_name',
        'is_active',
        'is_staff',
        'companies_display',
    )
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'groups')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('username',)

    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email')}),
        (
            'Permissions',
            {
                'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
                'description': (
                    'Django account flags. Company sign-in access is controlled per company '
                    '(Companies → Members inline is_enabled), not by this Active checkbox.'
                ),
            },
        ),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        (
            'Companies',
            {
                'fields': ('companies_display', 'owned_companies_display'),
                'description': (
                    'Enable/disable access per company on the Company change page '
                    '(Members inline) or under Company memberships.'
                ),
            },
        ),
    )
    readonly_fields = ('companies_display', 'owned_companies_display', 'last_login', 'date_joined')
    add_fieldsets = (
        (
            None,
            {
                'classes': ('wide',),
                'fields': ('username', 'email', 'password1', 'password2', 'is_active', 'is_staff'),
            },
        ),
    )

    @admin.display(description='Companies')
    def companies_display(self, obj) -> str:
        if not obj.pk:
            return '—'
        rows = list(
            obj.company_memberships.select_related('company')
            .order_by('company__name')
            .values_list('company__name', 'is_enabled')[:20]
        )
        if not rows:
            return '—'
        parts = [f'{name} ({"on" if enabled else "off"})' for name, enabled in rows]
        text = ', '.join(parts)
        return text if len(text) <= 80 else text[:77] + '…'

    @admin.display(description='Owned companies')
    def owned_companies_display(self, obj) -> str:
        if not obj.pk:
            return '—'
        names = list(obj.owned_companies.order_by('name').values_list('name', flat=True)[:20])
        if not names:
            return '—'
        text = ', '.join(names)
        return text if len(text) <= 64 else text[:61] + '…'


@admin.register(PersonalAccessToken)
class PersonalAccessTokenAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'company',
        'user',
        'read_only',
        'access_global_metrics',
        'name',
        'created_at',
        'last_used_at',
        'revoked_at',
    )
    list_editable = ('access_global_metrics',)
    list_filter = ('read_only', 'access_global_metrics', 'revoked_at')
    search_fields = ('user__email', 'user__username', 'id', 'name')
    ordering = ('-created_at',)
    list_select_related = ('company', 'user')
    readonly_fields = (
        'id',
        'company',
        'user',
        'jti',
        'created_at',
        'revoked_at',
        'last_used_at',
    )
    fieldsets = (
        (None, {'fields': ('id', 'company', 'user', 'name')}),
        (
            'Token',
            {
                'fields': ('jti', 'read_only', 'access_global_metrics'),
                'description': (
                    'JWT claims pat_ro / pat_agm must match these flags; changing a flag invalidates '
                    'existing JWTs until you re-issue the PAT. Only staff may enable global metrics.'
                ),
            },
        ),
        ('Status', {'fields': ('created_at', 'revoked_at', 'last_used_at')}),
    )

    def has_add_permission(self, request):
        return False


@admin.register(LoginEvent)
class LoginEventAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'created_at',
        'outcome',
        'provider',
        'user',
        'is_staff_at_event',
        'client_country',
        'client_city',
    )
    list_filter = ('outcome', 'provider', 'is_staff_at_event')
    search_fields = ('user__email', 'user__username', 'ip_hash', 'failure_reason')
    ordering = ('-created_at', '-id')
    readonly_fields = (
        'created_at',
        'user',
        'outcome',
        'provider',
        'failure_reason',
        'is_staff_at_event',
        'ip_hash',
        'user_agent',
        'client_timezone',
        'client_device_id_hash',
        'client_country',
        'client_city',
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    list_display = ('user', 'last_seen_at')
    ordering = ('-last_seen_at',)
    search_fields = ('user__email', 'user__username')
    readonly_fields = ('user', 'last_seen_at')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


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
