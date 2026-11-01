from django.contrib import admin

from apps.agents.models import Agent, McpApprovalRequest, McpCallLog, McpOAuthClient


@admin.register(McpOAuthClient)
class McpOAuthClientAdmin(admin.ModelAdmin):
    list_display = ('client_id', 'client_name', 'created_at')
    search_fields = ('client_id', 'client_name')


@admin.register(Agent)
class AgentAdmin(admin.ModelAdmin):
    list_display = ('name', 'company', 'access_mode', 'read_level', 'paused_at', 'revoked_at', 'expires_at')
    list_filter = ('access_mode', 'read_level')
    search_fields = ('name', 'id')
    raw_id_fields = ('company', 'oauth_client', 'created_by')


@admin.register(McpApprovalRequest)
class McpApprovalRequestAdmin(admin.ModelAdmin):
    list_display = ('id', 'agent', 'service', 'action', 'status', 'expires_at', 'created_at')
    list_filter = ('status', 'service')
    raw_id_fields = ('agent', 'company', 'decided_by')


@admin.register(McpCallLog)
class McpCallLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'agent', 'service', 'tool', 'status_code', 'created_at')
    list_filter = ('service',)
    raw_id_fields = ('agent', 'company')
