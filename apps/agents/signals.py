"""Invalidate MCP session grants when agent permission fields change (company-scoped)."""

from __future__ import annotations

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from apps.agents.agent_permissions import invalidate_agent_session_grants
from apps.agents.models import Agent


def _permission_fields() -> frozenset[str]:
    return frozenset(
        {
            'access_mode',
            'read_level',
            'allow_destructive_without_asking',
            'services_allowed',
        }
    )


@receiver(pre_save, sender=Agent)
def agent_cache_previous_permission_state(sender, instance: Agent, **kwargs):
    if not instance.pk:
        instance._prev_perm_snapshot = None  # type: ignore[attr-defined]
        return
    try:
        prev = Agent.objects.only(*_permission_fields()).get(pk=instance.pk)
    except Agent.DoesNotExist:
        instance._prev_perm_snapshot = None  # type: ignore[attr-defined]
        return
    instance._prev_perm_snapshot = {  # type: ignore[attr-defined]
        'access_mode': prev.access_mode,
        'read_level': prev.read_level,
        'allow_destructive_without_asking': prev.allow_destructive_without_asking,
        'services_allowed': list(prev.services_allowed or []),
    }


@receiver(post_save, sender=Agent)
def agent_permissions_changed(sender, instance: Agent, created: bool, **kwargs):
    if created:
        return
    prev = getattr(instance, '_prev_perm_snapshot', None)
    if not isinstance(prev, dict):
        return
    cur_services = list(instance.services_allowed or [])
    changed = (
        prev.get('access_mode') != instance.access_mode
        or prev.get('read_level') != instance.read_level
        or bool(prev.get('allow_destructive_without_asking'))
        != bool(instance.allow_destructive_without_asking)
        or prev.get('services_allowed') != cur_services
    )
    if changed:
        invalidate_agent_session_grants(instance)
