"""Company membership hooks that invalidate session Allow grants."""

from __future__ import annotations

from django.db.models.signals import post_delete, post_save, pre_delete
from django.dispatch import receiver

from apps.agents.agent_permissions import invalidate_agents_for_user_company
from apps.companies.models import CompanyMembership


@receiver(post_save, sender=CompanyMembership)
def membership_access_changed(sender, instance: CompanyMembership, **kwargs):
    if not instance.is_enabled:
        invalidate_agents_for_user_company(user_id=instance.user_id, company_id=instance.company_id)


@receiver(post_delete, sender=CompanyMembership)
def membership_removed(sender, instance: CompanyMembership, **kwargs):
    invalidate_agents_for_user_company(user_id=instance.user_id, company_id=instance.company_id)


@receiver(pre_delete, sender=CompanyMembership)
def membership_pre_delete(sender, instance: CompanyMembership, **kwargs):
    invalidate_agents_for_user_company(user_id=instance.user_id, company_id=instance.company_id)
