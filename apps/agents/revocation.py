"""Revocation list for downstream MCP services (30 s cache recommended)."""

from __future__ import annotations

from django.db.models import Max
from django.utils import timezone

from apps.agents.models import Agent, DeletedAgentRevocation

REVOCATION_CACHE_SECONDS = 30


def active_max_grant_version(*, company_id: int | None = None) -> int:
    """Largest Agent.grant_version for non-revoked agents; drives policy fingerprint for active tenants."""
    qs = Agent.objects.filter(revoked_at__isnull=True)
    if company_id is not None:
        qs = qs.filter(company_id=company_id)
    val = qs.aggregate(m=Max('grant_version')).get('m')
    return int(val or 0)


def revoked_agent_ids(*, company_id: int | None = None) -> list[str]:
    qs = Agent.objects.filter(revoked_at__isnull=False)
    deleted = DeletedAgentRevocation.objects.all()
    if company_id is not None:
        qs = qs.filter(company_id=company_id)
        deleted = deleted.filter(company_id=company_id)
    ids = {str(aid) for aid in qs.values_list('id', flat=True)}
    ids.update(str(aid) for aid in deleted.values_list('agent_id', flat=True))
    return sorted(ids)


def is_agent_blocked(agent: Agent) -> bool:
    """True when this one agent must be refused. Looks at the agent only, not the company.

    Same rules as ``blocked_agent_ids``: revoked, paused, expired, or its creator is gone.
    """
    if agent.revoked_at is not None or agent.paused_at is not None:
        return True
    if agent.expires_at is not None and agent.expires_at <= timezone.now():
        return True
    return creator_statuses([agent]).get(str(agent.pk)) == CREATOR_GONE


def agent_id_is_blocked(agent_id: str, company_id: int | None = None) -> bool:
    """``is_agent_blocked`` by id, one row. An agent that no longer exists is blocked."""
    import uuid

    try:
        pk = uuid.UUID(str(agent_id))
    except (ValueError, AttributeError, TypeError):
        return True
    qs = Agent.objects.filter(pk=pk)
    if company_id is not None:
        qs = qs.filter(company_id=company_id)
    agent = qs.first()
    if agent is None:
        return True
    return is_agent_blocked(agent)


def revoke_agents(agents) -> int:
    """Revoke these agents now: row, refresh sessions and approval session grants."""
    from apps.agents.agent_permissions import invalidate_agent_session_grants
    from apps.agents.tokens import revoke_all_agent_refresh_sessions

    now = timezone.now()
    count = 0
    for agent in agents:
        if agent.revoked_at is None:
            Agent.objects.filter(pk=agent.pk, revoked_at__isnull=True).update(
                revoked_at=now, paused_at=agent.paused_at or now
            )
            count += 1
        revoke_all_agent_refresh_sessions(agent)
        invalidate_agent_session_grants(agent)
    return count


def revoke_agents_created_by(user) -> int:
    """Revoke every non-global agent this user created, in every company.

    Called before a user row is deleted: ``Agent.created_by`` is ``SET_NULL``, so without this
    the agents would outlive the person with no creator and no status.
    """
    return revoke_agents(
        list(Agent.objects.filter(created_by=user, global_agent_id__isnull=True, revoked_at__isnull=True))
    )


def paused_agent_ids(*, company_id: int | None = None) -> list[str]:
    qs = Agent.objects.filter(paused_at__isnull=False, revoked_at__isnull=True)
    if company_id is not None:
        qs = qs.filter(company_id=company_id)
    return [str(aid) for aid in qs.values_list('id', flat=True)]


def expired_agent_ids(*, company_id: int | None = None) -> list[str]:
    now = timezone.now()
    qs = Agent.objects.filter(expires_at__isnull=False, expires_at__lte=now, revoked_at__isnull=True)
    if company_id is not None:
        qs = qs.filter(company_id=company_id)
    return [str(aid) for aid in qs.values_list('id', flat=True)]


CREATOR_OWNER = 'owner'
CREATOR_MEMBER = 'member'
CREATOR_GONE = 'gone'


def creator_statuses(agents) -> dict[str, str]:
    """The creator's current standing in the agent's company, by agent id.

    ``owner`` or ``member`` for a creator with enabled access to the company (an owner is also
    in ``Company.owners``), ``gone`` when the account is inactive, the membership was removed
    or disabled, or the user no longer exists. This is the same test that decides whether the
    person can get a token for the company, so an agent never outlives its creator's access.

    Global agents are left out: their regional row records ``created_by`` but they are not the
    creator's personal agent, and services must not read a role for them. So are agents with
    no creator (company service agents).
    """
    from django.contrib.auth import get_user_model

    from apps.companies.models import Company, CompanyMembership

    rows = [
        (str(a.pk), a.created_by_id, a.company_id)
        for a in agents
        if getattr(a, 'global_agent_id', None) is None and a.created_by_id is not None
    ]
    if not rows:
        return {}
    user_ids = {uid for _a, uid, _c in rows}
    company_ids = {cid for _a, _u, cid in rows}
    active = set(get_user_model().objects.filter(pk__in=user_ids, is_active=True).values_list('pk', flat=True))
    enabled = set(
        CompanyMembership.objects.filter(
            user_id__in=user_ids, company_id__in=company_ids, is_enabled=True
        ).values_list('user_id', 'company_id')
    )
    owners = set(
        Company.owners.through.objects.filter(user_id__in=user_ids, company_id__in=company_ids).values_list(
            'user_id', 'company_id'
        )
    )
    out: dict[str, str] = {}
    for agent_id, uid, cid in rows:
        if uid not in active or (uid, cid) not in enabled:
            out[agent_id] = CREATOR_GONE
        elif (uid, cid) in owners:
            out[agent_id] = CREATOR_OWNER
        else:
            out[agent_id] = CREATOR_MEMBER
    return out


def gone_creator_agent_ids(*, company_id: int | None = None) -> list[str]:
    """Live agents whose creator no longer has access to the company."""
    qs = Agent.objects.filter(revoked_at__isnull=True, global_agent_id__isnull=True, created_by__isnull=False)
    if company_id is not None:
        qs = qs.filter(company_id=company_id)
    return [aid for aid, status in creator_statuses(list(qs)).items() if status == CREATOR_GONE]


def blocked_agent_ids(*, company_id: int | None = None) -> list[str]:
    ids = set(revoked_agent_ids(company_id=company_id))
    ids.update(paused_agent_ids(company_id=company_id))
    ids.update(expired_agent_ids(company_id=company_id))
    ids.update(gone_creator_agent_ids(company_id=company_id))
    return sorted(ids)


def agent_snapshot(agent: Agent, *, creator_status: str | None = None) -> dict:
    """One regional agent row. ``agent_id`` is the regional primary key, never a global agent id.

    ``creator_status`` (``owner``, ``member`` or ``gone``) is the creator's live standing in the
    company. Services give a personal agent the creator's role from this field and refuse an
    agent whose creator is ``gone``. It is absent for global agents and agents with no creator.
    """
    snap: dict = {
        'agent_id': str(agent.id),
        'company_id': int(agent.company_id),
        'is_active': bool(agent.is_active),
        'paused': agent.paused_at is not None,
        'grant_version': int(getattr(agent, 'grant_version', 0) or 0),
    }
    gc = getattr(agent, 'global_company_id', None)
    cb = getattr(agent, 'company_binding_version', None)
    if gc is not None:
        snap['global_company_id'] = str(gc)
    if cb is not None:
        snap['company_binding_version'] = int(cb)
    if creator_status is not None:
        snap['creator_status'] = creator_status
    return snap


def regional_agent_snapshots(*, company_id: int | None = None) -> list[dict]:
    """Every regional agent for this poll, including active rows consumers authorize against."""
    qs = Agent.objects.all().order_by('id')
    if company_id is not None:
        qs = qs.filter(company_id=company_id)
    rows = list(qs)
    statuses = creator_statuses(rows)
    return [agent_snapshot(agent, creator_status=statuses.get(str(agent.pk))) for agent in rows]


def blocked_agent_snapshots(*, company_id: int | None = None) -> list[dict]:
    """Blocked subset only. The poll response uses ``regional_agent_snapshots``."""
    ids = blocked_agent_ids(company_id=company_id)
    if not ids:
        return []
    rows = list(Agent.objects.filter(pk__in=ids).order_by('id'))
    statuses = creator_statuses(rows)
    return [agent_snapshot(agent, creator_status=statuses.get(str(agent.pk))) for agent in rows]
