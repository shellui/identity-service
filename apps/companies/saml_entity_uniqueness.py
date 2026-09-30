"""Global SAML IdP entity ID uniqueness across companies."""

from __future__ import annotations

from allauth.socialaccount.models import SocialApp


def idp_entity_id_from_social_app(app: SocialApp) -> str:
    settings_data = app.settings if isinstance(getattr(app, 'settings', None), dict) else {}
    idp = settings_data.get('idp') if isinstance(settings_data.get('idp'), dict) else {}
    return str(idp.get('entity_id') or '').strip().lower()


def find_cross_company_saml_entity_id_conflict(
    entity_id: str,
    *,
    company_id: int,
    exclude_social_app_id: int | None = None,
) -> SocialApp | None:
    normalized = str(entity_id or '').strip().lower()
    if not normalized:
        return None
    qs = SocialApp.objects.filter(provider='saml')
    if exclude_social_app_id is not None:
        qs = qs.exclude(pk=exclude_social_app_id)
    for app in qs.iterator():
        if idp_entity_id_from_social_app(app) != normalized:
            continue
        settings_data = app.settings if isinstance(app.settings, dict) else {}
        try:
            owner = int(settings_data.get('shellui_company_id'))
        except (TypeError, ValueError):
            owner = None
        if owner is not None and int(owner) == int(company_id):
            continue
        return app
    return None
