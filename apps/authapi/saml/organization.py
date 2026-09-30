"""Organization slug (SocialApp.client_id) and company binding for SAML IdPs."""

from __future__ import annotations

import re
import secrets

from allauth.socialaccount.models import SocialApp
from django.http import Http404

from apps.companies.models import Company, CompanyOAuthClient

ORG_SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{7,127}$')


def generate_organization_slug(*, company_id: int) -> str:
    prefix = f'c{int(company_id)}-'
    suffix = secrets.token_hex(8)
    slug = f'{prefix}{suffix}'
    return slug[:128]


def assert_valid_organization_slug(value: str) -> str:
    cleaned = str(value or '').strip().lower()
    if not ORG_SLUG_RE.fullmatch(cleaned):
        raise ValueError('invalid_organization_slug')
    return cleaned


def shellui_company_id_from_app(app: SocialApp) -> int | None:
    settings_data = app.settings if isinstance(getattr(app, 'settings', None), dict) else {}
    raw = settings_data.get('shellui_company_id')
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def get_saml_app_for_slug(request, organization_slug: str) -> SocialApp:
    from apps.authapi.oauth_social_account import get_bound_oauth_social_app

    bound = get_bound_oauth_social_app(request)
    if bound is not None:
        if str(bound.client_id).strip().lower() != str(organization_slug).strip().lower():
            raise SocialApp.DoesNotExist()
        if str(bound.provider).strip().lower() != 'saml':
            raise SocialApp.DoesNotExist()
        return bound
    slug = assert_valid_organization_slug(organization_slug)
    try:
        app = SocialApp.objects.get(provider='saml', client_id=slug)
    except SocialApp.DoesNotExist as exc:
        raise Http404('saml_app_not_found') from exc
    if str(app.provider).strip().lower() != 'saml':
        raise Http404('saml_app_not_found')
    return app


def require_company_for_saml_app(app: SocialApp, *, company_id: int) -> Company:
    owner = shellui_company_id_from_app(app)
    if owner is None or int(owner) != int(company_id):
        raise PermissionError('saml_company_mismatch')
    try:
        return Company.objects.get(pk=int(company_id))
    except Company.DoesNotExist as exc:
        raise PermissionError('saml_company_mismatch') from exc


def company_owns_saml_app(company_id: int, app: SocialApp) -> bool:
    linked = CompanyOAuthClient.objects.filter(company_id=company_id, social_app=app).exists()
    if not linked:
        return False
    owner = shellui_company_id_from_app(app)
    return owner is not None and int(owner) == int(company_id)


def idp_entity_id_from_settings(settings_data: dict) -> str:
    idp = settings_data.get('idp') if isinstance(settings_data.get('idp'), dict) else {}
    return str(idp.get('entity_id') or '').strip()
