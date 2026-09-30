"""Normalize SAML SocialApp.settings from admin API extra_settings."""

from __future__ import annotations

from typing import Any

from apps.authapi.oauth_safe_http import assert_public_http_url
from apps.authapi.provider_registry import ProviderCatalogEntry
from apps.authapi.saml.utils import merge_shellui_advanced


def merge_saml_social_settings(
    entry: ProviderCatalogEntry,
    validated: dict,
    *,
    existing: dict | None = None,
    company_id: int,
) -> tuple[dict, str | None]:
    base = dict(existing or {})
    extra = dict(validated.get('extra_settings') or {})
    idp_input = extra.get('idp') if isinstance(extra.get('idp'), dict) else {}
    if not idp_input and isinstance(base.get('idp'), dict):
        idp_input = dict(base['idp'])

    entity_id = str(
        extra.get('idp_entity_id')
        or idp_input.get('entity_id')
        or base.get('idp', {}).get('entity_id')
        or ''
    ).strip()
    if not entity_id:
        return base, 'error_code:saml_idp_entity_id_required'

    idp: dict[str, Any] = {'entity_id': entity_id}
    metadata_url = str(
        extra.get('metadata_url') or idp_input.get('metadata_url') or ''
    ).strip()
    if metadata_url:
        try:
            assert_public_http_url(metadata_url)
        except Exception:
            return base, 'error_code:saml_metadata_url_blocked'
        idp['metadata_url'] = metadata_url

    sso_url = str(extra.get('sso_url') or idp_input.get('sso_url') or '').strip()
    cert = str(extra.get('x509cert') or idp_input.get('x509cert') or '').strip()
    if not metadata_url:
        if not sso_url or not cert:
            return base, 'error_code:saml_idp_manual_fields_required'
        try:
            assert_public_http_url(sso_url)
        except Exception:
            return base, 'error_code:saml_sso_url_blocked'
        idp['sso_url'] = sso_url
        idp['x509cert'] = cert
    slo_url = str(extra.get('slo_url') or idp_input.get('slo_url') or '').strip()
    if slo_url:
        try:
            assert_public_http_url(slo_url)
        except Exception:
            return base, 'error_code:saml_slo_url_blocked'
        idp['slo_url'] = slo_url

    attribute_mapping = extra.get('attribute_mapping')
    if attribute_mapping is None and isinstance(base.get('attribute_mapping'), dict):
        attribute_mapping = base['attribute_mapping']
    if not isinstance(attribute_mapping, dict):
        attribute_mapping = {
            'uid': ['urn:oasis:names:tc:SAML:attribute:subject-id'],
            'email': [
                'urn:oid:0.9.2342.19200300.100.1.3',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
            ],
            'first_name': [
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
            ],
            'last_name': [
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/familyname',
                'urn:oid:2.5.4.4',
            ],
        }

    advanced = merge_shellui_advanced(base.get('advanced') if isinstance(base.get('advanced'), dict) else {})
    adv_in = extra.get('advanced') if isinstance(extra.get('advanced'), dict) else {}
    if 'allow_idp_initiated_sso' in extra:
        advanced['reject_idp_initiated_sso'] = not bool(extra.get('allow_idp_initiated_sso'))
    if isinstance(adv_in, dict) and 'reject_idp_initiated_sso' in adv_in:
        advanced['reject_idp_initiated_sso'] = bool(adv_in['reject_idp_initiated_sso'])
    if isinstance(adv_in, dict) and 'want_message_signed' in adv_in:
        advanced['want_message_signed'] = bool(adv_in['want_message_signed'])
    advanced = merge_shellui_advanced(advanced)

    trusted = bool(extra.get('trusted_for_verified_domains', base.get('trusted_for_verified_domains', False)))

    base['catalog_slug'] = entry.docs_slug
    base['shellui_company_id'] = int(company_id)
    base['idp'] = idp
    base['attribute_mapping'] = attribute_mapping
    base['advanced'] = advanced
    base['trusted_for_verified_domains'] = trusted
    if 'use_nameid_for_email' in extra:
        base['use_nameid_for_email'] = bool(extra.get('use_nameid_for_email'))
    return base, None
