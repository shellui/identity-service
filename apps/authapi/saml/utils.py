"""Build python3-saml settings for identity-hosted SP endpoints."""

from __future__ import annotations

from django.http import HttpRequest
from django.urls import reverse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.constants import OneLogin_Saml2_Constants

from apps.authapi.saml.metadata_import import fetch_idp_metadata_xml, parse_idp_metadata
from apps.authapi.saml.organization import idp_entity_id_from_settings


def shellui_saml_clock_skew_seconds() -> int:
    return 90


def _reverse_sp_url(request: HttpRequest, name: str, organization_slug: str) -> str:
    return request.build_absolute_uri(reverse(name, kwargs={'organization_slug': organization_slug}))


def default_shellui_saml_advanced() -> dict:
    return {
        'strict': True,
        'reject_idp_initiated_sso': True,
        'authn_request_signed': False,
        'want_assertion_signed': True,
        'want_message_signed': False,
        'reject_deprecated_algorithm': True,
        'allow_single_label_domains': False,
        'want_attribute_statement': True,
    }


def merge_shellui_advanced(existing: dict | None) -> dict:
    base = default_shellui_saml_advanced()
    if isinstance(existing, dict):
        for key, value in existing.items():
            if key == 'reject_idp_initiated_sso':
                base[key] = bool(value)
            elif key in base:
                base[key] = value
    return base


def build_sp_config(request: HttpRequest, provider_config: dict, organization_slug: str) -> dict:
    acs_url = _reverse_sp_url(request, 'shellui-saml-acs', organization_slug)
    sls_url = _reverse_sp_url(request, 'shellui-saml-sls', organization_slug)
    metadata_url = _reverse_sp_url(request, 'shellui-saml-metadata', organization_slug)
    sp_block = provider_config.get('sp') if isinstance(provider_config.get('sp'), dict) else {}
    sp_entity_id = str(sp_block.get('entity_id') or '').strip() or metadata_url
    sp_config = {
        'entityId': sp_entity_id,
        'assertionConsumerService': {
            'url': acs_url,
            'binding': OneLogin_Saml2_Constants.BINDING_HTTP_POST,
        },
        'singleLogoutService': {
            'url': sls_url,
            'binding': OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
        },
    }
    avd = merge_shellui_advanced(provider_config.get('advanced') if isinstance(provider_config.get('advanced'), dict) else {})
    if avd.get('x509cert') is not None:
        sp_config['x509cert'] = avd['x509cert']
    if avd.get('x509cert_new'):
        sp_config['x509certNew'] = avd['x509cert_new']
    if avd.get('private_key') is not None:
        sp_config['privateKey'] = avd['private_key']
    if avd.get('name_id_format') is not None:
        sp_config['NameIDFormat'] = avd['name_id_format']
    return sp_config


def resolve_idp_block(provider_config: dict) -> dict:
    idp = provider_config.get('idp')
    if not isinstance(idp, dict):
        raise ValueError('idp_config_missing')
    metadata_url = str(idp.get('metadata_url') or '').strip()
    entity_id = str(idp.get('entity_id') or '').strip()
    if metadata_url:
        xml_bytes = fetch_idp_metadata_xml(metadata_url)
        parsed = parse_idp_metadata(xml_bytes, expected_entity_id=entity_id)
        merged = dict(idp)
        merged.update(parsed['idp'])
        merged.pop('metadata_url', None)
        return merged
    cert = str(idp.get('x509cert') or '').strip()
    sso_url = str(idp.get('sso_url') or '').strip()
    if not entity_id or not cert or not sso_url:
        raise ValueError('idp_manual_config_incomplete')
    block = {
        'entityId': entity_id,
        'x509cert': cert,
        'singleSignOnService': {'url': sso_url},
    }
    slo_url = str(idp.get('slo_url') or '').strip()
    if slo_url:
        block['singleLogoutService'] = {'url': slo_url}
    return block


def build_saml_config(request: HttpRequest, provider_config: dict, organization_slug: str) -> dict:
    avd = merge_shellui_advanced(provider_config.get('advanced') if isinstance(provider_config.get('advanced'), dict) else {})
    security_config = {
        'authnRequestsSigned': avd.get('authn_request_signed', False),
        'digestAlgorithm': avd.get('digest_algorithm', OneLogin_Saml2_Constants.SHA256),
        'logoutRequestSigned': avd.get('logout_request_signed', False),
        'logoutResponseSigned': avd.get('logout_response_signed', False),
        'requestedAuthnContext': False,
        'signatureAlgorithm': avd.get(
            'signature_algorithm', OneLogin_Saml2_Constants.RSA_SHA256
        ),
        'signMetadata': avd.get('metadata_signed', False),
        'wantAssertionsEncrypted': avd.get('want_assertion_encrypted', False),
        'wantAssertionsSigned': avd.get('want_assertion_signed', True),
        'wantMessagesSigned': avd.get('want_message_signed', False),
        'nameIdEncrypted': avd.get('name_id_encrypted', False),
        'wantNameIdEncrypted': avd.get('want_name_id_encrypted', False),
        'allowSingleLabelDomains': avd.get('allow_single_label_domains', False),
        'rejectDeprecatedAlgorithm': avd.get('reject_deprecated_algorithm', True),
        'wantNameId': avd.get('want_name_id', True),
        'wantAttributeStatement': avd.get('want_attribute_statement', True),
        'allowRepeatAttributeName': avd.get('allow_repeat_attribute_name', True),
    }
    saml_config = {
        'strict': avd.get('strict', True),
        'security': security_config,
        'clockSkew': shellui_saml_clock_skew_seconds(),
    }
    contact_person = provider_config.get('contact_person')
    if contact_person:
        saml_config['contactPerson'] = contact_person
    organization = provider_config.get('organization')
    if organization:
        saml_config['organization'] = organization
    idp_block = resolve_idp_block(provider_config)
    saml_config['idp'] = idp_block
    saml_config['sp'] = build_sp_config(request, provider_config, organization_slug)
    attribute_mapping = provider_config.get('attribute_mapping')
    if isinstance(attribute_mapping, dict) and attribute_mapping:
        saml_config['attributeConsumingService'] = {'serviceName': 'Shellui', 'attributes': []}
    return saml_config


def prepare_django_request(request: HttpRequest) -> dict:
    return {
        'https': 'on' if request.is_secure() else 'off',
        'http_host': request.META.get('HTTP_HOST') or request.get_host(),
        'script_name': request.META.get('SCRIPT_NAME'),
        'path_info': request.META['PATH_INFO'],
        'get_data': request.GET.copy(),
        'post_data': request.POST.copy(),
    }


def build_auth(request: HttpRequest, social_app) -> OneLogin_Saml2_Auth:
    settings_data = social_app.settings if isinstance(social_app.settings, dict) else {}
    config = build_saml_config(request, settings_data, str(social_app.client_id))
    return OneLogin_Saml2_Auth(prepare_django_request(request), config)


def sp_public_urls(request: HttpRequest, organization_slug: str, *, settings_data: dict) -> dict:
    sp = build_sp_config(request, settings_data, organization_slug)
    return {
        'acs_url': sp['assertionConsumerService']['url'],
        'entity_id': sp['entityId'],
        'metadata_url': _reverse_sp_url(request, 'shellui-saml-metadata', organization_slug),
        'sls_url': sp['singleLogoutService']['url'],
        'idp_entity_id': idp_entity_id_from_settings(settings_data),
    }
