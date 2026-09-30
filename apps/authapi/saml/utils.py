"""Build python3-saml settings for identity-hosted SP endpoints."""

from __future__ import annotations

from django.http import HttpRequest
from django.urls import reverse
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.errors import OneLogin_Saml2_Error

from apps.authapi.saml.organization import idp_entity_id_from_settings


class SAMLConfigError(Exception):
    """Stored IdP settings cannot be turned into a python3-saml configuration."""


def _reverse_sp_url(request: HttpRequest, name: str, organization_slug: str) -> str:
    return request.build_absolute_uri(reverse(name, kwargs={'organization_slug': organization_slug}))


def sp_acs_url(request: HttpRequest, organization_slug: str) -> str:
    return _reverse_sp_url(request, 'shellui-saml-acs', organization_slug)


def sp_sls_url(request: HttpRequest, organization_slug: str) -> str:
    return _reverse_sp_url(request, 'shellui-saml-sls', organization_slug)


def sp_entity_id(request: HttpRequest, organization_slug: str) -> str:
    return _reverse_sp_url(request, 'shellui-saml-metadata', organization_slug)


def default_shellui_saml_advanced() -> dict:
    return {
        'reject_idp_initiated_sso': True,
        'want_message_signed': False,
    }


def merge_shellui_advanced(existing: dict | None) -> dict:
    """
    Keep only the advanced options a company admin may choose.

    Everything that weakens response validation (strict mode, signed assertions, deprecated
    algorithms) is fixed in ``security_settings`` and never read from stored settings.
    """
    merged = default_shellui_saml_advanced()
    if not isinstance(existing, dict):
        return merged
    if 'reject_idp_initiated_sso' in existing:
        merged['reject_idp_initiated_sso'] = bool(existing['reject_idp_initiated_sso'])
    if existing.get('want_message_signed') is True:
        merged['want_message_signed'] = True
    return merged


def idp_initiated_sso_allowed(settings_data: dict) -> bool:
    advanced = settings_data.get('advanced') if isinstance(settings_data.get('advanced'), dict) else {}
    return not merge_shellui_advanced(advanced)['reject_idp_initiated_sso']


def security_settings(settings_data: dict, *, require_signed_messages: bool = False) -> dict:
    advanced = merge_shellui_advanced(
        settings_data.get('advanced') if isinstance(settings_data.get('advanced'), dict) else {}
    )
    return {
        'authnRequestsSigned': False,
        'logoutRequestSigned': False,
        'logoutResponseSigned': False,
        'signMetadata': False,
        'wantAssertionsSigned': True,
        'wantMessagesSigned': bool(require_signed_messages or advanced['want_message_signed']),
        'wantAssertionsEncrypted': False,
        'wantNameId': True,
        'wantNameIdEncrypted': False,
        'nameIdEncrypted': False,
        'wantAttributeStatement': False,
        'allowRepeatAttributeName': True,
        'requestedAuthnContext': False,
        'failOnAuthnContextMismatch': False,
        'allowSingleLabelDomains': False,
        'rejectDeprecatedAlgorithm': True,
        'signatureAlgorithm': OneLogin_Saml2_Constants.RSA_SHA256,
        'digestAlgorithm': OneLogin_Saml2_Constants.SHA256,
    }


def idp_signing_certificates(idp: dict) -> list[str]:
    certs = idp.get('x509certs')
    if isinstance(certs, list):
        cleaned = [''.join(str(cert).split()) for cert in certs if isinstance(cert, str) and cert.strip()]
    else:
        cleaned = []
    single = idp.get('x509cert')
    if isinstance(single, str) and single.strip():
        value = ''.join(single.split())
        if value not in cleaned:
            cleaned.insert(0, value)
    return cleaned


def resolve_idp_block(settings_data: dict) -> dict:
    """python3-saml ``idp`` block from the stored snapshot. Never fetches metadata at request time."""
    idp = settings_data.get('idp')
    if not isinstance(idp, dict):
        raise SAMLConfigError('idp_config_missing')
    entity_id = str(idp.get('entity_id') or '').strip()
    sso_url = str(idp.get('sso_url') or '').strip()
    certs = idp_signing_certificates(idp)
    if not entity_id or not sso_url or not certs:
        raise SAMLConfigError('idp_config_incomplete')
    block: dict = {
        'entityId': entity_id,
        'singleSignOnService': {
            'url': sso_url,
            'binding': OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
        },
        'x509cert': certs[0],
    }
    if len(certs) > 1:
        block['x509certMulti'] = {'signing': certs}
    slo_url = str(idp.get('slo_url') or '').strip()
    if slo_url:
        slo: dict = {'url': slo_url, 'binding': OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT}
        slo_response_url = str(idp.get('slo_response_url') or '').strip()
        if slo_response_url:
            slo['responseUrl'] = slo_response_url
        block['singleLogoutService'] = slo
    return block


def build_sp_config(request: HttpRequest, organization_slug: str) -> dict:
    return {
        'entityId': sp_entity_id(request, organization_slug),
        'assertionConsumerService': {
            'url': sp_acs_url(request, organization_slug),
            'binding': OneLogin_Saml2_Constants.BINDING_HTTP_POST,
        },
        'singleLogoutService': {
            'url': sp_sls_url(request, organization_slug),
            'binding': OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
        },
        'NameIDFormat': OneLogin_Saml2_Constants.NAMEID_UNSPECIFIED,
    }


def build_saml_config(
    request: HttpRequest,
    settings_data: dict,
    organization_slug: str,
    *,
    require_signed_messages: bool = False,
    include_idp: bool = True,
) -> dict:
    config: dict = {
        'strict': True,
        'debug': False,
        'security': security_settings(settings_data, require_signed_messages=require_signed_messages),
        'sp': build_sp_config(request, organization_slug),
    }
    if include_idp:
        config['idp'] = resolve_idp_block(settings_data)
    return config


def prepare_django_request(request: HttpRequest, *, path_info: str | None = None, post_data: dict | None = None) -> dict:
    return {
        'https': 'on' if request.is_secure() else 'off',
        'http_host': request.get_host(),
        'script_name': request.META.get('SCRIPT_NAME', ''),
        'path_info': path_info if path_info is not None else request.path_info,
        'get_data': request.GET.dict() if post_data is None else {},
        'post_data': dict(post_data) if post_data is not None else request.POST.dict(),
        'query_string': request.META.get('QUERY_STRING', '') if post_data is None else '',
        'validate_signature_from_qs': True,
    }


def build_auth(
    request: HttpRequest,
    social_app,
    *,
    request_data: dict | None = None,
    require_signed_messages: bool = False,
):
    from apps.authapi.saml.validation import ShellUISAMLAuth

    settings_data = social_app.settings if isinstance(social_app.settings, dict) else {}
    config = build_saml_config(
        request,
        settings_data,
        str(social_app.client_id),
        require_signed_messages=require_signed_messages,
    )
    try:
        return ShellUISAMLAuth(request_data or prepare_django_request(request), config)
    except OneLogin_Saml2_Error as exc:
        raise SAMLConfigError('settings_invalid') from exc


def sp_public_urls(request: HttpRequest, organization_slug: str, *, settings_data: dict) -> dict:
    return {
        'acs_url': sp_acs_url(request, organization_slug),
        'entity_id': sp_entity_id(request, organization_slug),
        'metadata_url': sp_entity_id(request, organization_slug),
        'sls_url': sp_sls_url(request, organization_slug),
        'idp_entity_id': idp_entity_id_from_settings(settings_data),
    }
