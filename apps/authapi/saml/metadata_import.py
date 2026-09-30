"""SSRF-pinned SAML IdP metadata import with response size cap."""

from __future__ import annotations

from defusedxml import ElementTree as DefusedET

from apps.authapi.oauth_pinned_http import pinned_fetch_bytes
from apps.authapi.oauth_safe_http import MAX_OAUTH_FETCH_BYTES, MAX_REDIRECTS, assert_public_http_url

METADATA_PARSE_NS = {
    'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
}


def fetch_idp_metadata_xml(metadata_url: str) -> bytes:
    url = assert_public_http_url(metadata_url)
    status, _, payload = pinned_fetch_bytes(
        url,
        timeout=20,
        max_redirects=MAX_REDIRECTS,
        max_bytes=MAX_OAUTH_FETCH_BYTES,
    )
    if status >= 400:
        raise ValueError('metadata_fetch_failed')
    return payload


def parse_idp_metadata(xml_bytes: bytes, *, expected_entity_id: str) -> dict:
    root = DefusedET.fromstring(xml_bytes)
    entity_id = str(expected_entity_id or '').strip()
    if not entity_id:
        raise ValueError('idp_entity_id_required')
    entity_nodes = root.findall('.//md:EntityDescriptor', METADATA_PARSE_NS)
    if not entity_nodes:
        raise ValueError('metadata_parse_failed')
    target = None
    for node in entity_nodes:
        if node.get('entityID') == entity_id:
            target = node
            break
    if target is None:
        raise ValueError('metadata_entity_id_mismatch')
    sso = target.find('.//md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]', METADATA_PARSE_NS)
    if sso is None:
        sso = target.find('.//md:SingleSignOnService', METADATA_PARSE_NS)
    if sso is None or not sso.get('Location'):
        raise ValueError('metadata_missing_sso')
    cert_node = target.find('.//ds:X509Certificate', METADATA_PARSE_NS)
    if cert_node is None or not (cert_node.text or '').strip():
        raise ValueError('metadata_missing_certificate')
    cert = ''.join(str(cert_node.text or '').split())
    slo_node = target.find('.//md:SingleLogoutService', METADATA_PARSE_NS)
    slo_url = str(slo_node.get('Location') or '').strip() if slo_node is not None else ''
    sso_url = str(sso.get('Location') or '').strip()
    assert_public_http_url(sso_url)
    idp: dict = {
        'entity_id': entity_id,
        'sso_url': sso_url,
        'x509cert': cert,
    }
    if slo_url:
        assert_public_http_url(slo_url)
        idp['slo_url'] = slo_url
    return {'idp': idp}
