"""SSRF-pinned SAML IdP metadata import with response size cap."""

from __future__ import annotations

from defusedxml import ElementTree as DefusedET

from apps.actions.ssrf import SSRFError
from apps.authapi.oauth_pinned_http import pinned_fetch_bytes
from apps.authapi.oauth_safe_http import MAX_OAUTH_FETCH_BYTES, MAX_REDIRECTS, assert_public_http_url

METADATA_PARSE_NS = {
    'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
}


def fetch_idp_metadata_xml(metadata_url: str) -> bytes:
    try:
        url = assert_public_http_url(metadata_url)
    except SSRFError as exc:
        raise ValueError('saml_metadata_url_blocked') from exc
    status, _, payload = pinned_fetch_bytes(
        url,
        timeout=20,
        max_redirects=MAX_REDIRECTS,
        max_bytes=MAX_OAUTH_FETCH_BYTES,
    )
    if status >= 400 or not payload:
        raise ValueError('saml_metadata_fetch_failed')
    return payload


def _signing_certificates(entity) -> list[str]:
    certs: list[str] = []
    descriptors = entity.findall('./md:IDPSSODescriptor', METADATA_PARSE_NS)
    if not descriptors:
        descriptors = entity.findall('.//md:IDPSSODescriptor', METADATA_PARSE_NS)
    for descriptor in descriptors:
        for key_descriptor in descriptor.findall('./md:KeyDescriptor', METADATA_PARSE_NS):
            use = str(key_descriptor.get('use') or '').strip().lower()
            if use == 'encryption':
                continue
            cert_node = key_descriptor.find('.//ds:X509Certificate', METADATA_PARSE_NS)
            if cert_node is None or not (cert_node.text or '').strip():
                continue
            cert = ''.join(str(cert_node.text or '').split())
            if cert not in certs:
                certs.append(cert)
    return certs


def parse_idp_metadata(xml_bytes: bytes, *, expected_entity_id: str) -> dict:
    root = DefusedET.fromstring(xml_bytes)
    entity_id = str(expected_entity_id or '').strip()
    if not entity_id:
        raise ValueError('saml_idp_entity_id_required')
    metadata_tag = '{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor'
    entity_nodes = [root] if root.tag == metadata_tag else []
    entity_nodes.extend(root.findall('.//md:EntityDescriptor', METADATA_PARSE_NS))
    if not entity_nodes:
        raise ValueError('saml_metadata_parse_failed')
    target = None
    for node in entity_nodes:
        if node.get('entityID') == entity_id:
            target = node
            break
    if target is None:
        raise ValueError('saml_metadata_entity_id_mismatch')
    sso = target.find(
        './/md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]',
        METADATA_PARSE_NS,
    )
    if sso is None or not sso.get('Location'):
        raise ValueError('saml_metadata_missing_sso')
    certs = _signing_certificates(target)
    if not certs:
        raise ValueError('saml_metadata_missing_certificate')
    slo_node = target.find(
        './/md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]',
        METADATA_PARSE_NS,
    )
    slo_url = str(slo_node.get('Location') or '').strip() if slo_node is not None else ''
    sso_url = str(sso.get('Location') or '').strip()
    try:
        assert_public_http_url(sso_url)
    except SSRFError as exc:
        raise ValueError('saml_metadata_sso_url_blocked') from exc
    idp: dict = {
        'entity_id': entity_id,
        'sso_url': sso_url,
        'x509cert': certs[0],
    }
    if len(certs) > 1:
        idp['x509certs'] = certs
    if slo_url:
        try:
            assert_public_http_url(slo_url)
        except SSRFError as exc:
            raise ValueError('saml_metadata_slo_url_blocked') from exc
        idp['slo_url'] = slo_url
        response_location = str(slo_node.get('ResponseLocation') or '').strip() if slo_node is not None else ''
        if response_location:
            try:
                assert_public_http_url(response_location)
            except SSRFError as exc:
                raise ValueError('saml_metadata_slo_url_blocked') from exc
            idp['slo_response_url'] = response_location
    return {'idp': idp}
