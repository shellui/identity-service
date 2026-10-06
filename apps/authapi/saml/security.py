"""Extra SAML response checks after python3-saml validation."""

from __future__ import annotations

import base64
import binascii

from lxml import etree

from apps.authapi.saml.request_id import consume_saml_request_id

SAML_PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol'


def extract_in_response_to_from_saml_response_b64(saml_response_b64: str | None) -> str | None:
    raw = str(saml_response_b64 or '').strip()
    if not raw:
        return None
    try:
        xml_bytes = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        root = etree.fromstring(xml_bytes)
    except etree.XMLSyntaxError:
        return None
    tag = etree.QName(root).localname
    if tag != 'Response':
        return None
    value = root.get('InResponseTo')
    return str(value).strip() if value else None


def validate_in_response_to(*, in_response_to: str | None, expected_company_id: int) -> dict | None:
    if not in_response_to:
        return None
    payload = consume_saml_request_id(in_response_to)
    if not payload:
        return None
    try:
        if int(payload.get('company_id')) != int(expected_company_id):
            return None
    except (TypeError, ValueError):
        return None
    return payload
