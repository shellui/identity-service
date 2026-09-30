"""Extra SAML response checks after python3-saml validation."""

from __future__ import annotations

import base64
import binascii

from lxml import etree
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from apps.authapi.saml.replay import (
    assertion_replay_ttl_seconds,
    consume_assertion_id_once,
    ensure_saml_replay_cache_backend,
)
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


def extract_assertion_ids(auth: OneLogin_Saml2_Auth) -> list[str]:
    aid = auth.get_last_assertion_id()
    if aid:
        return [str(aid)]
    return []


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


def enforce_replay_protection(
    auth: OneLogin_Saml2_Auth,
    *,
    company_id: int,
    idp_entity_id: str,
) -> bool:
    ensure_saml_replay_cache_backend()
    assertion_ids = extract_assertion_ids(auth)
    if not assertion_ids:
        return False
    ttl = assertion_replay_ttl_seconds(auth)
    if ttl is None:
        return False
    for aid in assertion_ids:
        if not consume_assertion_id_once(
            company_id=company_id,
            idp_entity_id=idp_entity_id,
            assertion_id=aid,
            ttl_seconds=ttl,
        ):
            return False
    return True
