"""Extra SAML response checks after python3-saml validation."""

from __future__ import annotations

from onelogin.saml2.auth import OneLogin_Saml2_Auth

from apps.authapi.saml.replay import consume_assertion_id_once
from apps.authapi.saml.request_id import consume_saml_request_id


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
    assertion_ids = extract_assertion_ids(auth)
    if not assertion_ids:
        return False
    for aid in assertion_ids:
        if not consume_assertion_id_once(
            company_id=company_id,
            idp_entity_id=idp_entity_id,
            assertion_id=aid,
        ):
            return False
    return True
