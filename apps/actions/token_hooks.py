from apps.actions.emit import emit_event_if_rules
from apps.actions.identity_payloads import scim_token_payload


def emit_scim_token_created(company, token) -> None:
    emit_event_if_rules(
        'identity.scim.token.created',
        company,
        scim_token_payload(token),
    )


def emit_scim_token_revoked(company, token) -> None:
    emit_event_if_rules(
        'identity.scim.token.revoked',
        company,
        scim_token_payload(token),
    )
