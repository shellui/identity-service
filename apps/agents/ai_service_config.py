"""AI service (MCP connector) settings for downstream token delegation."""

from __future__ import annotations

from django.conf import settings

from shellui_django.mcp.identity_jwks import IdentityJwksError, get_jwks_document

from apps.federation.parsing import parse_jwks


def ai_service_url() -> str:
    return (getattr(settings, 'AI_SERVICE_URL', '') or '').strip().rstrip('/')


def ai_service_issuer() -> str:
    return (getattr(settings, 'AI_SERVICE_ISSUER', '') or '').strip().rstrip('/')


def ai_service_jwks_url() -> str:
    explicit = (getattr(settings, 'AI_SERVICE_JWKS_URL', '') or '').strip()
    if explicit:
        return explicit.rstrip('/')
    origin = ai_service_url()
    if origin:
        return f'{origin}/.well-known/jwks.json'
    return ''


def ai_service_inline_jwks() -> dict:
    raw = getattr(settings, 'AI_SERVICE_JWKS', None) or {}
    if isinstance(raw, dict) and raw.get('keys'):
        return raw
    if isinstance(raw, str) and raw.strip():
        return parse_jwks(raw)
    return {}


def ai_service_delegation_enabled() -> bool:
    if not ai_service_url() or not ai_service_issuer():
        return False
    inline = ai_service_inline_jwks()
    if inline.get('keys'):
        return True
    return bool(ai_service_jwks_url())


def resolve_ai_service_verification_material() -> dict | str:
    inline = ai_service_inline_jwks()
    if inline.get('keys'):
        return inline
    url = ai_service_jwks_url()
    if not url:
        raise IdentityJwksError('AI service JWKS is not configured.')
    timeout = float(getattr(settings, 'AI_SERVICE_JWKS_TIMEOUT_SECONDS', 10.0))
    return get_jwks_document(jwks_url=url, timeout=timeout)
