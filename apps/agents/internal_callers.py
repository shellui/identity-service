"""Registry of services trusted to sign internal MCP assertions (RS256, one key per caller)."""

from __future__ import annotations

from dataclasses import dataclass

import jwt
from django.conf import settings
from django.core.cache import cache
from shellui_django.mcp.identity_jwks import IdentityJwksError, get_jwks_document
from shellui_django.mcp.internal import (
    APPROVAL_SCOPE,
    INTERNAL_ASSERTION_LEEWAY_SECONDS,
    INTERNAL_ASSERTION_MAX_LIFETIME_SECONDS,
    InternalAssertionError,
    verify_mcp_internal_assertion,
)

from apps.agents.ai_service_config import (
    ai_service_issuer,
    resolve_ai_service_verification_material,
)
from apps.federation.parsing import parse_jwks

_JTI_CACHE_PREFIX = 'mcp:internal-assertion:jti:'

# Services that sign with their own key and publish it at ``{origin}/.well-known/jwks.json``.
JWKS_CALLERS = ('storage', 'hosting', 'email')


@dataclass(frozen=True)
class TrustedCaller:
    name: str
    issuer: str


@dataclass(frozen=True)
class VerifiedAssertion:
    """Verified JWT claims plus which registered caller key matched ``iss``."""

    claims: dict
    caller: TrustedCaller


def _setting(name: str) -> str:
    return str(getattr(settings, name, '') or '').strip().rstrip('/')


def _jwks_caller_issuer(name: str) -> str:
    return _setting(f'{name.upper()}_SERVICE_ISSUER')


def trusted_callers() -> list[TrustedCaller]:
    """Callers with an explicit issuer. Unset issuer means that caller is not trusted."""
    callers = [TrustedCaller('ai', ai_service_issuer())]
    callers += [TrustedCaller(name, _jwks_caller_issuer(name)) for name in JWKS_CALLERS]
    callers.append(TrustedCaller('dashboard', _setting('PROVISIONING_ISSUER')))
    return [caller for caller in callers if caller.issuer]


def _jwks_caller_material(name: str) -> dict:
    prefix = name.upper()
    inline = getattr(settings, f'{prefix}_SERVICE_JWKS', None) or {}
    if isinstance(inline, str):
        inline = parse_jwks(inline)
    if isinstance(inline, dict) and inline.get('keys'):
        return inline
    url = _setting(f'{prefix}_SERVICE_JWKS_URL')
    if not url:
        origin = _setting(f'{prefix}_SERVICE_HTTP_URL')
        url = f'{origin}/.well-known/jwks.json' if origin else ''
    if not url:
        raise IdentityJwksError(f'{name} service JWKS is not configured.')
    timeout = float(getattr(settings, 'INTERNAL_CALLER_JWKS_TIMEOUT_SECONDS', 10.0))
    return get_jwks_document(jwks_url=url, timeout=timeout)


def caller_verification_material(caller: TrustedCaller) -> dict | str:
    if caller.name == 'ai':
        return resolve_ai_service_verification_material()
    if caller.name == 'dashboard':
        pem = (getattr(settings, 'PROVISIONING_PUBLIC_KEY', '') or '').strip()
        if not pem:
            raise IdentityJwksError('Dashboard public key is not configured.')
        return pem
    return _jwks_caller_material(caller.name)


def _caller_for_issuer(issuer: str) -> TrustedCaller | None:
    wanted = issuer.strip().rstrip('/')
    for caller in trusted_callers():
        if caller.issuer == wanted:
            return caller
    return None


def _assertion_jti_cache_ttl_seconds(max_lifetime_seconds: int) -> int:
    return max_lifetime_seconds + INTERNAL_ASSERTION_LEEWAY_SECONDS + 30


def _approval_assertion_max_lifetime_seconds() -> int:
    configured = int(getattr(settings, 'MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS', 0) or 0)
    floor = int(INTERNAL_ASSERTION_MAX_LIFETIME_SECONDS)
    return max(floor, configured)


def _register_jti_factory(max_lifetime_seconds: int):
    ttl = _assertion_jti_cache_ttl_seconds(max_lifetime_seconds)

    def _register_jti(jti: str) -> bool:
        return cache.add(f'{_JTI_CACHE_PREFIX}{jti}', 1, timeout=ttl)

    return _register_jti


def verify_caller_assertion(raw_token: str, *, audience: str, scope: str, target: str) -> VerifiedAssertion:
    """Verify an internal assertion against the key of the registered caller named in ``iss``.

    The unverified ``iss`` only selects which registered key to try. The signature, issuer,
    audience, scope, target, lifetime and single use of ``jti`` are then all enforced.
    """
    token = (raw_token or '').strip()
    if token.lower().startswith('bearer '):
        token = token[7:].strip()
    if not token:
        raise InternalAssertionError('Missing assertion.')
    try:
        unverified = jwt.decode(token, options={'verify_signature': False})
    except jwt.PyJWTError as exc:
        raise InternalAssertionError('Invalid assertion.') from exc
    caller = _caller_for_issuer(str(unverified.get('iss') or ''))
    if caller is None:
        raise InternalAssertionError('Unknown assertion issuer.')
    try:
        material = caller_verification_material(caller)
    except IdentityJwksError as exc:
        raise InternalAssertionError('Caller verification key is unavailable.', status=503) from exc
    max_lifetime = (
        _approval_assertion_max_lifetime_seconds() if scope == APPROVAL_SCOPE else INTERNAL_ASSERTION_MAX_LIFETIME_SECONDS
    )
    claims = verify_mcp_internal_assertion(
        token,
        material,
        expected_issuer=caller.issuer,
        expected_audience=audience,
        expected_scope=scope,
        expected_target=target,
        register_jti=_register_jti_factory(max_lifetime),
        max_lifetime_seconds=max_lifetime,
    )
    if scope == APPROVAL_SCOPE and caller.name in JWKS_CALLERS and claims.get('service') != caller.name:
        # A service key may only request approvals for its own tools.
        raise InternalAssertionError('Assertion service does not match caller.', status=403)
    return VerifiedAssertion(claims=claims, caller=caller)
