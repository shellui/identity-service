"""Small helpers for OAuth adapter tests (no profile echo / catch-all HTTP mocks)."""

from __future__ import annotations

from allauth.socialaccount.models import SocialApp


def authorize_get_path(slug: str) -> str:
    if slug == 'shopify':
        return '/api/v1/authorize?shop=fixture-shop.myshopify.com'
    return '/api/v1/authorize'


def prepare_social_app_for_audit(slug: str, app: SocialApp) -> None:
    if slug == 'apple':
        app.key = 'APPLE-TEAM-ID'
        settings_data = dict(app.settings or {})
        settings_data['certificate_key'] = _ephemeral_apple_audit_certificate_key()
        app.settings = settings_data
        app.save(update_fields=['key', 'settings'])


def _ephemeral_apple_audit_certificate_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
