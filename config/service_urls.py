"""Resolve public service origins vs internal HTTP origins for container networks."""


def internal_origin(public_url: str, internal_url: str) -> str:
    """Prefer ``internal_url`` for server-to-server calls; fall back to ``public_url``."""
    chosen = (internal_url or public_url or '').strip()
    return chosen.rstrip('/')
