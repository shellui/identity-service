"""Refuse MCP OAuth for operator accounts."""

from __future__ import annotations

from django.contrib.auth.models import AbstractBaseUser


def is_mcp_oauth_refused_user(user: AbstractBaseUser) -> bool:
    if getattr(user, 'is_superuser', False) or getattr(user, 'is_staff', False):
        return True
    if getattr(user, 'is_global_staff', False):
        return True
    return False
