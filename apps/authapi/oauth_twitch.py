"""Pinned Twitch OAuth endpoints (not company-configurable).

Twitch's Helix Get Users call is ``GET https://api.twitch.tv/helix/users``.
The ``email`` field is included only when the user access token has the
``user:read:email`` scope. Twitch documents that field as the user's verified
email address:

https://dev.twitch.tv/docs/api/reference#get-users

Authorize and token calls stay on ``https://id.twitch.tv``.
"""

from __future__ import annotations

TWITCH_ID_HOST = 'id.twitch.tv'
TWITCH_API_HOST = 'api.twitch.tv'

TWITCH_AUTHORIZE_URL = f'https://{TWITCH_ID_HOST}/oauth2/authorize'
TWITCH_ACCESS_TOKEN_URL = f'https://{TWITCH_ID_HOST}/oauth2/token'
TWITCH_PROFILE_URL = f'https://{TWITCH_API_HOST}/helix/users'

# Minimum scope that returns the verified email. allauth's TwitchProvider default.
TWITCH_SCOPE: tuple[str, ...] = ('user:read:email',)

# Company settings must not replace the pinned hosts or the scope.
TWITCH_FORBIDDEN_SETTINGS: frozenset[str] = frozenset(
    {
        'authorize_url',
        'access_token_url',
        'profile_url',
        'server_url',
        'scope',
        'SCOPE',
        'auth_params',
    }
)
