"""Per-user, per-company Shellui navigation overlay sync (schema version 1).

The document is stored once per (user, company). Runtime installs are
third-party only; the shared JSON Schema lives in
``apps/authapi/schemas/navigation-overlay.v1.json`` and must stay aligned
with the Shellui copy under ``packages/sdk/schemas/``.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone as dt_timezone
import unicodedata
from urllib.parse import urlsplit

from django.db import IntegrityError, transaction
from django.utils import timezone
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from rest_framework import serializers, status
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.actions.emit import emit_event_if_rules
from apps.authapi.models import UserNavigationOverlay
from apps.authapi.permissions import ShellUIPermission
from apps.authapi.throttling import check_rate_limit

OVERLAY_VERSION = 1
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_INSTALLED_APPS = 100
MAX_ORDER_ENTRIES = 200
MAX_HIDDEN_PATHS = 200
MAX_URL_LENGTH = 2048
MAX_NAME_LENGTH = 120
MAX_ID_LENGTH = 64
MAX_PATH_LENGTH = 200
MAX_CAPABILITIES = 8
MAX_ORIGIN_LENGTH = 2048

# Overlay entries are third-party only. ``auth`` is never accepted.
THIRD_PARTY_CAPABILITIES = frozenset({'theme', 'locale', 'ui', 'navigate', 'storage', 'ai'})

# First path segment, compared case-insensitively. Keep this list in sync with
# the reserved paths in the Shellui shell (packages/sdk, plus admin from
# getAdminPath). test_reserved_segments_match_the_shell_list pins the same set.
RESERVED_PATH_SEGMENTS = frozenset(
    {'admin', '__settings', 'legal', 'files', 'login', 'marketplace', 'settings'}
)

TOP_LEVEL_KEYS = frozenset({'version', 'installedApps', 'order', 'hiddenPaths', 'updatedAt'})
APP_REQUIRED_KEYS = frozenset(
    {'id', 'name', 'origin', 'url', 'path', 'thirdParty', 'capabilities', 'installedAt', 'updatedAt'}
)
APP_OPTIONAL_KEYS = frozenset({'icon'})
APP_KEYS = APP_REQUIRED_KEYS | APP_OPTIONAL_KEYS
SCOPING_KEYS = frozenset({'company_id', 'user_id', 'userId', 'user'})

_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
_PATH_RE = re.compile(
    r'^(?:/[A-Za-z0-9][A-Za-z0-9._-]*|[A-Za-z0-9][A-Za-z0-9._-]*)'
    r'(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$'
)
_HOST_RE = re.compile(
    r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*'
    r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
)


class OverlayValidationError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def _control_chars(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _format_chars(value: str) -> bool:
    """Invisible format characters (category Cf), such as U+202E or U+200B, that can disguise a name."""
    return any(unicodedata.category(ch) == 'Cf' for ch in value)


def _split_url(value: str, label: str):
    """urlsplit plus hostname and port, with malformed input (``https://[::1``, ``:99999``) as a 400."""
    try:
        parts = urlsplit(value)
        return parts, parts.hostname, parts.port
    except ValueError as exc:
        raise OverlayValidationError(f'{label} is not a valid URL.') from exc


# Carrier-grade NAT. ipaddress treats it as public (is_private is false).
_CGNAT = ipaddress.ip_network('100.64.0.0/10')


def _host_ends_in_a_number(host: str) -> bool:
    """WHATWG 'ends in a number': last label is all digits or starts with 0x.

    Browsers parse those forms as IPv4 (decimal 2130706433, hex 0x7f000001,
    short 127.1), so a hostname check that only looks at dotted literals
    would miss them.
    """
    last = host.rsplit('.', 1)[-1]
    lowered = last.lower()
    return lowered.startswith('0x') or last.isdigit()


def _blocked_host(host: str) -> bool:
    lowered = host.lower().rstrip('.')
    if (
        lowered == 'localhost'
        or lowered.endswith('.localhost')
        or lowered.endswith('.local')
        or lowered.endswith('.internal')
    ):
        return True
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        # Reject numeric IPv4 forms before the hostname regex, which would
        # otherwise accept them as ordinary labels.
        return _host_ends_in_a_number(lowered)
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or ip in _CGNAT
    )


def _https_url(value, *, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
        raise OverlayValidationError(f'{label} must be an https URL of at most {MAX_URL_LENGTH} characters.')
    if value != value.strip() or _control_chars(value) or '\\' in value or any(ch.isspace() for ch in value):
        raise OverlayValidationError(f'{label} must be an https URL.')
    parts, host, port = _split_url(value, label)
    if parts.scheme.lower() != 'https':
        raise OverlayValidationError(f'{label} must use https.')
    if parts.username is not None or parts.password is not None:
        raise OverlayValidationError(f'{label} must not include a username or password.')
    if not host:
        raise OverlayValidationError(f'{label} must include a host.')
    try:
        host.encode('idna')
    except UnicodeError as exc:
        raise OverlayValidationError(f'{label} has an invalid host.') from exc
    if port == 0:
        raise OverlayValidationError(f'{label} has an invalid port.')
    if _blocked_host(host):
        raise OverlayValidationError(f'{label} must not use a loopback, private, or otherwise blocked host.')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host) or not _HOST_RE.fullmatch(host):
            raise OverlayValidationError(f'{label} has an invalid host.')
    return value


def _origin_of(url: str, label: str = 'url') -> str:
    _parts, host, port = _split_url(url, label)
    if host is None:
        raise OverlayValidationError(f'{label} must include a host.')
    origin = f'https://{host}'
    if port and port != 443:
        origin = f'{origin}:{port}'
    return origin


def _https_origin(value, *, url: str, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_ORIGIN_LENGTH:
        raise OverlayValidationError(f'{label} must be an https origin of at most {MAX_ORIGIN_LENGTH} characters.')
    if value != value.strip() or _control_chars(value) or '\\' in value or any(ch.isspace() for ch in value):
        raise OverlayValidationError(f'{label} must be an https origin.')
    parts, host, _port = _split_url(value, label)
    if (
        parts.scheme.lower() != 'https'
        or parts.path not in ('', '/')
        or parts.query
        or parts.fragment
        or parts.username is not None
        or parts.password is not None
        or not host
    ):
        raise OverlayValidationError(f'{label} must be an https origin with no path, query, or fragment.')
    expected = _origin_of(url)
    origin = _origin_of(value, label)
    if origin != expected:
        raise OverlayValidationError(f'{label} must match the origin of url.')
    return origin


def _is_reserved_path(value: str) -> bool:
    lowered = value.lower()
    if '..' in value or '%2e' in lowered or '\\' in value:
        return True
    segments = [seg for seg in value.strip('/').split('/') if seg]
    if not segments:
        return True
    return segments[0].lower() in RESERVED_PATH_SEGMENTS


def _navigation_token(value, *, label: str, allow_reserved: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_LENGTH or value != value.strip():
        raise OverlayValidationError(f'{label} must be a path or id of at most {MAX_PATH_LENGTH} characters.')
    if _control_chars(value) or not _PATH_RE.fullmatch(value):
        raise OverlayValidationError(
            f'{label} must be a navigation path or id (letters, digits, ".", "_", "-", and "/").'
        )
    if not allow_reserved and _is_reserved_path(value):
        raise OverlayValidationError(f'{label} is a reserved core path.')
    return value


def _string_list(value, *, label: str, max_items: int, allow_reserved: bool) -> list[str]:
    if not isinstance(value, list):
        raise OverlayValidationError(f'{label} must be an array.')
    if len(value) > max_items:
        raise OverlayValidationError(f'{label} can include at most {max_items} entries.')
    cleaned: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        token = _navigation_token(item, label=f'{label}[{index}]', allow_reserved=allow_reserved)
        if token in seen:
            raise OverlayValidationError(f'{label}[{index}] is a duplicate.')
        seen.add(token)
        cleaned.append(token)
    return cleaned


def _capabilities(value, *, label: str) -> list[str]:
    if not isinstance(value, list):
        raise OverlayValidationError(f'{label} must be an array.')
    if len(value) > MAX_CAPABILITIES:
        raise OverlayValidationError(f'{label} can include at most {MAX_CAPABILITIES} entries.')
    cleaned: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        item_label = f'{label}[{index}]'
        if not isinstance(item, str) or not item or len(item) > 32 or item != item.strip() or _control_chars(item):
            raise OverlayValidationError(f'{item_label} must be a capability name.')
        if item == 'auth':
            raise OverlayValidationError(f'{item_label} "auth" is not allowed on a third-party app.')
        if item not in THIRD_PARTY_CAPABILITIES:
            raise OverlayValidationError(f'{item_label} "{item}" is not an allowed capability.')
        if item in seen:
            raise OverlayValidationError(f'{item_label} is a duplicate.')
        seen.add(item)
        cleaned.append(item)
    return cleaned


def _timestamp(value, *, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 40 or value != value.strip() or _control_chars(value):
        raise OverlayValidationError(f'{label} must be an ISO-8601 timestamp with a timezone.')
    parsed_text = value[:-1] + '+00:00' if value.endswith('Z') else value
    try:
        parsed = datetime.fromisoformat(parsed_text)
    except ValueError as exc:
        raise OverlayValidationError(f'{label} must be an ISO-8601 timestamp with a timezone.') from exc
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise OverlayValidationError(f'{label} must include a timezone.')
    return value


def _installed_app(value, *, index: int) -> dict:
    label = f'installedApps[{index}]'
    if not isinstance(value, dict):
        raise OverlayValidationError(f'{label} must be an object.')
    unknown = set(value) - APP_KEYS
    if unknown:
        name = sorted(unknown)[0]
        raise OverlayValidationError(f'{label} has unknown field "{name}".')
    missing = APP_REQUIRED_KEYS - set(value)
    if missing:
        name = sorted(missing)[0]
        raise OverlayValidationError(f'{label} is missing {name}.')

    app_id = value.get('id')
    if not isinstance(app_id, str) or not _ID_RE.fullmatch(app_id):
        raise OverlayValidationError(
            f'{label}.id must be 1 to {MAX_ID_LENGTH} characters (letters, digits, ".", "_", "-").'
        )
    name = value.get('name')
    if (
        not isinstance(name, str)
        or not name
        or name != name.strip()
        or len(name) > MAX_NAME_LENGTH
        or _control_chars(name)
        or _format_chars(name)
    ):
        raise OverlayValidationError(f'{label}.name must be 1 to {MAX_NAME_LENGTH} characters.')
    if value.get('thirdParty') is not True:
        raise OverlayValidationError(f'{label}.thirdParty must be true. Overlay apps are third-party only.')
    url = _https_url(value.get('url'), label=f'{label}.url')
    origin = _https_origin(value.get('origin'), url=url, label=f'{label}.origin')
    path = _navigation_token(value.get('path'), label=f'{label}.path', allow_reserved=False)
    capabilities = _capabilities(value.get('capabilities'), label=f'{label}.capabilities')
    cleaned = {
        'id': app_id,
        'name': name,
        'origin': origin,
        'url': url,
        'path': path,
        'thirdParty': True,
        'capabilities': capabilities,
        'installedAt': _timestamp(value.get('installedAt'), label=f'{label}.installedAt'),
        'updatedAt': _timestamp(value.get('updatedAt'), label=f'{label}.updatedAt'),
    }
    if 'icon' in value:
        cleaned['icon'] = _https_url(value.get('icon'), label=f'{label}.icon')
    return cleaned


def validate_navigation_overlay(data) -> dict:
    """Return a cleaned version-1 overlay document, or raise OverlayValidationError."""
    if not isinstance(data, dict):
        raise OverlayValidationError('Navigation overlay must be a JSON object.')
    unknown = set(data) - TOP_LEVEL_KEYS - SCOPING_KEYS
    if unknown:
        name = sorted(unknown)[0]
        raise OverlayValidationError(f'Unknown field "{name}".')
    missing = {'version', 'installedApps', 'order', 'hiddenPaths'} - set(data)
    if missing:
        name = sorted(missing)[0]
        raise OverlayValidationError(f'Missing field "{name}".')

    version = data.get('version')
    if type(version) is not int or version != OVERLAY_VERSION:
        raise OverlayValidationError('Unsupported navigation overlay version. Use version 1.')

    installed = data.get('installedApps')
    if not isinstance(installed, list):
        raise OverlayValidationError('installedApps must be an array.')
    if len(installed) > MAX_INSTALLED_APPS:
        raise OverlayValidationError(f'A navigation overlay can include at most {MAX_INSTALLED_APPS} installed apps.')

    apps: list[dict] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for index, item in enumerate(installed):
        app = _installed_app(item, index=index)
        if app['id'] in seen_ids:
            raise OverlayValidationError(f'installedApps[{index}].id is a duplicate.')
        path_key = app['path'].lower().strip('/')
        if path_key in seen_paths:
            raise OverlayValidationError(f'installedApps[{index}].path is a duplicate.')
        seen_ids.add(app['id'])
        seen_paths.add(path_key)
        apps.append(app)

    hidden = _string_list(
        data.get('hiddenPaths'), label='hiddenPaths', max_items=MAX_HIDDEN_PATHS, allow_reserved=False
    )
    document = {
        'version': OVERLAY_VERSION,
        'installedApps': apps,
        'order': _string_list(data.get('order'), label='order', max_items=MAX_ORDER_ENTRIES, allow_reserved=True),
        'hiddenPaths': hidden,
    }
    if 'updatedAt' in data:
        document['updatedAt'] = _timestamp(data.get('updatedAt'), label='updatedAt')
    return document


class InstalledAppSerializer(serializers.Serializer):
    id = serializers.CharField(max_length=MAX_ID_LENGTH)
    name = serializers.CharField(max_length=MAX_NAME_LENGTH)
    origin = serializers.CharField(max_length=MAX_ORIGIN_LENGTH)
    url = serializers.CharField(max_length=MAX_URL_LENGTH)
    path = serializers.CharField(max_length=MAX_PATH_LENGTH)
    icon = serializers.CharField(required=False, max_length=MAX_URL_LENGTH)
    thirdParty = serializers.BooleanField()
    capabilities = serializers.ListField(child=serializers.CharField(max_length=32))
    installedAt = serializers.CharField(max_length=40)
    updatedAt = serializers.CharField(max_length=40)


class NavigationOverlaySerializer(serializers.Serializer):
    """Request and response schema. ``to_internal_value`` applies the strict checker."""

    version = serializers.IntegerField()
    installedApps = InstalledAppSerializer(many=True)
    order = serializers.ListField(child=serializers.CharField(max_length=MAX_PATH_LENGTH))
    hiddenPaths = serializers.ListField(child=serializers.CharField(max_length=MAX_PATH_LENGTH))
    updatedAt = serializers.CharField(required=False, max_length=40)

    def to_internal_value(self, data):
        try:
            return validate_navigation_overlay(data)
        except OverlayValidationError as exc:
            raise serializers.ValidationError({'error': exc.message}) from exc


def _error_message(errors) -> str:
    if isinstance(errors, dict):
        for value in errors.values():
            return _error_message(value)
    if isinstance(errors, list):
        if not errors:
            return 'Invalid navigation overlay.'
        return _error_message(errors[0])
    return str(errors)


def _payload_too_large(request) -> bool:
    raw = request.body if request.body is not None else b''
    return len(raw) > MAX_PAYLOAD_BYTES


def _overlay_etag(row: UserNavigationOverlay) -> str:
    stamp = row.updated_at.astimezone(dt_timezone.utc).isoformat().replace('+00:00', 'Z')
    return f'"{stamp}"'


def _parse_if_match(header: str | None) -> list[str] | None:
    if header is None:
        return None
    text = header.strip()
    if not text:
        return []
    if text == '*':
        return ['*']
    values: list[str] = []
    for part in text.split(','):
        token = part.strip()
        if token.startswith('W/'):
            token = token[2:].strip()
        if len(token) >= 2 and token[0] == token[-1] == '"':
            token = token[1:-1]
        if token:
            values.append(token)
    return values


def _if_match_ok(header: str | None, row: UserNavigationOverlay | None) -> bool:
    tags = _parse_if_match(header)
    if row is None:
        # Creating needs no If-Match. `*` means "a document exists", so it fails here.
        return tags is None
    if tags is None:
        return False
    if tags == ['*']:
        return True
    current = _overlay_etag(row)[1:-1]
    return current in tags


def _document_for_row(row: UserNavigationOverlay | None) -> dict | None:
    if row is None:
        return None
    document = dict(row.document)
    document['updatedAt'] = row.updated_at.astimezone(dt_timezone.utc).isoformat().replace('+00:00', 'Z')
    return document


def _row_for(user, company, *, for_update: bool = False) -> UserNavigationOverlay | None:
    queryset = UserNavigationOverlay.objects.filter(user=user, company=company)
    if for_update:
        queryset = queryset.select_for_update()
    return queryset.first()


def _if_match_header(request) -> str | None:
    header = request.headers.get('If-Match')
    return header if header is not None else request.META.get('HTTP_IF_MATCH')


def _empty_if_match(request) -> Response | None:
    header = _if_match_header(request)
    if header is not None and not header.strip():
        return Response({'error': 'If-Match must not be empty.'}, status=status.HTTP_400_BAD_REQUEST)
    return None


def _precondition_failed(user, company):
    """412 with the current ETag, when a document exists, so a client can retry after a read.

    Clients must not rely on it: the row can change again before the retry.
    """
    response = Response(
        {'error': 'If-Match does not match the current navigation overlay.'},
        status=status.HTTP_412_PRECONDITION_FAILED,
    )
    row = _row_for(user, company)
    if row is not None:
        response['ETag'] = _overlay_etag(row)
    return response


def _replace_overlay_row(user, company, document: dict, header: str | None):
    """Create or replace the overlay if If-Match matches the current row version.

    The write is a conditional UPDATE on ``updated_at`` (the ETag version) so
    two requests that both passed a stale check cannot both commit.
    """
    now = timezone.now()
    stored = dict(document)
    stored['updatedAt'] = now.astimezone(dt_timezone.utc).isoformat().replace('+00:00', 'Z')
    with transaction.atomic():
        row = _row_for(user, company, for_update=True)
        if not _if_match_ok(header, row):
            return None
        if row is None:
            try:
                return UserNavigationOverlay.objects.create(
                    user=user, company=company, document=stored
                )
            except IntegrityError:
                return None
        # Conditional update on the current ETag timestamp, the row version.
        updated = UserNavigationOverlay.objects.filter(
            pk=row.pk,
            updated_at=row.updated_at,
        ).update(document=stored, updated_at=now)
        if updated != 1:
            return None
        row.refresh_from_db()
        return row


def _delete_overlay_row(user, company, header: str | None) -> tuple[bool, bool]:
    """Delete the overlay if If-Match matches. Returns (deleted, precondition_ok)."""
    with transaction.atomic():
        row = _row_for(user, company, for_update=True)
        if row is None:
            return False, True
        if not _if_match_ok(header, row):
            return False, False
        deleted, _ = UserNavigationOverlay.objects.filter(
            pk=row.pk,
            updated_at=row.updated_at,
        ).delete()
        if not deleted:
            return False, False
        return True, True


def _overlay_response(document, *, status_code: int, row: UserNavigationOverlay | None = None) -> Response:
    response = Response(document, status=status_code)
    if row is not None:
        response['ETag'] = _overlay_etag(row)
    return response


class NullableJSONRenderer(JSONRenderer):
    """Render a missing overlay as JSON null. DRF's renderer turns None into an empty body."""

    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = (renderer_context or {}).get('response')
        if data is None and response is not None and response.status_code == status.HTTP_200_OK:
            return b'null'
        return super().render(data, accepted_media_type, renderer_context)


def _company_for(request, user):
    from apps.authapi.views import _required_company_from_request

    return _required_company_from_request(request, user=user)


def _require_account(request):
    user = getattr(request, 'user', None)
    if user is None or not getattr(user, 'is_authenticated', False):
        return None, Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    return user, None


def _token_claim(request, key: str):
    token = getattr(request, 'auth', None)
    if token is None or not hasattr(token, 'get'):
        return None
    return token.get(key)


def _agent_or_pat_write_error(request, *, writing: bool) -> Response | None:
    if _token_claim(request, 'agent_id') is not None:
        return Response(
            {
                'error': 'Agent tokens cannot change the navigation overlay.',
                'error_code': 'agent_cannot_edit_navigation',
            },
            status=status.HTTP_403_FORBIDDEN,
        )
    if writing and _token_claim(request, 'pat_id') is not None:
        return Response(
            {
                'error': 'Personal access tokens cannot change the navigation overlay.',
                'error_code': 'pat_cannot_edit_navigation',
            },
            status=status.HTTP_403_FORBIDDEN,
        )
    return None


def _cross_user_response(request, user) -> Response | None:
    raw = request.GET.get('user_id')
    if raw in (None, '') and request.method == 'PUT' and isinstance(getattr(request, 'data', None), dict):
        raw = request.data.get('user_id')
        if raw in (None, ''):
            raw = request.data.get('userId')
    if raw in (None, ''):
        return None
    if isinstance(raw, bool):
        return Response({'error': 'user_id must be the authenticated user.'}, status=status.HTTP_403_FORBIDDEN)
    try:
        requested = int(raw)
    except (TypeError, ValueError):
        return Response({'error': 'user_id must be the authenticated user.'}, status=status.HTTP_403_FORBIDDEN)
    if requested != user.pk:
        return Response({'error': 'user_id must be the authenticated user.'}, status=status.HTTP_403_FORBIDDEN)
    return None


_PRECONDITION_FAILED_DESCRIPTION = (
    'If-Match is missing or does not match the current ETag. The response carries the '
    'current ETag header when a document exists. Clients should still read the document '
    'before they retry.'
)

_ETAG_RESPONSE_HEADER = OpenApiParameter(
    name='ETag',
    type=str,
    location=OpenApiParameter.HEADER,
    response=[200, 412],
    description='Current version of the saved document, for If-Match on the next write.',
)

_COMPANY_ID_PARAMETER = OpenApiParameter(
    name='company_id',
    type=int,
    location=OpenApiParameter.QUERY,
    required=False,
    description='Must match the bearer token company_id when provided.',
)


def _emit_overlay_event(event_id: str, company, user, *, source: str, app_ids: list[str] | None = None) -> None:
    payload = {'user_id': user.pk, 'source': source, 'email': getattr(user, 'email', '') or ''}
    if app_ids is not None:
        payload['app_ids'] = app_ids
    emit_event_if_rules(event_id, company, payload)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-navigation'],
        operation_id='api_v1_navigation_overlay_retrieve',
        summary='Get the current user navigation overlay',
        description=(
            'Return the Shellui navigation overlay saved for the authenticated user and '
            'the token company. The response is JSON null when no document is saved for '
            'that pair. Each company the user belongs to has its own document. Agents '
            'cannot read or write this resource. A user_id that is not the authenticated '
            'user is rejected. Successful responses include an ETag derived from the row '
            'timestamp, for use with If-Match on later writes.'
        ),
        parameters=[_COMPANY_ID_PARAMETER],
        responses={
            200: OpenApiResponse(
                response=NavigationOverlaySerializer,
                description='Saved overlay document, or JSON null when none is saved',
            ),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
            403: OpenApiResponse(description='Company mismatch, disabled membership, agent token, or a user id for someone else'),
            404: OpenApiResponse(description='Unknown company'),
        },
    ),
    put=extend_schema(
        tags=['auth-navigation'],
        operation_id='api_v1_navigation_overlay_update',
        summary='Save the current user navigation overlay',
        description=(
            'Validate and replace the navigation overlay for the authenticated user and '
            'the token company. Version must be 1. Every installed app is third-party: '
            'firstParty is rejected, thirdParty must be true, and the auth capability is '
            'never accepted. Each app must include origin, url, path, installedAt, and '
            'updatedAt. URLs must be https and must not use a loopback or private host. '
            'Apps may not claim or hide reserved core paths. The raw body must be 64 KB '
            'or smaller, and installedApps can hold at most 100 entries. When a document '
            'already exists, If-Match must equal the current ETag (or *). Document '
            'updatedAt is set by the server.'
        ),
        parameters=[_COMPANY_ID_PARAMETER, _ETAG_RESPONSE_HEADER],
        request=NavigationOverlaySerializer,
        responses={
            200: OpenApiResponse(response=NavigationOverlaySerializer, description='Saved overlay document'),
            400: OpenApiResponse(description='Invalid overlay'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
            403: OpenApiResponse(
                description='Company mismatch, disabled membership, agent or personal access token, or a user id for someone else'
            ),
            404: OpenApiResponse(description='Unknown company'),
            412: OpenApiResponse(description=_PRECONDITION_FAILED_DESCRIPTION),
            413: OpenApiResponse(description='Payload is larger than 64 KB'),
            429: OpenApiResponse(description='Write rate limit exceeded'),
        },
    ),
    delete=extend_schema(
        tags=['auth-navigation'],
        operation_id='api_v1_navigation_overlay_destroy',
        summary='Delete the current user navigation overlay',
        description=(
            'Delete the navigation overlay saved for the authenticated user and the token '
            'company. When a document exists, If-Match must equal the current ETag (or *).'
        ),
        parameters=[_COMPANY_ID_PARAMETER, _ETAG_RESPONSE_HEADER],
        responses={
            204: OpenApiResponse(description='Overlay deleted, or no document was saved'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
            403: OpenApiResponse(
                description='Company mismatch, disabled membership, agent or personal access token, or a user id for someone else'
            ),
            404: OpenApiResponse(description='Unknown company'),
            412: OpenApiResponse(description=_PRECONDITION_FAILED_DESCRIPTION),
            429: OpenApiResponse(description='Write rate limit exceeded'),
        },
    ),
)
class ShellUINavigationOverlayView(APIView):
    permission_classes = [ShellUIPermission]
    renderer_classes = [NullableJSONRenderer]
    serializer_class = NavigationOverlaySerializer

    def get(self, request):
        user, err = _require_account(request)
        if err:
            return err
        agent_err = _agent_or_pat_write_error(request, writing=False)
        if agent_err:
            return agent_err
        company, company_err = _company_for(request, user)
        if company_err:
            return company_err
        cross_user = _cross_user_response(request, user)
        if cross_user:
            return cross_user
        row = _row_for(user, company)
        return _overlay_response(_document_for_row(row), status_code=status.HTTP_200_OK, row=row)

    def put(self, request):
        user, err = _require_account(request)
        if err:
            return err
        write_err = _agent_or_pat_write_error(request, writing=True)
        if write_err:
            return write_err
        limited = check_rate_limit(request, scope='navigation_overlay_write', identity=f'user:{user.pk}')
        if limited:
            return limited
        if _payload_too_large(request):
            return Response(
                {'error': 'Navigation overlay payload exceeds 64 KB.'},
                status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )
        company, company_err = _company_for(request, user)
        if company_err:
            return company_err
        cross_user = _cross_user_response(request, user)
        if cross_user:
            return cross_user
        empty = _empty_if_match(request)
        if empty:
            return empty
        serializer = NavigationOverlaySerializer(data=request.data)
        if not serializer.is_valid():
            return Response({'error': _error_message(serializer.errors)}, status=status.HTTP_400_BAD_REQUEST)
        row = _replace_overlay_row(
            user, company, serializer.validated_data, _if_match_header(request)
        )
        if row is None:
            return _precondition_failed(user, company)
        stored = _document_for_row(row)
        _emit_overlay_event(
            'identity.navigation_overlay.updated',
            company,
            user,
            source='api',
            app_ids=[app['id'] for app in stored.get('installedApps', [])] if stored else [],
        )
        return _overlay_response(stored, status_code=status.HTTP_200_OK, row=row)

    def delete(self, request):
        user, err = _require_account(request)
        if err:
            return err
        write_err = _agent_or_pat_write_error(request, writing=True)
        if write_err:
            return write_err
        limited = check_rate_limit(request, scope='navigation_overlay_write', identity=f'user:{user.pk}')
        if limited:
            return limited
        company, company_err = _company_for(request, user)
        if company_err:
            return company_err
        cross_user = _cross_user_response(request, user)
        if cross_user:
            return cross_user
        empty = _empty_if_match(request)
        if empty:
            return empty
        deleted, precondition_ok = _delete_overlay_row(user, company, _if_match_header(request))
        if not precondition_ok:
            return _precondition_failed(user, company)
        if deleted:
            _emit_overlay_event('identity.navigation_overlay.deleted', company, user, source='api')
        return Response(status=status.HTTP_204_NO_CONTENT)


__all__ = [
    'MAX_INSTALLED_APPS',
    'MAX_PAYLOAD_BYTES',
    'OverlayValidationError',
    'RESERVED_PATH_SEGMENTS',
    'ShellUINavigationOverlayView',
    'validate_navigation_overlay',
]
