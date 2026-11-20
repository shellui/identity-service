"""Per-user Shellui navigation overlay sync (schema version 1).

The document is stored once per account, same as ``UserPreference``. The
endpoint still requires a bearer token for a company the account belongs to.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from urllib.parse import urlsplit

from django.contrib.auth.models import AbstractBaseUser
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import serializers, status
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.authapi.models import UserNavigationOverlay
from apps.authapi.permissions import ShellUIPermission
from apps.companies.models import Company

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

# Third-party entries may use only this set. ``auth`` is rejected for them.
THIRD_PARTY_CAPABILITIES = frozenset({'theme', 'locale', 'ui', 'navigate', 'storage', 'ai'})
FIRST_PARTY_CAPABILITIES = THIRD_PARTY_CAPABILITIES | {'auth'}

TOP_LEVEL_KEYS = frozenset({'version', 'installedApps', 'order', 'hiddenPaths', 'updatedAt'})
APP_REQUIRED_KEYS = frozenset({'id', 'name', 'url', 'capabilities'})
APP_OPTIONAL_KEYS = frozenset({'firstParty', 'path', 'iconUrl'})
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


def _same_account(raw, user: AbstractBaseUser) -> bool:
    if isinstance(raw, bool) or raw is None:
        return False
    if isinstance(raw, int):
        return raw == user.pk
    if isinstance(raw, str):
        text = raw.strip()
        return bool(text) and text.isdigit() and int(text) == user.pk
    return False


def _https_url(value, *, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
        raise OverlayValidationError(f'{label} must be an https URL of at most {MAX_URL_LENGTH} characters.')
    if value != value.strip() or _control_chars(value) or '\\' in value or any(ch.isspace() for ch in value):
        raise OverlayValidationError(f'{label} must be an https URL.')
    parts = urlsplit(value)
    if parts.scheme.lower() != 'https':
        raise OverlayValidationError(f'{label} must use https.')
    if parts.username is not None or parts.password is not None:
        raise OverlayValidationError(f'{label} must not include a username or password.')
    try:
        host = parts.hostname
    except ValueError as exc:
        raise OverlayValidationError(f'{label} must include a host.') from exc
    if not host:
        raise OverlayValidationError(f'{label} must include a host.')
    try:
        host.encode('idna')
    except UnicodeError as exc:
        raise OverlayValidationError(f'{label} has an invalid host.') from exc
    try:
        port = parts.port
    except ValueError as exc:
        raise OverlayValidationError(f'{label} has an invalid port.') from exc
    if port == 0:
        raise OverlayValidationError(f'{label} has an invalid port.')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host) or (
            host != 'localhost' and not _HOST_RE.fullmatch(host)
        ):
            raise OverlayValidationError(f'{label} has an invalid host.')
    return value


def _navigation_token(value, *, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_LENGTH or value != value.strip():
        raise OverlayValidationError(f'{label} must be a path or id of at most {MAX_PATH_LENGTH} characters.')
    if _control_chars(value) or not _PATH_RE.fullmatch(value):
        raise OverlayValidationError(
            f'{label} must be a navigation path or id (letters, digits, ".", "_", "-", and "/").'
        )
    return value


def _string_list(value, *, label: str, max_items: int) -> list[str]:
    if not isinstance(value, list):
        raise OverlayValidationError(f'{label} must be an array.')
    if len(value) > max_items:
        raise OverlayValidationError(f'{label} can include at most {max_items} entries.')
    cleaned: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        token = _navigation_token(item, label=f'{label}[{index}]')
        if token in seen:
            raise OverlayValidationError(f'{label}[{index}] is a duplicate.')
        seen.add(token)
        cleaned.append(token)
    return cleaned


def _capabilities(value, *, first_party: bool, label: str) -> list[str]:
    if not isinstance(value, list):
        raise OverlayValidationError(f'{label} must be an array.')
    if len(value) > MAX_CAPABILITIES:
        raise OverlayValidationError(f'{label} can include at most {MAX_CAPABILITIES} entries.')
    allowed = FIRST_PARTY_CAPABILITIES if first_party else THIRD_PARTY_CAPABILITIES
    cleaned: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        item_label = f'{label}[{index}]'
        if not isinstance(item, str) or not item or len(item) > 32 or item != item.strip() or _control_chars(item):
            raise OverlayValidationError(f'{item_label} must be a capability name.')
        if item == 'auth' and not first_party:
            raise OverlayValidationError(f'{item_label} "auth" is not allowed on a third-party app.')
        if item not in allowed:
            raise OverlayValidationError(f'{item_label} "{item}" is not an allowed capability.')
        if item in seen:
            raise OverlayValidationError(f'{item_label} is a duplicate.')
        seen.add(item)
        cleaned.append(item)
    return cleaned


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
    ):
        raise OverlayValidationError(f'{label}.name must be 1 to {MAX_NAME_LENGTH} characters.')
    url = _https_url(value.get('url'), label=f'{label}.url')
    first_party = False
    if 'firstParty' in value:
        if not isinstance(value['firstParty'], bool):
            raise OverlayValidationError(f'{label}.firstParty must be true or false.')
        first_party = value['firstParty']
    capabilities = _capabilities(value.get('capabilities'), first_party=first_party, label=f'{label}.capabilities')

    cleaned = {
        'id': app_id,
        'name': name,
        'url': url,
        'capabilities': capabilities,
    }
    if 'firstParty' in value:
        cleaned['firstParty'] = first_party
    if 'path' in value:
        cleaned['path'] = _navigation_token(value.get('path'), label=f'{label}.path')
    if 'iconUrl' in value:
        cleaned['iconUrl'] = _https_url(value.get('iconUrl'), label=f'{label}.iconUrl')
    return cleaned


def _updated_at(value) -> str:
    if not isinstance(value, str) or not value or len(value) > 40 or value != value.strip() or _control_chars(value):
        raise OverlayValidationError('updatedAt must be an ISO-8601 timestamp with a timezone.')
    parsed_text = value[:-1] + '+00:00' if value.endswith('Z') else value
    try:
        parsed = datetime.fromisoformat(parsed_text)
    except ValueError as exc:
        raise OverlayValidationError('updatedAt must be an ISO-8601 timestamp with a timezone.') from exc
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise OverlayValidationError('updatedAt must include a timezone.')
    return value


def validate_navigation_overlay(data) -> dict:
    """Return a cleaned version-1 overlay document, or raise OverlayValidationError."""
    if not isinstance(data, dict):
        raise OverlayValidationError('Navigation overlay must be a JSON object.')
    unknown = set(data) - TOP_LEVEL_KEYS - SCOPING_KEYS
    if unknown:
        name = sorted(unknown)[0]
        raise OverlayValidationError(f'Unknown field "{name}".')
    missing = TOP_LEVEL_KEYS - set(data)
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
    for index, item in enumerate(installed):
        app = _installed_app(item, index=index)
        if app['id'] in seen_ids:
            raise OverlayValidationError(f'installedApps[{index}].id is a duplicate.')
        seen_ids.add(app['id'])
        apps.append(app)

    return {
        'version': OVERLAY_VERSION,
        'installedApps': apps,
        'order': _string_list(data.get('order'), label='order', max_items=MAX_ORDER_ENTRIES),
        'hiddenPaths': _string_list(data.get('hiddenPaths'), label='hiddenPaths', max_items=MAX_HIDDEN_PATHS),
        'updatedAt': _updated_at(data.get('updatedAt')),
    }


class InstalledAppSerializer(serializers.Serializer):
    id = serializers.CharField(max_length=MAX_ID_LENGTH)
    name = serializers.CharField(max_length=MAX_NAME_LENGTH)
    url = serializers.CharField(max_length=MAX_URL_LENGTH)
    capabilities = serializers.ListField(child=serializers.CharField(max_length=32))
    firstParty = serializers.BooleanField(required=False)
    path = serializers.CharField(required=False, max_length=MAX_PATH_LENGTH)
    iconUrl = serializers.CharField(required=False, max_length=MAX_URL_LENGTH)


class NavigationOverlaySerializer(serializers.Serializer):
    """Request schema. ``to_internal_value`` applies the strict checker."""

    version = serializers.IntegerField()
    installedApps = InstalledAppSerializer(many=True)
    order = serializers.ListField(child=serializers.CharField(max_length=MAX_PATH_LENGTH))
    hiddenPaths = serializers.ListField(child=serializers.CharField(max_length=MAX_PATH_LENGTH))
    updatedAt = serializers.CharField(max_length=40)

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


def _token_company_id(request) -> int | None:
    token = getattr(request, 'auth', None)
    if token is None or not hasattr(token, 'get'):
        return None
    raw = token.get('company_id')
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _company_for_request(request, user) -> tuple[Company | None, Response | None]:
    """Resolve company the way ``/api/v1/preferences`` does: query, PUT body, then token."""
    raw_candidate = request.GET.get('company_id')
    if raw_candidate in (None, '') and request.method == 'PUT':
        body = request.data
        if isinstance(body, dict):
            raw_candidate = body.get('company_id')
    raw = str(raw_candidate).strip() if raw_candidate not in (None, '') else ''
    token_company_id = _token_company_id(request)

    company_id: int | None = None
    if raw:
        try:
            company_id = int(raw)
        except (TypeError, ValueError):
            return None, Response({'error': 'Invalid company_id parameter.'}, status=status.HTTP_400_BAD_REQUEST)
    elif token_company_id is not None:
        company_id = token_company_id
    else:
        return None, Response({'error': 'Missing company_id parameter.'}, status=status.HTTP_400_BAD_REQUEST)

    if raw and token_company_id is not None and token_company_id != company_id:
        return None, Response(
            {'error': 'Requested company_id does not match token company_id.'},
            status=status.HTTP_403_FORBIDDEN,
        )

    try:
        company = Company.objects.get(pk=company_id)
    except Company.DoesNotExist:
        return None, Response({'error': 'Company not found.'}, status=status.HTTP_404_NOT_FOUND)

    if not company.members.filter(pk=user.pk).exists():
        return None, Response({'error': 'Forbidden for this company.'}, status=status.HTTP_403_FORBIDDEN)
    return company, None


def _payload_too_large(request) -> bool:
    raw_length = request.META.get('CONTENT_LENGTH')
    if raw_length not in (None, ''):
        try:
            if int(raw_length) > MAX_PAYLOAD_BYTES:
                return True
        except (TypeError, ValueError):
            return True
    body = request.body or b''
    return len(body) > MAX_PAYLOAD_BYTES


def _cross_user_response(request, user) -> Response | None:
    """Reject a user id that is not the authenticated account. Matching ids are ignored."""
    candidates = [request.GET.get('user_id'), request.GET.get('userId')]
    if request.method == 'PUT' and isinstance(request.data, dict):
        for key in ('user_id', 'userId', 'user'):
            if key in request.data:
                candidates.append(request.data.get(key))
    for raw in candidates:
        if raw in (None, ''):
            continue
        if not _same_account(raw, user):
            return Response({'error': 'Forbidden.'}, status=status.HTTP_403_FORBIDDEN)
    return None


def _document_for_user(user) -> dict | None:
    row = UserNavigationOverlay.objects.filter(user=user).only('document').first()
    if row is None:
        return None
    document = row.document
    return document if isinstance(document, dict) else None


class NullableJSONRenderer(JSONRenderer):
    """Render a missing overlay as JSON null. DRF's renderer turns None into an empty body."""

    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = (renderer_context or {}).get('response')
        if data is None and response is not None and response.status_code == status.HTTP_200_OK:
            return b'null'
        return super().render(data, accepted_media_type, renderer_context)


def _require_account(request):
    user = getattr(request, 'user', None)
    if user is None or not getattr(user, 'is_authenticated', False):
        return None, Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    return user, None


@extend_schema_view(
    get=extend_schema(
        tags=['auth-navigation'],
        operation_id='api_v1_navigation_overlay_retrieve',
        summary='Get the current user navigation overlay',
        description=(
            'Return the Shellui navigation overlay saved for the authenticated user. '
            'The response is JSON null when that user has not saved one. '
            'The document is per user, not per company. The token company_id must be a '
            'company the user belongs to. A user_id that is not the authenticated user is rejected.'
        ),
        responses={
            200: OpenApiResponse(description='Saved overlay document, or JSON null when none is saved'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
            403: OpenApiResponse(description='Company mismatch, or a user id for someone else'),
        },
    ),
    put=extend_schema(
        tags=['auth-navigation'],
        operation_id='api_v1_navigation_overlay_update',
        summary='Save the current user navigation overlay',
        description=(
            'Validate and replace the authenticated user navigation overlay. '
            'Version must be 1. installedApps, order, and hiddenPaths must be arrays. '
            'Each installed app url must be https. Third-party apps may list only the '
            'capabilities theme, locale, ui, navigate, storage, and ai. The auth capability '
            'and any other name are rejected on third-party entries. The raw body must be '
            '64 KB or smaller, and installedApps can hold at most 100 entries.'
        ),
        request=NavigationOverlaySerializer,
        responses={
            200: OpenApiResponse(description='Saved overlay document'),
            400: OpenApiResponse(description='Invalid overlay, or a payload over 64 KB'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
            403: OpenApiResponse(description='Company mismatch, read-only token, or a user id for someone else'),
        },
    ),
    delete=extend_schema(
        tags=['auth-navigation'],
        operation_id='api_v1_navigation_overlay_destroy',
        summary='Delete the current user navigation overlay',
        description='Delete the navigation overlay saved for the authenticated user.',
        responses={
            204: OpenApiResponse(description='Overlay deleted'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
            403: OpenApiResponse(description='Company mismatch, read-only token, or a user id for someone else'),
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
        _company, company_err = _company_for_request(request, user)
        if company_err:
            return company_err
        cross_user = _cross_user_response(request, user)
        if cross_user:
            return cross_user
        return Response(_document_for_user(user), status=status.HTTP_200_OK)

    def put(self, request):
        user, err = _require_account(request)
        if err:
            return err
        if _payload_too_large(request):
            return Response(
                {'error': 'Navigation overlay payload exceeds 64 KB.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        _company, company_err = _company_for_request(request, user)
        if company_err:
            return company_err
        cross_user = _cross_user_response(request, user)
        if cross_user:
            return cross_user

        serializer = NavigationOverlaySerializer(data=request.data)
        if not serializer.is_valid():
            return Response({'error': _error_message(serializer.errors)}, status=status.HTTP_400_BAD_REQUEST)
        document = serializer.validated_data
        UserNavigationOverlay.objects.update_or_create(user=user, defaults={'document': document})
        return Response(document, status=status.HTTP_200_OK)

    def delete(self, request):
        user, err = _require_account(request)
        if err:
            return err
        _company, company_err = _company_for_request(request, user)
        if company_err:
            return company_err
        cross_user = _cross_user_response(request, user)
        if cross_user:
            return cross_user
        UserNavigationOverlay.objects.filter(user=user).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
