"""Company admin REST API for the event log (``/api/v1/events``) and the legacy ``/api/v1/login-events``."""

from __future__ import annotations

from django.db.models import F, Q, QuerySet
from django.utils.dateparse import parse_datetime
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.actions.models import EventLog
from apps.actions.registry import all_event_types, get_event_type, is_registered_event
from apps.actions.retention import retention_status
from apps.authapi.login_audit import LOGIN_EVENT_TYPES
from apps.authapi.models import UserPreference
from apps.authapi.permissions import ShellUIPermission
from apps.authapi.serializers import ShellUIOpenAPISerializer
from apps.authapi.views import _require_staff_or_company_owner

_MAX_PAGE_SIZE = 100
_LOGIN_TYPES = tuple(LOGIN_EVENT_TYPES.values())
_OUTCOME_BY_TYPE = {event_type: outcome for outcome, event_type in LOGIN_EVENT_TYPES.items()}


def _bad_request(message: str) -> Response:
    return Response({'error': message}, status=status.HTTP_400_BAD_REQUEST)


def _company_events(company) -> QuerySet:
    return EventLog.objects.filter(company=company).annotate(user_email=F('user__email'))


def _parse_page(request) -> tuple[int, int] | None:
    try:
        page = max(1, int(request.GET.get('page') or 1))
        page_size = min(_MAX_PAGE_SIZE, max(1, int(request.GET.get('page_size') or 20)))
    except (TypeError, ValueError):
        return None
    return page, page_size


def _filter_common(request, qs: QuerySet) -> tuple[QuerySet, Response | None]:
    """``user_id``, ``created_after`` (inclusive) and ``created_before`` (exclusive)."""
    uid = (request.GET.get('user_id') or '').strip()
    if uid:
        try:
            qs = qs.filter(user_id=int(uid))
        except ValueError:
            return qs, _bad_request('Invalid user_id.')
    for param, lookup in (('created_after', 'created_at__gte'), ('created_before', 'created_at__lt')):
        raw = (request.GET.get(param) or '').strip()
        if raw:
            dt = parse_datetime(raw)
            if dt is None:
                return qs, _bad_request(f'Invalid {param}.')
            qs = qs.filter(**{lookup: dt})
    return qs, None


def _paginated(qs: QuerySet, page: int, page_size: int, row_payload) -> Response:
    total = qs.count()
    start = (page - 1) * page_size
    return Response(
        {
            'count': total,
            'page': page,
            'page_size': page_size,
            'results': [row_payload(row) for row in qs[start : start + page_size]],
        }
    )


def _event_label(event_type: str) -> str:
    return get_event_type(event_type).label if is_registered_event(event_type) else event_type


def _event_payload(row: EventLog) -> dict:
    data = row.data or {}
    return {
        'id': row.id,
        'company_id': row.company_id,
        'created_at': row.created_at,
        'event_type': row.event_type,
        'label': _event_label(row.event_type),
        'user_id': row.user_id,
        'user_email': row.user_email or data.get('email'),
        'data': data,
    }


_DATE_PARAMS = [
    OpenApiParameter(
        name='created_after',
        type=str,
        location=OpenApiParameter.QUERY,
        required=False,
        description='ISO 8601 datetime (inclusive lower bound).',
    ),
    OpenApiParameter(
        name='created_before',
        type=str,
        location=OpenApiParameter.QUERY,
        required=False,
        description='ISO 8601 datetime (exclusive upper bound).',
    ),
]
_PAGE_PARAMS = [
    OpenApiParameter(name='page', type=int, location=OpenApiParameter.QUERY, required=False),
    OpenApiParameter(name='page_size', type=int, location=OpenApiParameter.QUERY, required=False),
]
_USER_ID_PARAM = OpenApiParameter(
    name='user_id',
    type=int,
    location=OpenApiParameter.QUERY,
    required=False,
    description='Filter by user id.',
)


@extend_schema_view(
    get=extend_schema(
        tags=['audit-events'],
        summary='List event log (staff or company owner)',
        description=(
            'Every catalog event recorded for the company (webhook events and sign-ins), newest first. '
            'Rows are kept for the company data retention (`GET /api/v1/events/retention`).'
        ),
        operation_id='api_v1_events_list',
        parameters=[
            _USER_ID_PARAM,
            OpenApiParameter(
                name='user',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Case-insensitive substring of the user email (also matches `data.email`).',
            ),
            OpenApiParameter(
                name='event_type',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Catalog event type; comma-separate several types.',
            ),
            *_DATE_PARAMS,
            *_PAGE_PARAMS,
        ],
        responses={200: OpenApiResponse(description='Paginated event log rows')},
    ),
)
class ShellUIAdminEventListView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        paging = _parse_page(request)
        if paging is None:
            return _bad_request('Invalid page or page_size.')
        qs, err = _filter_common(request, _company_events(company))
        if err:
            return err

        email = (request.GET.get('user') or '').strip()
        if email:
            qs = qs.filter(Q(user__email__icontains=email) | Q(data__email__icontains=email))

        types = [t.strip() for t in (request.GET.get('event_type') or '').split(',') if t.strip()]
        if types:
            if not all(is_registered_event(t) for t in types):
                return _bad_request('Invalid event_type.')
            qs = qs.filter(event_type__in=types)

        return _paginated(qs, *paging, _event_payload)


@extend_schema_view(
    get=extend_schema(
        tags=['audit-events'],
        summary='Retrieve event log row (staff or company owner)',
        operation_id='api_v1_events_retrieve',
        responses={200: OpenApiResponse(description='Event log row')},
    ),
)
class ShellUIAdminEventDetailView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        row = _company_events(company).filter(pk=pk).first()
        if row is None:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_event_payload(row))


@extend_schema_view(
    get=extend_schema(
        tags=['audit-events'],
        summary='List event types recorded in the event log (staff or company owner)',
        description='`webhook=false` types (sign-ins) are logged but cannot trigger webhook rules.',
        operation_id='api_v1_events_types_list',
    ),
)
class ShellUIAdminEventTypesView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        _actor, _company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        return Response(
            {
                'results': [
                    {'type': e.id, 'label': e.label, 'description': e.description, 'webhook': e.webhook}
                    for e in all_event_types()
                    if e.emit_by_default
                ]
            }
        )


@extend_schema_view(
    get=extend_schema(
        tags=['audit-events'],
        summary='Event log retention status (staff or company owner)',
        description=(
            '`data_retention_days` is set by Shellui operators in Django admin. `stale_events` is true '
            'when the oldest event is more than one day past retention, which means the '
            '`purge_expired_data` scheduled job is not running.'
        ),
        operation_id='api_v1_events_retention_retrieve',
    ),
)
class ShellUIAdminEventRetentionView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        return Response(retention_status(company))


def _login_event_payload(row: EventLog) -> dict:
    data = row.data or {}
    return {
        'id': row.id,
        'company_id': row.company_id,
        'created_at': row.created_at,
        'user_id': row.user_id,
        'user_email': row.user_email,
        'outcome': _OUTCOME_BY_TYPE[row.event_type],
        'provider': data.get('provider', ''),
        'failure_reason': data.get('failure_reason', ''),
        'is_staff_at_event': bool(data.get('is_staff_at_event')),
        'ip_hash': data.get('ip_hash', ''),
        'user_agent': data.get('user_agent', ''),
        'client_timezone': data.get('client_timezone', ''),
        'client_device_id_hash': data.get('client_device_id_hash', ''),
        'client_country': data.get('client_country', ''),
        'client_city': data.get('client_city', ''),
    }


def _company_login_events(company) -> QuerySet:
    return _company_events(company).filter(event_type__in=_LOGIN_TYPES)


@extend_schema_view(
    get=extend_schema(
        tags=['audit-events'],
        summary='List sign-in events (deprecated, staff or company owner)',
        description=(
            'Deprecated: use `GET /api/v1/events?event_type=identity.auth.login.succeeded,'
            'identity.auth.login.failed`. Same rows as the event log, in the former login audit shape.'
        ),
        operation_id='api_v1_login_events_list',
        deprecated=True,
        parameters=[
            _USER_ID_PARAM,
            OpenApiParameter(name='outcome', type=str, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='provider', type=str, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='is_staff_at_event', type=bool, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='client_country', type=str, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='client_city', type=str, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='client_timezone', type=str, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='language', type=str, location=OpenApiParameter.QUERY, required=False),
            *_DATE_PARAMS,
            *_PAGE_PARAMS,
        ],
        responses={200: OpenApiResponse(description='Paginated sign-in events')},
    ),
)
class ShellUIAdminLoginEventListView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        paging = _parse_page(request)
        if paging is None:
            return _bad_request('Invalid page or page_size.')
        qs, err = _filter_common(request, _company_login_events(company))
        if err:
            return err

        outcome = (request.GET.get('outcome') or '').strip().lower()
        if outcome:
            if outcome not in LOGIN_EVENT_TYPES:
                return _bad_request('Invalid outcome.')
            qs = qs.filter(event_type=LOGIN_EVENT_TYPES[outcome])

        provider = (request.GET.get('provider') or '').strip().lower()
        if provider:
            qs = qs.filter(data__provider=provider)

        staff = (request.GET.get('is_staff_at_event') or '').strip().lower()
        if staff in ('1', 'true', 'yes'):
            qs = qs.filter(data__is_staff_at_event=True)
        elif staff in ('0', 'false', 'no'):
            qs = qs.exclude(data__is_staff_at_event=True)
        elif staff:
            return _bad_request('Invalid is_staff_at_event (use true or false).')

        for param in ('client_country', 'client_city', 'client_timezone'):
            value = (request.GET.get(param) or '').strip()
            if value:
                qs = qs.filter(**{f'data__{param}__icontains': value})

        lang = (request.GET.get('language') or '').strip().lower()
        if lang:
            if lang not in {choice[0] for choice in UserPreference.LANGUAGE_CHOICES}:
                return _bad_request('Invalid language.')
            qs = qs.filter(user__preference__language=lang)

        return _paginated(qs, *paging, _login_event_payload)


@extend_schema_view(
    get=extend_schema(
        tags=['audit-events'],
        summary='Retrieve sign-in event (deprecated, staff or company owner)',
        description='Deprecated: use `GET /api/v1/events/<id>`.',
        operation_id='api_v1_login_events_retrieve',
        deprecated=True,
        responses={200: OpenApiResponse(description='Sign-in event')},
    ),
)
class ShellUIAdminLoginEventDetailView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        row = _company_login_events(company).filter(pk=pk).first()
        if row is None:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_login_event_payload(row))
