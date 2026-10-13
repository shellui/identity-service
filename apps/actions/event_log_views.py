"""Company admin REST API for the event log (``/api/v1/events``)."""

from __future__ import annotations

from django.db.models import F, Q, QuerySet
from django.utils.dateparse import parse_datetime
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.actions.models import EventLog
from apps.actions.registry import (
    company_event_types,
    get_event_type,
    is_registered_event,
    staff_only_event_types,
)
from apps.actions.retention import retention_status
from apps.authapi.permissions import ShellUIPermission
from apps.authapi.serializers import ShellUIOpenAPISerializer
from apps.authapi.views import _require_staff_or_company_owner

_MAX_PAGE_SIZE = 100


def _bad_request(message: str) -> Response:
    return Response({'error': message}, status=status.HTTP_400_BAD_REQUEST)


def _company_events(company) -> QuerySet:
    return EventLog.objects.filter(company=company).annotate(user_email=F('user__email'))


def _platform_events() -> QuerySet:
    """Staff-only platform events (scheduled job runs). They never have a company."""
    types = [e.id for e in staff_only_event_types()]
    return EventLog.objects.filter(company__isnull=True, event_type__in=types).annotate(
        user_email=F('user__email')
    )


def _scoped_events(request, actor, company) -> tuple[QuerySet | None, Response | None]:
    """``scope=company`` (default) or ``scope=platform`` (Django staff only)."""
    scope = (request.GET.get('scope') or 'company').strip().lower()
    if scope == 'company':
        return _company_events(company), None
    if scope == 'platform':
        if not getattr(actor, 'is_staff', False):
            return None, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        return _platform_events(), None
    return None, _bad_request('Invalid scope.')


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
_SCOPE_PARAM = OpenApiParameter(
    name='scope',
    type=str,
    location=OpenApiParameter.QUERY,
    required=False,
    enum=['company', 'platform'],
    description=(
        '`company` (default): events of the company in the token. `platform`: staff-only platform '
        'events without a company (`identity.scheduled_job.succeeded`, `identity.scheduled_job.failed`). '
        'Non-staff callers get 403.'
    ),
)
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
            _SCOPE_PARAM,
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
        actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        paging = _parse_page(request)
        if paging is None:
            return _bad_request('Invalid page or page_size.')
        base, err = _scoped_events(request, actor, company)
        if err:
            return err
        qs, err = _filter_common(request, base)
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
        parameters=[_SCOPE_PARAM],
        responses={200: OpenApiResponse(description='Event log row')},
    ),
)
class ShellUIAdminEventDetailView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request, pk):
        actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        base, err = _scoped_events(request, actor, company)
        if err:
            return err
        row = base.filter(pk=pk).first()
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
                    for e in company_event_types()
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

