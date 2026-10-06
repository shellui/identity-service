"""Company audience for email broadcasts: users matching filters, with their language."""

from __future__ import annotations

from datetime import UTC, datetime, time

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.companies.group_graph import effective_user_ids_for_group
from apps.companies.models import CompanyGroup

from .permissions import ShellUIPermission
from .serializers import ShellUIOpenAPISerializer
from .views import _require_staff_or_company_owner

User = get_user_model()

ROLES = {'owner', 'staff', 'member'}
ACCESS = {'enabled', 'disabled', 'any'}
MAX_PAGE_SIZE = 1000


class AudienceError(ValueError):
    pass


def _ids(raw: str, field: str) -> list[int]:
    values = []
    for part in (raw or '').split(','):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            raise AudienceError(field)
        values.append(int(part))
    return values


def _moment(raw: str, field: str, *, end_of_day: bool = False) -> datetime | None:
    raw = (raw or '').strip()
    if not raw:
        return None
    moment = parse_datetime(raw)
    if moment is None:
        day = parse_date(raw)
        if day is None:
            raise AudienceError(field)
        moment = datetime.combine(day, time.max if end_of_day else time.min)
    if timezone.is_naive(moment):
        moment = timezone.make_aware(moment, UTC)
    return moment


def audience_queryset(company, params):
    """Members of ``company`` matching every given filter, plus any ``user_ids``."""
    group_ids = _ids(params.get('group_ids', ''), 'group_ids')
    roles = {item.strip() for item in (params.get('roles') or '').split(',') if item.strip()}
    if roles - ROLES:
        raise AudienceError('roles')
    access = (params.get('access') or 'enabled').strip()
    if access not in ACCESS:
        raise AudienceError('access')
    joined_after = _moment(params.get('joined_after'), 'joined_after')
    joined_before = _moment(params.get('joined_before'), 'joined_before', end_of_day=True)
    seen_after = _moment(params.get('seen_after'), 'seen_after')
    seen_before = _moment(params.get('seen_before'), 'seen_before', end_of_day=True)
    picked = _ids(params.get('user_ids', ''), 'user_ids')

    members = User.objects.filter(company_memberships__company=company, is_active=True).exclude(email='')
    membership = {'company_memberships__company': company}
    if access != 'any':
        membership['company_memberships__is_enabled'] = access == 'enabled'
    if joined_after:
        membership['company_memberships__created_at__gte'] = joined_after
    if joined_before:
        membership['company_memberships__created_at__lte'] = joined_before
    matched = User.objects.filter(is_active=True, **membership).exclude(email='')
    if group_ids:
        user_ids: set[int] = set()
        for group in CompanyGroup.objects.filter(company=company, pk__in=group_ids):
            user_ids |= effective_user_ids_for_group(group)
        matched = matched.filter(pk__in=user_ids)
    if roles:
        owner_ids = company.owners.values('pk')
        role_filter = Q()
        if 'owner' in roles:
            role_filter |= Q(pk__in=owner_ids)
        if 'staff' in roles:
            role_filter |= Q(is_staff=True)
        if 'member' in roles:
            role_filter |= ~Q(pk__in=owner_ids) & Q(is_staff=False)
        matched = matched.filter(role_filter)
    if seen_after:
        matched = matched.filter(activity__last_seen_at__gte=seen_after)
    if seen_before:
        matched = matched.filter(Q(activity__isnull=True) | Q(activity__last_seen_at__lte=seen_before))
    if picked:
        has_filters = any(
            [group_ids, roles, joined_after, joined_before, seen_after, seen_before, params.get('access')]
        )
        selection = Q(pk__in=picked) | Q(pk__in=matched.values('pk')) if has_filters else Q(pk__in=picked)
        matched = members.filter(selection)
    return matched.distinct().order_by('pk')


def _row(user) -> dict:
    preference = getattr(user, 'preference', None)
    return {
        'id': user.pk,
        'email': user.email,
        'first_name': user.first_name or '',
        'last_name': user.last_name or '',
        'language': getattr(preference, 'language', '') or 'en',
    }


@extend_schema_view(
    get=extend_schema(
        tags=['directory-users'],
        summary='Broadcast audience (staff or company owner)',
        description=(
            'Members of the token company matching every filter, for email broadcasts. '
            '`user_ids` adds hand-picked members; alone, it is the whole audience. '
            'Users without an email or with a deactivated account are left out. '
            'Each row carries the language from the user preferences (`en` by default).'
        ),
        operation_id='api_v1_users_audience',
        parameters=[
            OpenApiParameter(name='group_ids', type=str, description='Comma-separated group ids. Nested groups count.'),
            OpenApiParameter(name='roles', type=str, description='Comma-separated: owner, staff, member.'),
            OpenApiParameter(name='access', type=str, description='enabled (default), disabled, or any.'),
            OpenApiParameter(name='joined_after', type=str, description='ISO date or datetime.'),
            OpenApiParameter(name='joined_before', type=str, description='ISO date or datetime, inclusive.'),
            OpenApiParameter(name='seen_after', type=str, description='ISO date or datetime.'),
            OpenApiParameter(
                name='seen_before', type=str, description='ISO date or datetime, inclusive. Never-seen users match.'
            ),
            OpenApiParameter(name='user_ids', type=str, description='Comma-separated user ids to add.'),
            OpenApiParameter(name='count_only', type=bool, description='Return only `count`.'),
            OpenApiParameter(name='page', type=int),
            OpenApiParameter(name='page_size', type=int, description=f'Up to {MAX_PAGE_SIZE}. Default 100.'),
        ],
        responses={
            200: OpenApiResponse(description='`{count, page, page_size, results}`'),
            400: OpenApiResponse(description='`{error: "invalid_filter", field}`'),
        },
    )
)
class ShellUIAdminUserAudienceView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            queryset = audience_queryset(company, request.GET)
            page = max(1, int(request.GET.get('page') or 1))
            page_size = min(MAX_PAGE_SIZE, max(1, int(request.GET.get('page_size') or 100)))
        except AudienceError as exc:
            return Response({'error': 'invalid_filter', 'field': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TypeError, ValueError):
            return Response({'error': 'invalid_filter', 'field': 'page'}, status=status.HTTP_400_BAD_REQUEST)
        total = queryset.count()
        if request.GET.get('count_only') in {'1', 'true'}:
            return Response({'count': total})
        start = (page - 1) * page_size
        rows = queryset.select_related('preference')[start : start + page_size]
        return Response({'count': total, 'page': page, 'page_size': page_size, 'results': [_row(u) for u in rows]})
