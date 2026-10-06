"""
Staff-only REST API for scheduled job monitoring (``/api/v1/scheduled-jobs``).

Scheduled jobs are platform-level: company owners get 403, even for their own company.
Responses carry keys and enums only (``health``, ``status``, ``error_key``, count kinds);
the admin panel translates them. See docs/scheduled-jobs.md#monitoring.
"""

from __future__ import annotations

from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.actions.models import DeliveryAttempt, EmailEventOutbox, ScheduledJobRun
from apps.actions.scheduled_jobs import JOBS, jobs_overview, run_payload
from apps.authapi.permissions import ShellUIPermission
from apps.authapi.serializers import ShellUIOpenAPISerializer
from apps.authapi.views import _authenticate_bearer_user

DEFAULT_RUNS_LIMIT = 20
MAX_RUNS_LIMIT = 100
MAX_CORRELATED = 100

_STAFF_RESPONSES = {
    401: OpenApiResponse(description='Missing or invalid Bearer token'),
    403: OpenApiResponse(description='Not Django staff (company owners included)'),
}


def _require_platform_staff(request) -> Response | None:
    """Django ``is_staff`` only. No company is needed: the data is not company-scoped."""
    user = _authenticate_bearer_user(request)
    if not user:
        return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    if not user.is_staff:
        return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
    return None


@extend_schema_view(
    get=extend_schema(
        tags=['scheduled-jobs'],
        summary='Scheduled jobs health (staff)',
        description=(
            'Per job (`retry_webhooks`, `purge_expired_data`): `health` (`healthy`, `overdue`, `failing`, '
            '`disabled`), `overdue` (no successful run within `overdue_after_seconds`), `last_run`, '
            '`last_success_at`, `next_expected_at`, `last_counts` and `last_24h` run counts. Also '
            '`scheduler_enabled`, `redis_reachable` (null without a broker) and the beat heartbeat '
            '(`beat_last_seen_at`, `beat_stale`).'
        ),
        operation_id='api_v1_scheduled_jobs_list',
        responses={200: OpenApiResponse(description='Scheduler status and one entry per job'), **_STAFF_RESPONSES},
    ),
)
class ScheduledJobsView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        err = _require_platform_staff(request)
        if err:
            return err
        return Response(jobs_overview())


@extend_schema_view(
    get=extend_schema(
        tags=['scheduled-jobs'],
        summary='Recent runs of one scheduled job (staff)',
        description=(
            'Newest first. Runs are kept 7 days. Runs skipped because another container held the lock '
            'are not stored; see `skipped_locked_total` and the `runs_total` metric.'
        ),
        operation_id='api_v1_scheduled_jobs_runs_list',
        parameters=[
            OpenApiParameter(
                name='limit',
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description=f'1 to {MAX_RUNS_LIMIT} (default {DEFAULT_RUNS_LIMIT}).',
            ),
            OpenApiParameter(
                name='status',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                enum=['running', 'succeeded', 'failed'],
            ),
        ],
        responses={
            200: OpenApiResponse(description='`{"job": …, "results": [run, …]}`'),
            404: OpenApiResponse(description='Unknown job'),
            **_STAFF_RESPONSES,
        },
    ),
)
class ScheduledJobRunsView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request, job):
        err = _require_platform_staff(request)
        if err:
            return err
        if job not in JOBS:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        try:
            limit = int(request.GET.get('limit') or DEFAULT_RUNS_LIMIT)
        except (TypeError, ValueError):
            return Response({'error': 'Invalid limit.'}, status=status.HTTP_400_BAD_REQUEST)
        limit = min(MAX_RUNS_LIMIT, max(1, limit))
        qs = ScheduledJobRun.objects.filter(job=job).order_by('-started_at', '-id')
        st = (request.GET.get('status') or '').strip().lower()
        if st:
            if st not in {c[0] for c in ScheduledJobRun.STATUS_CHOICES}:
                return Response({'error': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(status=st)
        return Response({'job': job, 'results': [run_payload(r) for r in qs[:limit]]})


@extend_schema_view(
    get=extend_schema(
        tags=['scheduled-jobs'],
        summary='One scheduled job run with its webhook deliveries and emails (staff)',
        description=(
            f'`webhook_delivery_attempts`: attempts made by this run (at most {MAX_CORRELATED}), across '
            f'companies. `email_events`: email-service event posts whose last attempt was made by this run '
            f'(at most {MAX_CORRELATED}). `*_truncated` is true when more exist.'
        ),
        operation_id='api_v1_scheduled_jobs_runs_retrieve',
        responses={200: OpenApiResponse(description='Run with correlated rows'), 404: OpenApiResponse(), **_STAFF_RESPONSES},
    ),
)
class ScheduledJobRunDetailView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request, pk):
        err = _require_platform_staff(request)
        if err:
            return err
        run = ScheduledJobRun.objects.filter(pk=pk).first()
        if run is None:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        attempts = list(
            DeliveryAttempt.objects.filter(scheduled_job_run_id=run.pk)
            .select_related('outbox')
            .order_by('created_at', 'id')[: MAX_CORRELATED + 1]
        )
        emails = list(
            EmailEventOutbox.objects.filter(last_scheduled_job_run_id=run.pk).order_by('created_at')[
                : MAX_CORRELATED + 1
            ]
        )
        payload = run_payload(run)
        payload['webhook_delivery_attempts'] = [
            {
                'id': a.pk,
                'delivery_id': str(a.outbox_id),
                'company_id': a.outbox.company_id,
                'event_type': a.outbox.event_type,
                'status': a.status,
                'http_status': a.http_status,
                'attempt_number': a.attempt_number,
                'duration_ms': a.duration_ms,
                'trigger': a.trigger or None,
                'created_at': a.created_at.isoformat(),
            }
            for a in attempts[:MAX_CORRELATED]
        ]
        payload['webhook_delivery_attempts_truncated'] = len(attempts) > MAX_CORRELATED
        payload['email_events'] = [
            {
                'id': str(e.pk),
                'company_id': e.company_id,
                'event_type': e.event_type,
                'status': e.status,
                'attempt_count': e.attempt_count,
                'delivered_at': e.delivered_at.isoformat() if e.delivered_at else None,
            }
            for e in emails[:MAX_CORRELATED]
        ]
        payload['email_events_truncated'] = len(emails) > MAX_CORRELATED
        return Response(payload)
