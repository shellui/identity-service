from datetime import timedelta

from django.db import migrations
from django.utils import timezone

# Older rows would be deleted by the first purge_expired_data run (default retention: 7 days).
_COPY_DAYS = 7
_BATCH = 2000
_TYPES = {'success': 'identity.auth.login.succeeded', 'failure': 'identity.auth.login.failed'}
_DATA_FIELDS = (
    'provider',
    'failure_reason',
    'is_staff_at_event',
    'ip_hash',
    'user_agent',
    'client_timezone',
    'client_device_id_hash',
    'client_country',
    'client_city',
)


def copy_recent_login_events(apps, schema_editor):
    LoginEvent = apps.get_model('authapi', 'LoginEvent')
    EventLog = apps.get_model('actions', 'EventLog')
    since = timezone.now() - timedelta(days=_COPY_DAYS)
    rows = (
        LoginEvent.objects.filter(created_at__gte=since)
        .order_by('created_at', 'id')
        .values('company_id', 'user_id', 'outcome', 'created_at', *_DATA_FIELDS)
    )
    batch = []
    for row in rows.iterator(chunk_size=_BATCH):
        batch.append(
            EventLog(
                company_id=row['company_id'],
                user_id=row['user_id'],
                event_type=_TYPES.get(row['outcome'], _TYPES['failure']),
                data={k: row[k] for k in _DATA_FIELDS if row[k] not in (None, '', False)},
                created_at=row['created_at'],
            )
        )
        if len(batch) >= _BATCH:
            EventLog.objects.bulk_create(batch)
            batch = []
    if batch:
        EventLog.objects.bulk_create(batch)


class Migration(migrations.Migration):

    dependencies = [
        ('actions', '0004_event_log'),
        ('authapi', '0015_scope_self_hosted_gitlab_uids'),
    ]

    operations = [
        migrations.RunPython(copy_recent_login_events, migrations.RunPython.noop),
    ]
