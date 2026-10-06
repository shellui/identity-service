"""Remove magic-link sign-in URLs and tokens from stored webhook data.

Before 0.7.0 the ``identity.auth.magic_link.requested`` webhook payload carried
``magic_link_url``, a live sign-in link, and it was stored in ``ActionOutbox.envelope``.
A receiver that echoed the payload could also put it in ``last_error`` and
``DeliveryAttempt.error_message``. This migration drops those keys and masks any
``token=`` query value left in text. Reversing is a no-op: the secrets are not restored.
"""

import re

from django.db import migrations

_EVENT_TYPE = 'identity.auth.magic_link.requested'
_SECRET_KEYS = ('magic_link_url', 'token', 'raw_token')
_TOKEN_RE = re.compile(r'(token=)[^&\s"\'|<>\\]+')
_REDACTED = '[redacted]'
_BATCH = 500


def _redact_text(value):
    if not isinstance(value, str) or 'token=' not in value:
        return value
    return _TOKEN_RE.sub(r'\1' + _REDACTED, value)


def _strip_keys(data):
    if not isinstance(data, dict):
        return data, False
    changed = False
    cleaned = {}
    for key, value in data.items():
        if key in _SECRET_KEYS:
            changed = True
            continue
        if isinstance(value, dict):
            value, sub_changed = _strip_keys(value)
            changed = changed or sub_changed
        elif isinstance(value, str):
            redacted = _redact_text(value)
            if redacted != value:
                changed = True
                value = redacted
        cleaned[key] = value
    return cleaned, changed


def redact_magic_link_secrets(apps, schema_editor):
    ActionOutbox = apps.get_model('actions', 'ActionOutbox')
    DeliveryAttempt = apps.get_model('actions', 'DeliveryAttempt')
    EventLog = apps.get_model('actions', 'EventLog')
    EmailEventOutbox = apps.get_model('actions', 'EmailEventOutbox')

    for row in ActionOutbox.objects.filter(event_type=_EVENT_TYPE).iterator(chunk_size=_BATCH):
        envelope, changed = _strip_keys(row.envelope)
        last_error = _redact_text(row.last_error)
        if changed or last_error != row.last_error:
            row.envelope = envelope
            row.last_error = last_error
            row.save(update_fields=['envelope', 'last_error'])

    attempts = DeliveryAttempt.objects.filter(
        outbox__event_type=_EVENT_TYPE,
        error_message__contains='token=',
    )
    for attempt in attempts.iterator(chunk_size=_BATCH):
        attempt.error_message = _redact_text(attempt.error_message)
        attempt.save(update_fields=['error_message'])

    for entry in EventLog.objects.filter(event_type=_EVENT_TYPE).iterator(chunk_size=_BATCH):
        data, changed = _strip_keys(entry.data)
        if changed:
            entry.data = data
            entry.save(update_fields=['data'])

    for row in EmailEventOutbox.objects.filter(event_type=_EVENT_TYPE).iterator(chunk_size=_BATCH):
        body, changed = _strip_keys(row.body)
        if changed:
            row.body = body
            row.save(update_fields=['body'])


class Migration(migrations.Migration):

    dependencies = [
        ('actions', '0006_email_event_outbox'),
    ]

    operations = [
        migrations.RunPython(redact_magic_link_secrets, migrations.RunPython.noop),
    ]
