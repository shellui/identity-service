# Scheduled jobs (cron)

identity-service has no background worker. Two management commands keep it healthy and should run on a schedule, from the same image and environment (database, `SECRET_KEY`) as the web service.

| Command | Schedule | Needed when | What happens if it never runs |
| ------- | -------- | ----------- | ----------------------------- |
| `purge_expired_data` | Every hour (for example at minute 17) | Always | The event log and webhook delivery history grow without limit. The admin panel and Django admin show an error once events are more than one day past retention |
| `retry_webhooks` | Every minute | A company uses [webhooks](actions.md), or `EMAIL_SERVICE_API_KEY` is set | Failed webhook deliveries and email-service event posts are never retried. First attempts still go out right after each event |

Both commands are safe to run when there is nothing to do: they exit after one or two indexed queries.

---

## `purge_expired_data`

Deletes rows older than each company's **data retention** (`Company.data_retention_days`, default **7 days**, set in Django admin only):

- [event log](event-log.md) rows (every catalog event and sign-in)
- finished webhook deliveries (`delivered` or `dead`) with their delivery attempts. `pending` and `failed` rows are kept so retries continue
- SCIM provisioning events

Events without a company (a sign-in that failed before the company was known) use the default of 7 days.

```bash
python manage.py purge_expired_data
python manage.py purge_expired_data --dry-run           # count only
python manage.py purge_expired_data --max-seconds 300   # stop after 5 minutes, the next run continues
```

| Flag | Default | Purpose |
| ---- | ------- | ------- |
| `--batch-size` | `2000` | Rows deleted per statement. Lower it if deletes compete with production traffic |
| `--max-seconds` | `0` (no limit) | Stop early. Output says `complete=false` and the next run picks up where it stopped |
| `--dry-run` | off | Count expired rows without deleting |

Output example:

```text
purge_expired_data: deleted events=1840 webhook_deliveries=12 scim_provisioning_events=0 complete=true
```

### Recommended schedule: every hour

```text
17 * * * * cd /app && python manage.py purge_expired_data --max-seconds 300 >> /var/log/purge_expired_data.log 2>&1
```

Why hourly rather than once at midnight:

- **Small, steady work.** Each run deletes about one hour of old events instead of a full day at once. Transactions stay short, there is no nightly I/O spike, and PostgreSQL autovacuum keeps up, so the tables stay at a stable size and reuse freed space.
- **Retention stays accurate.** Rows live at most one hour longer than the configured retention.
- **Missed runs are harmless.** The next run catches up. The stale-events error in the admin panel only appears after a full day without a successful run, so a single failure never alerts anyone.
- **Avoid minute 0.** Many jobs start on the hour; an odd minute such as 17 spreads the load.

A daily run at a quiet hour (for example `17 3 * * *`) also works for small deployments. Expect events to live up to 8 days with a 7-day retention.

### Stale events warning

When the oldest event of a company is older than **retention + 1 day**, identity-service reports it:

- the Shellui admin panel shows an error on the dashboard and on **Log events**
- Django admin shows it under **Data retention** on the company page
- `GET /api/v1/events/retention` returns `"stale_events": true`

Fix it by scheduling `purge_expired_data` as described above. The next successful run removes the warning.

### Storage notes

- Each event row is a compact JSON document: empty values are dropped, the user is a column, and only two indexes exist (company timeline, user timeline). A sign-in row with its indexes takes roughly 0.5 KB, so 10,000 sign-ins a day kept for 7 days use about 35 MB.
- PostgreSQL: autovacuum reclaims deleted rows for reuse. You do not need `VACUUM FULL` in normal operation.
- SQLite: freed pages are reused but the file does not shrink. Run `VACUUM` manually if you need the disk space back after lowering a retention.

---

## `retry_webhooks`

Retries webhook deliveries whose first attempt failed, with exponential backoff (details in [actions.md](actions.md#delivery-retries-and-cron)). The same command retries email-service event posts. See [Email](email-service.md).

```text
* * * * * cd /app && python manage.py retry_webhooks >> /var/log/retry_webhooks.log 2>&1
```

Keep `--max-seconds` (default 50) under 60 so a run finishes before the next one starts. Overlapping runs are still safe: rows are claimed with skip-locked leases.

---

## Where to configure the jobs

Run the commands with the **same image, environment variables and database** as the web service. The image entrypoint runs migrations and starts Gunicorn, so override the command rather than starting a full container.

### Coolify

On the identity-service resource, open **Scheduled Tasks** and add:

| Name | Command | Frequency |
| ---- | ------- | --------- |
| Purge expired data | `python manage.py purge_expired_data --max-seconds 300` | `17 * * * *` |
| Retry webhooks | `python manage.py retry_webhooks` | `* * * * *` |

Tasks run inside the running container, so they share its environment.

### Docker Compose (host crontab)

```text
17 * * * * cd /srv/identity-service && docker compose exec -T -u appuser identity-service python manage.py purge_expired_data --max-seconds 300
*  * * * * cd /srv/identity-service && docker compose exec -T -u appuser identity-service python manage.py retry_webhooks
```

### Kubernetes

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: identity-purge-expired-data
spec:
  schedule: "17 * * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      backoffLimit: 0
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: purge
              image: shellui/identity-service:latest
              command: ["python", "manage.py", "purge_expired_data", "--max-seconds", "300"]
              envFrom:
                - secretRef:
                    name: identity-service-env
```

Use the same pattern with `schedule: "* * * * *"` and `["python", "manage.py", "retry_webhooks"]` for webhook retries.

### Monitoring

Both commands print one summary line and exit with a non-zero status on errors, so any scheduler that alerts on failed jobs covers them. For `purge_expired_data`, the stale-events warning is a second safety net that needs no extra setup.

---

## Related docs

- [Event log](event-log.md)
- [Shellui webhooks](actions.md)
- [Configuration](configuration.md)
