---
description: The two maintenance jobs identity-service runs on a schedule - webhook retries and data purge - how the container runs them, and how to run them yourself.
---

# Scheduled jobs

identity-service runs two maintenance jobs on a schedule. The Docker image runs them for you: with `REDIS_URL` set (required in production), there is nothing to set up.

| Job | Schedule | What happens if it never runs |
| --- | -------- | ----------------------------- |
| `purge_expired_data` | Every hour, at minute 17, for at most 5 minutes | The event log and webhook delivery history grow without limit. The admin panel and Django admin show an error once events are more than one day past retention |
| `retry_webhooks` | Every minute | Failed [webhook](actions.md) deliveries and email-service event posts are never retried. First attempts still go out right after each event |

Both jobs are safe to run when there is nothing to do: they finish after one or two indexed queries.

## How it works

The container starts two processes:

- **gunicorn**, the web app
- a **Celery worker with an embedded beat** (`celery -A config worker --beat`). Beat sends each job on time, the worker runs it. It uses one process with a pool of 2 threads, so an hourly purge never delays webhook retries.

Redis is the message broker. The jobs are the same code as the `purge_expired_data` and `retry_webhooks` management commands, so their output and behavior are identical.

The container entrypoint watches both processes. A `SIGTERM` (for example `docker stop` or a redeploy) is passed to both, so in-flight work finishes cleanly. If either process exits, the entrypoint stops the other one and the container exits, so Docker or Coolify restarts it.

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `REDIS_URL` | unset | Redis for the shared cache and the job broker. **Required when `DEBUG=false`:** without it the container logs `REDIS_URL is required when DEBUG is false` and exits with status 1, also with `SCHEDULER_ENABLED=false`. With `DEBUG=true` the jobs do not run, the container logs a warning and the web app still starts |
| `CELERY_BROKER_URL` | `REDIS_URL` | Use a different Redis for the jobs. Does not replace `REDIS_URL`, which the cache needs |
| `SCHEDULER_ENABLED` | `true` | `false` keeps the worker out of this container. Use it with a dedicated worker container or your own cron. `REDIS_URL` is still required in production |
| `CELERY_WORKER_CONCURRENCY` | `2` | Threads in the worker. 2 lets a purge and a retry run at the same time |

The worker uses the same settings as the web app: `LOG_LEVEL` and stdout logging, Sentry (task errors are reported when `SENTRY_DSN` is set), and `POSTGRES_STATEMENT_TIMEOUT` / `POSTGRES_LOCK_TIMEOUT`.

Each run logs one summary line, for example:

```text
INFO [apps.actions.tasks] retry_webhooks: processed=0 delivered=0 retried=0 dead=0 email_processed=0 email_delivered=0 email_retried=0 email_dead=0 run_id=1234
```

### Several containers

Every job takes a Redis lock before it starts (`SET NX` with an expiry: 2 minutes for `retry_webhooks`, 15 minutes for `purge_expired_data`). When another container already runs the same job, the run is skipped and logs `skipped, another run is in progress`. So you can run several replicas of the image, each with its own beat, and a job never runs twice at the same time. The lock expires on its own if a container dies mid-run.

Jobs use their own queue (`identity-service`) and lock keys, so one Redis can serve identity-service and other Shellui services.

### Run the worker in its own container

The image takes a mode as its command:

| Command | Starts |
| ------- | ------ |
| `web` (default) | migrations, then gunicorn and the worker (unless `SCHEDULER_ENABLED=false`) |
| `worker` | only the worker with beat. No migrations, no web server. Needs `REDIS_URL` (`CELERY_BROKER_URL` alone is enough only with `DEBUG=true`) |
| anything else | runs that command as `appuser`, for example `python manage.py createsuperuser` |

Docker Compose example with the same image and environment:

```yaml
services:
  identity-service:
    image: shellui/identity-service:latest
    env_file: .env
    environment:
      SCHEDULER_ENABLED: "false"
  identity-worker:
    image: shellui/identity-service:latest
    command: worker
    env_file: .env
    restart: unless-stopped
```

The web container runs migrations; the worker only needs the same database. With SQLite, both containers must mount the same `/app/data` volume, so prefer Postgres for this setup.

### Turn it off and use your own scheduler

Set `SCHEDULER_ENABLED=false` and run the management commands from any scheduler, with the same image, environment variables and database as the web service. Examples are in [Run the commands yourself](#run-the-commands-yourself).

## `purge_expired_data`

Deletes rows older than each company's **data retention** (`Company.data_retention_days`, default **7 days**, set in Django admin only):

- [event log](event-log.md) rows (every catalog event and sign-in)
- finished webhook deliveries (`delivered` or `dead`) with their delivery attempts. `pending` and `failed` rows are kept so retries continue
- SCIM provisioning events
- [scheduled job runs](#monitoring) older than 7 days

Events without a company (a sign-in that failed before the company was known, or a staff-only scheduled job event) use the default of 7 days.

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
purge_expired_data: deleted events=1840 webhook_deliveries=12 email_events=0 scim_provisioning_events=0 scheduled_job_runs=168 complete=true run_id=1235
```

### Why every hour

- **Small, steady work.** Each run deletes about one hour of old events instead of a full day at once. Transactions stay short, there is no nightly I/O spike, and PostgreSQL autovacuum keeps up, so the tables stay at a stable size and reuse freed space.
- **Retention stays accurate.** Rows live at most one hour longer than the configured retention.
- **Missed runs are harmless.** The next run catches up. The stale-events error in the admin panel only appears after a full day without a successful run, so a single failure never alerts anyone.
- **Avoid minute 0.** Many jobs start on the hour; an odd minute such as 17 spreads the load.

### Stale events warning

When the oldest event of a company is older than **retention + 1 day**, identity-service reports it:

- the Shellui admin panel shows an error on the dashboard and on **Log events**
- Django admin shows it under **Data retention** on the company page
- `GET /api/v1/events/retention` returns `"stale_events": true`

Check that the container has `REDIS_URL` set and that its logs show `purge_expired_data` runs (or that your own scheduler runs the command). The next successful run removes the warning.

### Storage notes

- Each event row is a compact JSON document: empty values are dropped, the user is a column, and only two indexes exist (company timeline, user timeline). A sign-in row with its indexes takes roughly 0.5 KB, so 10,000 sign-ins a day kept for 7 days use about 35 MB.
- PostgreSQL: autovacuum reclaims deleted rows for reuse. You do not need `VACUUM FULL` in normal operation.
- SQLite: freed pages are reused but the file does not shrink. Run `VACUUM` manually if you need the disk space back after lowering a retention.

## `retry_webhooks`

Retries webhook deliveries whose first attempt failed, with exponential backoff (details in [actions.md](actions.md#delivery-retries-and-scheduling)). The same job retries email-service event posts. See [Email delivery](email-service.md).

```bash
python manage.py retry_webhooks
python manage.py retry_webhooks --batch-size 50 --max-seconds 50 --concurrency 4
```

Keep `--max-seconds` (default 50) under 60 so a run finishes before the next one starts. Overlapping runs are still safe: rows are claimed with skip-locked leases.

## Run the commands yourself

Only needed with `SCHEDULER_ENABLED=false`, or with `DEBUG=true` and no Redis. Run the commands with the **same image, environment variables and database** as the web service.

```text
17 * * * * cd /app && python manage.py purge_expired_data --max-seconds 300
*  * * * * cd /app && python manage.py retry_webhooks
```

### Coolify

Set `SCHEDULER_ENABLED=false`, then on the identity-service resource open **Scheduled Tasks** and add:

| Name | Command | Frequency |
| ---- | ------- | --------- |
| Purge expired data | `python manage.py purge_expired_data --max-seconds 300` | `17 * * * *` |
| Retry webhooks | `python manage.py retry_webhooks` | `* * * * *` |

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

Use the same pattern with `schedule: "* * * * *"` and `["python", "manage.py", "retry_webhooks"]` for webhook retries. On Kubernetes you can also run a `worker` Deployment instead of CronJobs.

## Monitoring

Every run of both jobs is recorded, whether the in-container beat or your own cron started it, so you can check that the jobs run and what they did. The Shellui admin panel shows this to Django staff on the **Identity** dashboard. Company owners never see it.

### What each run records

The management command records its own run, so the Celery path and the cron path give the same data. Each run writes one `ScheduledJobRun` row:

| Field | Content |
| ----- | ------- |
| `job` | `retry_webhooks` or `purge_expired_data` |
| `trigger` | `celery` (in-container beat) or `command` (your scheduler, or a manual run) |
| `status` | `running`, `succeeded` or `failed` |
| `started_at`, `finished_at`, `duration_ms` | Timing |
| `counts` | Items processed, see below |
| `error_key`, `error_class`, `error_message` | On failure: a stable key (`database_error`, `redis_error`, `timeout`, `network_error`, `interrupted`, `unexpected_error`), the exception class and a short message without URL query strings, credentials or tokens |
| `host` | Host name and process id |
| `event_log_id` | The platform event written for this run |

`counts` for `retry_webhooks`: `webhook_deliveries_attempted`, `webhook_deliveries_succeeded`, `webhook_deliveries_failed` (will be retried), `webhook_deliveries_given_up` (now `dead`), and the same four for `email_events_*` (email-service event posts).

`counts` for `purge_expired_data`: rows deleted per type (`events`, `webhook_deliveries`, `email_events`, `scim_provisioning_events`, `scheduled_job_runs`) and `complete` (false when `--max-seconds` ran out).

Some runs are not stored:

- **Skipped runs**: when another container holds the lock, the run only increments the `skipped_locked` counter. With two replicas, one run in two is skipped, and a row for each would double the writes
- **Dry runs**: `--dry-run` changes nothing, so it is not recorded

Runs are kept 7 days: `purge_expired_data` deletes older ones. The latest timestamps per job (`ScheduledJobState`) and the metric counters (`ScheduledJobCounter`) are never purged. A `running` row older than the job's lock expiry (2 minutes for `retry_webhooks`, 15 minutes for `purge_expired_data`) belongs to a process that died, so the next run marks it `failed` with `error_key=interrupted`.

### Health and overdue jobs

A job is overdue when its last successful run is older than 3 times its interval:

| Job | Interval | Overdue after |
| --- | -------- | ------------- |
| `retry_webhooks` | 1 minute | 3 minutes |
| `purge_expired_data` | 1 hour | 2 hours 15 minutes |

Before the first successful run, the clock starts when the monitoring tables were created (the migration). Each job gets one `health` value:

- `disabled`: `SCHEDULER_ENABLED=false` and no run was ever recorded. Set up your cron (see [Run the commands yourself](#run-the-commands-yourself)); the first recorded run turns monitoring on
- `failing`: the last finished run failed
- `overdue`: no successful run within the limit above
- `healthy`: none of the above

Cron runs are monitored like in-container runs, so `SCHEDULER_ENABLED=false` with a working cron reports `healthy`.

Two more signals cover the scheduler itself:

- `redis_reachable`: identity-service answers a `PING` on the broker (`null` without a broker)
- beat heartbeat: each time beat publishes a job, it stores the time in Redis (`identity-service:scheduler:beat:heartbeat`). `beat_stale` is true when the scheduler is enabled and beat published nothing for 3 minutes. A fresh heartbeat with an overdue job means the worker is stuck or down

### Admin API (staff only)

The endpoints use the same Bearer JWT or personal access token as other admin endpoints. They need Django `is_staff`: other callers get `403`, including company owners, and calls without a token get `401`. No `company_id` is needed. Responses contain keys and enums only (`health`, `status`, `error_key`, count names), which the admin panel translates.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET` | `/api/v1/scheduled-jobs` | `scheduler_enabled`, `redis_reachable`, `beat_last_seen_at`, `beat_stale`, and per job: `health`, `overdue`, `last_run`, `last_success_at`, `last_failure_at`, `last_skipped_at`, `last_duration_ms`, `last_counts`, `next_expected_at`, `last_24h`, `skipped_locked_total` |
| `GET` | `/api/v1/scheduled-jobs/{job}/runs?limit=20&status=failed` | Recent runs, newest first. `limit` 1 to 100, `status` optional |
| `GET` | `/api/v1/scheduled-jobs/runs/{id}` | One run with the webhook delivery attempts and email-service event posts it made |
| `GET` | `/api/v1/events?scope=platform` | The platform events of the runs (see [Event log](event-log.md#platform-events-staff-only)) |

Example job entry:

```json
{
  "job": "retry_webhooks",
  "health": "healthy",
  "overdue": false,
  "interval_seconds": 60,
  "overdue_after_seconds": 180,
  "last_success_at": "2026-10-06T13:21:02.511+00:00",
  "next_expected_at": "2026-10-06T13:22:01.904+00:00",
  "last_counts": {"webhook_deliveries_attempted": 2, "webhook_deliveries_succeeded": 2},
  "last_24h": {"succeeded": 1439, "failed": 1},
  "skipped_locked_total": 0
}
```

### From a run to its webhooks and emails

Every webhook delivery attempt stores a `trigger` and, for retries, the run that made it:

- `trigger=dispatch`: the first try, right after the event
- `trigger=automatic_retry`: a `retry_webhooks` run, with `scheduled_job_run_id`

Staff can go both ways:

- run to deliveries: `GET /api/v1/scheduled-jobs/runs/{id}` lists the attempts of every company, and `GET /api/v1/actions/deliveries?scheduled_job_run_id={id}` filters the delivery log of the token company
- delivery to run: each attempt in `GET /api/v1/actions/deliveries/{id}` has `scheduled_job_run_id`

Company owners see `trigger` on their own delivery attempts, so they know a retry was automatic, but never `scheduled_job_run_id` or any run detail. Filtering by `scheduled_job_run_id` as an owner returns `403`.

Email-service event posts store `last_trigger` and `last_scheduled_job_run_id` for their latest attempt, so the run that delivered an email keeps the link. While a job runs, identity-service sends `X-Request-ID: sjr-{run_id}` to email-service, and every identity log line of the run ends with `[req=sjr-{run_id}]`, so you can search both services' logs for one run. Magic-link and invitation emails are sent on the request path (email-service or SMTP), never by a scheduled job.

### Failed runs

A failed run:

- is stored with `status=failed` and its `error_key`
- logs one ERROR line with the job, run id, trigger and sanitized error, plus the traceback. The original exception message is replaced by the sanitized one, so a URL query string or credential in it never reaches the logs
- is reported to Sentry when `SENTRY_DSN` is set, through the same scrubbing as other events, tagged `scheduled_job`, `scheduled_job_trigger` and `scheduled_job_run_id`
- increments `shellui_auth_scheduled_job_runs_total{status="failed"}`
- makes the command exit with status 1 and print `retry_webhooks failed: OperationalError: … (run_id=1234)`, so an external scheduler that alerts on failed jobs still works

If Redis is down when a Celery run tries to take its lock, that run is recorded as `failed` with `error_key=redis_error`.

### Prometheus metrics

`GET /api/v1/metrics/all` includes the scheduled job metrics. It needs Django staff or a personal access token with `access_global_metrics` (see [Metrics](metrics.md)). The company endpoint `GET /api/v1/metrics` never includes them. Values come from the database, so they are the same whichever gunicorn worker answers and survive restarts.

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `shellui_auth_scheduled_job_runs_total` | counter | `job`, `status` | Finished runs: `succeeded`, `failed`, `skipped_locked` |
| `shellui_auth_scheduled_job_items_total` | counter | `job`, `kind` | Items processed, `kind` is a `counts` name |
| `shellui_auth_scheduled_job_last_success_timestamp_seconds` | gauge | `job` | Unix time of the last successful run (0 before the first one) |
| `shellui_auth_scheduled_job_last_run_timestamp_seconds` | gauge | `job` | Unix time the last run started (0 before the first one) |
| `shellui_auth_scheduled_job_last_run_duration_seconds` | gauge | `job` | Duration of the last finished run |
| `shellui_auth_scheduled_job_overdue` | gauge | `job` | 1 when overdue (see the table above) |
| `shellui_auth_scheduler_enabled` | gauge | none | 1 when `SCHEDULER_ENABLED` is true |
| `shellui_auth_scheduler_redis_up` | gauge | none | 1 when the broker answers `PING`. Absent without a broker |
| `shellui_auth_scheduler_beat_last_seen_timestamp_seconds` | gauge | none | Unix time beat last published a job. Absent before the first one |

Suggested alert rules:

```yaml
groups:
  - name: identity-scheduled-jobs
    rules:
      - alert: IdentityScheduledJobOverdue
        expr: shellui_auth_scheduled_job_overdue == 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "identity-service job {{ $labels.job }} has no recent successful run"
      - alert: IdentityScheduledJobFailing
        expr: increase(shellui_auth_scheduled_job_runs_total{status="failed"}[15m]) >= 3
        labels:
          severity: warning
      - alert: IdentitySchedulerRedisDown
        expr: shellui_auth_scheduler_redis_up == 0
        for: 2m
        labels:
          severity: critical
      - alert: IdentityWebhooksGivenUp
        expr: increase(shellui_auth_scheduled_job_items_total{kind="webhook_deliveries_given_up"}[1h]) > 0
        labels:
          severity: info
```

The overdue alert covers a stopped beat, a stuck worker and a missing cron line alike. Scrape every 30 to 60 seconds: each scrape runs a few indexed queries and one Redis `PING`.

### Other safety nets

- The commands exit with status 1 on errors, so any external scheduler that alerts on failed jobs covers them
- For `purge_expired_data`, the stale-events warning is a second safety net that needs no setup

## Related

- [Event log](event-log.md)
- [Webhooks](actions.md)
- [Configuration](configuration.md#scheduled-jobs)
