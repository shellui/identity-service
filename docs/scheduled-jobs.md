# Scheduled jobs

identity-service runs two maintenance jobs on a schedule. The Docker image runs them for you: with `REDIS_URL` set (required in production), there is nothing to set up.

| Job | Schedule | What happens if it never runs |
| --- | -------- | ----------------------------- |
| `purge_expired_data` | Every hour, at minute 17, for at most 5 minutes | The event log and webhook delivery history grow without limit. The admin panel and Django admin show an error once events are more than one day past retention |
| `retry_webhooks` | Every minute | Failed [webhook](actions.md) deliveries and email-service event posts are never retried. First attempts still go out right after each event |

Both jobs are safe to run when there is nothing to do: they finish after one or two indexed queries.

---

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
INFO [apps.actions.tasks] retry_webhooks: processed=0 delivered=0 retried=0 dead=0 email_processed=0 email_delivered=0 email_retried=0 email_dead=0
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

---

## `retry_webhooks`

Retries webhook deliveries whose first attempt failed, with exponential backoff (details in [actions.md](actions.md#delivery-retries-and-scheduling)). The same job retries email-service event posts. See [Email](email-service.md).

```bash
python manage.py retry_webhooks
python manage.py retry_webhooks --batch-size 50 --max-seconds 50 --concurrency 4
```

Keep `--max-seconds` (default 50) under 60 so a run finishes before the next one starts. Overlapping runs are still safe: rows are claimed with skip-locked leases.

---

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

---

## Monitoring

- In-container jobs log one line per run. A failing run logs an error with the traceback, and is reported to Sentry when `SENTRY_DSN` is set.
- The commands exit with a non-zero status on errors, so any external scheduler that alerts on failed jobs covers them.
- For `purge_expired_data`, the stale-events warning is a second safety net that needs no extra setup.

---

## Related docs

- [Event log](event-log.md)
- [Shellui webhooks](actions.md)
- [Configuration](configuration.md)
