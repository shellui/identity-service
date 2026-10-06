---
description: Every environment variable of identity-service, grouped by topic, with defaults and what production requires.
---

# Configuration

identity-service is configured with environment variables. Copy [`.env.example`](https://github.com/shellui/identity-service/blob/main/.env.example) to `.env` for local runs, and pass the same variables to Docker, Coolify, or your orchestrator in production. Durations accept a bare number of seconds or a suffix: `s`, `m`, `h`, `d` (for example `5m` or `30d`).

## Required in production

With `DEBUG=false` (the Docker image default), identity-service refuses to start without these:

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Signs Django sessions and CSRF tokens. Required in every mode |
| `JWT_PRIVATE_KEY` | RS256 private key that signs tokens, see [JWT and JWKS](jwks.md#configure-signing) |
| `JWT_ISSUER` | `iss` claim, the public identity URL, for example `https://auth.example.com` |
| `JWT_AUDIENCE` | `aud` claim, for example `shellui` |
| `REDIS_URL` | Shared cache and job broker, see [Shared cache (Redis)](#shared-cache-redis) |
| `ALLOWED_HOSTS` | Comma-separated host names, no scheme, for example `auth.example.com` |

Behind TLS, also set `CSRF_TRUSTED_ORIGINS` to the full HTTPS URL (for example `https://auth.example.com`) so Django admin and the OAuth confirmation page accept form posts.

## Tokens

| Variable | Default | Purpose |
| --- | --- | --- |
| `JWT_ACCESS_TOKEN_LIFETIME` | `5m` | Access token lifetime |
| `JWT_REFRESH_TOKEN_LIFETIME` | `7d` | Refresh token lifetime |
| `PERSONAL_ACCESS_TOKEN_LIFETIME` | `30d` | Lifetime of new personal access tokens |
| `JWT_PUBLIC_KEY`, `JWT_KEY_ID` | derived | Derived from the private key when unset |
| `JWT_PREVIOUS_PUBLIC_KEY`, `JWT_PREVIOUS_KEY_ID` | empty | Previous key during a rotation, still published in JWKS |
| `JWT_ACCEPT_HS256_LEGACY` | `false` | Accept HS256 tokens while moving from HS256 to RS256 |
| `SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE` | `5m` | Maximum age of `auth_time` for [account deletion](account-deletion.md) |

## Sign-in

| Variable | Default | Purpose |
| --- | --- | --- |
| `OAUTH_TOKEN_DELIVERY` | `code` | `code`: one-time `shellui_auth_code` exchanged with `POST /api/v1/oauth/session`. `fragment`: tokens in the URL fragment (legacy) |
| `OAUTH_SESSION_CODE_TTL_SECONDS` | `120` | Lifetime of the one-time code |
| `OAUTH_SKIP_CONFIRM_PROVIDERS` | `google` | Providers that skip the confirmation page, comma-separated. Set it empty to always show the page |
| `OAUTH_ALLOW_LOOPBACK_REDIRECTS` | same as `DEBUG` | Allow `redirect_to` on `localhost`, `127.0.0.1`, and `::1` |
| `MAGIC_LINK_ENABLED` | `true` | Turns every magic link endpoint on or off |
| `MAGIC_LINK_TTL_SECONDS` | `1800` | Magic link lifetime |
| `MAGIC_LINK_EMAIL_DEFAULT_LANGUAGE` | `en` | Magic link email language when the request and the user have none |
| `SCIM_ENABLED` | `true` | `false` makes every SCIM URL return **404** (emergency switch) |

See [OAuth login](oauth-login.md), [Magic link](magic-link.md), and [SCIM provisioning](scim.md).

## Email

identity-service sends magic links, invitations, and owner notifications. See [Email delivery](email-service.md) for how email-service and SMTP fit together.

| Variable | Default | Purpose |
| --- | --- | --- |
| `EMAIL_SERVICE_API_KEY` | empty | email-service key (`esk_`). Unset sends everything over SMTP |
| `EMAIL_SERVICE_URL` | `https://email.shellui.com` | email-service origin. Local: `http://localhost:8003`, or `http://host.docker.internal:8003` from a container |
| `EMAIL_SERVICE_TIMEOUT_SECONDS` | `5` | Timeout for one HTTP attempt |
| `EMAIL_SERVICE_SEND_ATTEMPTS` | `3` | Attempts for one direct send |
| `EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS` | `1` | Longest pause between direct send attempts |
| `EMAIL_BACKEND` | console with `DEBUG=true`, SMTP otherwise | Django email backend |
| `EMAIL_HOST`, `EMAIL_PORT` | `localhost`, `25` | SMTP server |
| `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD` | empty | SMTP credentials |
| `EMAIL_USE_TLS`, `EMAIL_USE_SSL` | `false` | SMTP encryption |
| `DEFAULT_FROM_EMAIL` | `noreply@localhost` | Sender address for SMTP |
| `EMAIL_TIMEOUT` | `10` | Seconds before an SMTP connect, read, or write gives up. Without it, a silent mail server could hold a sign-in request forever |

email-service `EMAIL_AUTH_LINK_HOSTS` must include the host of `JWT_ISSUER`.

## Webhooks

| Variable | Default | Purpose |
| --- | --- | --- |
| `ACTIONS_WEBHOOK_TIMEOUT_SECONDS` | `5` | Timeout of one webhook POST |
| `ACTIONS_OUTBOX_MAX_ATTEMPTS` | `8` | Delivery attempts before a delivery fails |
| `ACTIONS_WEBHOOK_ALLOW_PRIVATE` | `false` | Allow webhooks to private IP addresses |
| `ACTIONS_WEBHOOK_RETRY_LEASE_SECONDS` | `120` | How long a retry worker holds a delivery |
| `ACTIONS_WEBHOOK_DISPATCH_WORKERS` | `4` | Threads that send webhooks after the database commit |

See [Webhooks](actions.md).

## Shared cache (Redis)

| Variable | Default | Purpose |
| --- | --- | --- |
| `REDIS_URL` | unset | Required with `DEBUG=false` since 0.7.0. Holds rate limits, the logout denylist, OAuth PKCE state, SAML request IDs and replay protection, and last-seen throttling. Also the broker of the [scheduled jobs](#scheduled-jobs) |

With `DEBUG=false`, the container refuses to start without `REDIS_URL`, also with `SCHEDULER_ENABLED=false` or `CELERY_BROKER_URL` set, because the cache and the OAuth and SAML state need it. In `web` and `worker` mode the entrypoint exits with status 1 before migrations:

```text
entrypoint: ERROR: REDIS_URL is required when DEBUG is false (example: redis://redis:6379/0).
```

`manage.py check --deploy` reports the same problem as `authapi.E004`. Other container commands, such as `createsuperuser`, and the test suite still run.

With `DEBUG=true`, `REDIS_URL` is optional: Django uses an in-process cache, and the container logs a warning and runs without the scheduled jobs.

```bash
# Redis next to identity-service in Docker Compose or Coolify
REDIS_URL=redis://redis:6379/0
```

[PUBLISH.md](https://github.com/shellui/identity-service/blob/main/PUBLISH.md) describes the Redis setup on Coolify.

## Scheduled jobs

The Docker image runs `retry_webhooks` every minute and `purge_expired_data` every hour, in a Celery worker next to gunicorn. With `REDIS_URL` set, there is nothing else to configure. See [Scheduled jobs](scheduled-jobs.md) for several replicas and external cron.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SCHEDULER_ENABLED` | `true` | Start the worker in the web container. Set `false` when a `worker` container or your own cron runs the jobs |
| `CELERY_BROKER_URL` | `REDIS_URL` | A different broker for the jobs |
| `CELERY_WORKER_CONCURRENCY` | `2` | Worker threads, so the hourly purge and a webhook retry can run together |

The container command picks what runs: `web` (default: migrations, gunicorn, and the worker), `worker` (the worker only, no migrations), or any other command, run as `appuser`.

## Database

| Variable | Default | Purpose |
| --- | --- | --- |
| `POSTGRES_DATABASE_URL` | empty | PostgreSQL DSN. Unset uses SQLite |
| `SQLITE_PATH` | `db.sqlite3`, `/app/data/db.sqlite3` in Docker | SQLite file |
| `POSTGRES_SSL_REQUIRE` | `true` with `DEBUG=false` | Require TLS to PostgreSQL |
| `POSTGRES_CONNECT_TIMEOUT` | `10` | Seconds, so workers do not hang on a dead connection |
| `POSTGRES_STATEMENT_TIMEOUT` | `15` | Seconds before PostgreSQL cancels a query. `0` turns it off. Not applied to `migrate` |
| `POSTGRES_LOCK_TIMEOUT` | `5` | Seconds before PostgreSQL stops waiting for a lock. `0` turns it off. Not applied to `migrate` |

SQLite runs in WAL mode for better concurrency on a single node. With PostgreSQL, connections that died while idle are replaced before the next request uses them.

For load balancer health checks, use `GET /health/live`. It touches neither the session nor the database.

## Gunicorn (Docker entrypoint)

| Variable | Default | Purpose |
| --- | --- | --- |
| `GUNICORN_WORKERS` | `4` | Worker processes |
| `GUNICORN_THREADS` | `4` | Threads per worker (`gthread` worker class) |
| `GUNICORN_TIMEOUT` | `60` | Seconds of silence before gunicorn restarts a frozen worker process. See the note below |
| `GUNICORN_GRACEFUL_TIMEOUT` | `30` | Seconds a worker gets to finish open requests on restart or shutdown |
| `GUNICORN_KEEP_ALIVE` | `75` | Seconds an idle keep-alive connection stays open. Keep it above the reverse proxy idle timeout to avoid random 502 errors |
| `GUNICORN_MAX_REQUESTS` | `1000` | Restart a worker after this many requests. `0` turns it off |
| `GUNICORN_MAX_REQUESTS_JITTER` | `200` | Random extra requests added to `GUNICORN_MAX_REQUESTS`, so workers do not all restart at once |

Concurrency is about `workers × threads`. A pool that is too small queues requests while OAuth calls hold threads.

:::note GUNICORN_TIMEOUT does not stop a stuck request
With the `gthread` worker class, a worker keeps sending heartbeats while one of its threads is blocked (on SMTP, the database, or an outbound HTTP call), so gunicorn never kills it. Requests sent to that worker can wait with no response and no log line. Request deadlines come from the app instead: `EMAIL_TIMEOUT`, `POSTGRES_STATEMENT_TIMEOUT`, `POSTGRES_LOCK_TIMEOUT`, and the 20 second OAuth HTTP timeouts. Set a response timeout on the reverse proxy too. `GUNICORN_MAX_REQUESTS` also recycles workers over time.
:::

The entrypoint sets `--worker-tmp-dir /dev/shm` (the heartbeat file lives in memory) and writes the gunicorn access and error logs to stdout. Each access log line ends with the duration and the request ID, for example `"GET /api/v1/settings HTTP/1.1" 200 512 "Mozilla/5.0" 182ms req=4f2c9a1e`. Lines have the path without the query string and no Referer, because query strings carry magic link tokens, OAuth codes, `confirm_token`, and `setup_token`.

## Security

| Variable | Default | Purpose |
| --- | --- | --- |
| `TRUSTED_PROXY_IPS` | empty | Reverse proxies allowed to set `X-Forwarded-For` (IPs or CIDR ranges) |
| `CORS_ALLOW_ALL_ORIGINS` | `true` | Allow API calls from any shell origin, without credentials |
| `CORS_ALLOW_CREDENTIALS` | `false` | Must stay `false` while `CORS_ALLOW_ALL_ORIGINS=true` |
| `CORS_ALLOWED_ORIGINS`, `CORS_ALLOWED_ORIGIN_REGEXES` | empty | Allowed origins when `CORS_ALLOW_ALL_ORIGINS=false` |
| `AUTH_RATE_LIMIT_ENABLED` | `true` | Turn rate limits off, for debugging only |
| `AUTH_RATE_LIMIT_*` | see link | One limit per scope: `OAUTH`, `TOKEN_REFRESH`, `SETTINGS`, `MAGIC_LINK`, `INVITATION`, `ADMIN_LOGIN`, `PAT` |
| `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` | on with `DEBUG=false` | HTTPS defaults |

See [Security hardening](security-hardening.md) for the rate limit defaults, proxies, and CORS.

## Runtime and observability

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEBUG` | `false` in Docker | Development mode. Never `true` in production |
| `SETUP_TOKEN` | empty | One-time token for the web form that creates the first superuser with `DEBUG=false`. Prefer `createsuperuser` |
| `IDENTITY_SERVICE_PORT` | `8000` | Host port in Docker Compose |
| `LOG_LEVEL` | `INFO`, `DEBUG` with `DEBUG=true` | App log level on stdout. Django errors and warnings (500 errors, `DisallowedHost`, CSRF failures) are always printed |
| `SLOW_REQUEST_THRESHOLD_SECONDS` | `2` | Log a warning for slower requests. `0` turns it off |
| `SENTRY_DSN` | empty | Turns on Sentry error reporting. No personal data is sent |
| `SENTRY_ENVIRONMENT`, `SENTRY_RELEASE` | empty | Sentry tags |
| `SENTRY_TRACES_SAMPLE_RATE` | `0` | Share of requests traced. `0` reports errors only; `0.1` shows slow requests |
| `SHELLUI_GEOIP_DATABASE_PATH` | empty | MaxMind GeoLite2 City file (`.mmdb`), adds country and city to sign-in events. Also needs the optional `geoip2` package, which the image does not include |

## Related

- [Run identity-service](getting-started.md): first start and production checklist
- [Security hardening](security-hardening.md)
- [Upgrade notes](upgrading.md)
