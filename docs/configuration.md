---
description: Every environment variable of identity-service, grouped by topic, with defaults and what production requires.
---

# Configuration

identity-service is configured with environment variables. This page is the full reference. [`.env.example`](../.env.example) lists only the required settings; every optional one appears there as a commented-out line with its default, so copy it to `.env` for local runs and uncomment only what you change. To start a production config, run `python manage.py generate_env --host auth.example.com`: it prints the required settings with fresh secrets, see [Run identity-service](getting-started.md#deploy-to-production). The variable list lives in `config/env_registry.py`, which renders `.env.example` (`generate_env --example`), and a test checks it against the code and this page. Pass the same variables to Docker, Coolify, or your orchestrator in production. Durations accept a bare number of seconds or a suffix: `s`, `m`, `h`, `d` (for example `5m` or `30d`).

## Required in production

With `DEBUG=false` (the Docker image default), identity-service refuses to start without these:

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Signs Django sessions and CSRF tokens. Required in every mode. With `DEBUG=false`, a key shorter than 50 characters or a known placeholder fails `manage.py check --deploy` (`authapi.E005`) |
| `JWT_PRIVATE_KEY` | RS256 private key that signs tokens, see [JWT and JWKS](jwks.md#configure-signing) |
| `JWT_ISSUER` | `iss` claim, the public identity URL, for example `https://auth.example.com` |
| `JWT_AUDIENCE` | `aud` claim, for example `shellui` |
| `REDIS_URL` | Shared cache and job broker, see [Shared cache (Redis)](#shared-cache-redis) |
| `ALLOWED_HOSTS` | Comma-separated host names, no scheme, for example `auth.example.com`. Defaults to `localhost,127.0.0.1`, so a public host gets **400** until it is listed |

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
| `OAUTH_TOKEN_DELIVERY` | `code` | `code`: one-time `shellui_auth_code` exchanged with `POST /api/v1/oauth/session`. `fragment` is ignored since 0.9.0: tokens are never sent in the URL fragment |
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
| `EMAIL_SERVICE_URL` | `https://email.shellui.com` | Public email-service origin (MCP discovery). Local stack: `http://localhost:8004`, see [Local dev stack](local-dev-stack.md) |
| `EMAIL_SERVICE_INTERNAL_URL` | empty | Server-to-server email-service origin. Unset uses `EMAIL_SERVICE_URL`. Local stack: `http://email:8000` |
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
| `ACTIONS_WEBHOOK_SYNC_DELIVERY` | `false` | Send webhooks inline in the request instead of in background threads. For tests only |

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
| `CELERY_BEAT_SCHEDULE_FILE` | `/tmp/celerybeat-schedule` | Where Celery beat keeps its schedule state (Docker entrypoint) |

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

For load balancer health checks, use `GET /health/live`. It touches neither the session nor the database. The Docker image already runs it as its `HEALTHCHECK`, so Coolify needs no health check config.

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
| `AUTH_RATE_LIMIT_OAUTH` | `30` | OAuth requests per minute |
| `AUTH_RATE_LIMIT_MCP_REGISTER` | `10` | MCP dynamic client registrations per hour, per client IP |
| `AUTH_RATE_LIMIT_MCP_SIGNIN` | `30` | MCP sign-in page requests per 5 minutes, per client IP |
| `AUTH_RATE_LIMIT_TOKEN_REFRESH` | `60` | Token refreshes per minute |
| `AUTH_RATE_LIMIT_SETTINGS` | `30` | `GET /api/v1/settings` per minute |
| `AUTH_RATE_LIMIT_MAGIC_LINK` | `10` | Magic link requests per minute |
| `AUTH_RATE_LIMIT_TOKEN_EXCHANGE` | `30` | Token exchange requests per minute, per client IP |
| `AUTH_RATE_LIMIT_PAT` | `30` | Personal access token requests per minute |
| `AUTH_RATE_LIMIT_ADMIN_LOGIN` | `10` | Django admin sign-ins per 5 minutes |
| `AUTH_RATE_LIMIT_INVITATION` | `30` | Invitations per 5 minutes per company |
| `AUTH_RATE_LIMIT_MCP_PERSONAL_AGENT` | `10` | Personal MCP agent token creations per hour, per user |
| `AUTH_RATE_LIMIT_MCP_DEVICE_CODE` | `30` | Device authorization requests per 5 minutes, per client IP |
| `AUTH_RATE_LIMIT_MCP_DEVICE_VERIFY` | `8` | Device user-code attempts per 5 minutes, per client IP |
| `MCP_DYNAMIC_CLIENT_REGISTRATION` | `true` | MCP OAuth dynamic client registration |
| `MCP_ACCESS_TOKEN_LIFETIME` | `15m` | MCP agent access JWT lifetime |
| `MCP_REFRESH_TOKEN_LIFETIME` | `30d` | MCP agent refresh token lifetime |
| `MCP_PERSONAL_AGENT_MAX_LIFETIME_DAYS` | `90` | Maximum lifetime for personal MCP bearer tokens and for device-login agents |
| `MCP_DEVICE_CODE_LIFETIME_SECONDS` | `600` | How long a device code stays valid (clamped 60 to 1800) |
| `MCP_DEVICE_CODE_INTERVAL_SECONDS` | `5` | Minimum seconds between device-code token polls (clamped 5 to 60) |
| `MCP_AGENT_ACTIVITY_RETENTION_DAYS` | `90` | How long member activity logs are kept for personal MCP agents |
| `MCP_APPROVAL_SESSION_TTL_SECONDS` | `60` | Seconds a client "Allow for this session" grant lasts (clamped 30 to 60) for non-destructive MCP writes |
| `MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS` | `900` | Maximum `exp - iat` Identity accepts on internal MCP approval assertions **from ai-service only** (600 to 900 second setup flows); other issuers stay at 60 seconds; shellui-django defaults to 60 |
| `MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS` | `600` | Lower bound for `mcp_session_ttl_seconds` on ai-service assertions with `setup_flow` when extending session Allow |
| `MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS` | `900` | Upper bound for the same |
| `MCP_RATE_LIMIT_AGENT` | `120` | MCP tool calls per minute per agent |
| `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` | `true` with `DEBUG=false`, `false` with `DEBUG=true` | HTTPS defaults. Secure cookies are named `__Host-sessionid` and `__Host-csrftoken`, with no `Domain`. `CSRF_COOKIE_HTTPONLY` is always on |
| `SECURE_HSTS_SECONDS` | `31536000` with `DEBUG=false`, `0` with `DEBUG=true` | HSTS max-age |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | `true` with `DEBUG=false` | Add `includeSubDomains` to HSTS |
| `SECURE_HSTS_PRELOAD` | `false` | Add `preload` to HSTS |

See [Security hardening](security-hardening.md) for the rate limit defaults, proxies, and CORS.

## Runtime and observability

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEBUG` | `false` | Optional. Unset or empty means `false`, so production does not need to set it. Set `true` only for local development (`.env.example` and `docker-compose.yml` do). Required in `.env.example` for local runs |
| `SETUP_TOKEN` | empty | One-time token for the web form that creates the first superuser with `DEBUG=false`. Prefer `createsuperuser` |
| `IDENTITY_DEV_SEED` | `false` | Local dev only. With `DEBUG=true`, the dev entrypoint runs `manage.py seed_dev` (company 1, `admin` / `admin`, `dev@localhost`). Never set in production |
| `IDENTITY_SERVICE_PORT` | `8000` | Host port in `docker-compose.yml` only |
| `LOG_LEVEL` | `INFO`, `DEBUG` with `DEBUG=true` | App log level on stdout. Django errors and warnings (500 errors, `DisallowedHost`, CSRF failures) are always printed |
| `SLOW_REQUEST_THRESHOLD_SECONDS` | `2` | Log a warning for slower requests. `0` turns it off |
| `SENTRY_DSN` | empty | Turns on Sentry error reporting. No personal data is sent |
| `SENTRY_ENVIRONMENT` | `production`, `development` with `DEBUG=true` | Sentry environment tag |
| `SENTRY_RELEASE` | package version | Sentry release tag |
| `SENTRY_TRACES_SAMPLE_RATE` | `0` | Share of requests traced. `0` reports errors only; `0.1` shows slow requests |
| `SHELLUI_GEOIP_DATABASE_PATH` | empty | MaxMind GeoLite2 City file (`.mmdb`), adds country and city to sign-in events. Also needs the optional `geoip2` package, which the image does not include |

## Instance role

Leave `SHELLUI_INSTANCE_ROLE` unset for a standalone deployment. `global` turns this process into an OpenID Provider. `region` trusts one upstream identity provider configured with `GLOBAL_ISSUER_URL`, a pinned `GLOBAL_JWKS`, and `GLOBAL_CLIENT_ID` / `GLOBAL_CLIENT_SECRET`. Endpoints, assertions, and the production host check are in [Instance roles](instance-roles.md).

| Variable | Default | Purpose |
| --- | --- | --- |
| `SHELLUI_INSTANCE_ROLE` | unset | `global`, `region`, or unset |
| `OIDC_CLIENTS` | empty | JSON list of confidential clients, provider role |
| `OIDC_CORS_ALLOWED_ORIGINS` | empty | Origins allowed on the OpenID endpoints. The Bearer API is unchanged |
| `OIDC_SESSION_TTL_SECONDS` | `43200` | Provider browser-session lifetime |
| `OIDC_CODE_TTL_SECONDS` | `60` | Authorization code lifetime |
| `OIDC_ID_TOKEN_TTL_SECONDS` | `300` | `id_token` lifetime |
| `OIDC_BACKCHANNEL_TIMEOUT_SECONDS` | `3` | Back-channel logout POST timeout |
| `GLOBAL_ISSUER_URL` | empty | Upstream issuer, relying party role (browser redirects and `iss` validation) |
| `GLOBAL_ISSUER_INTERNAL_URL` | empty | Base URL for server-side calls to the upstream token endpoint. Unset uses `GLOBAL_ISSUER_URL`. Local stack: `http://identity:8000` on a regional server |
| `GLOBAL_JWKS` | empty | Pinned upstream JWKS JSON |
| `GLOBAL_CLIENT_ID`, `GLOBAL_CLIENT_SECRET` | empty | Upstream client credentials |
| `GLOBAL_REDIRECT_URI` | `{JWT_ISSUER}/oauth/upstream-callback` | Upstream redirect URI when the public URL differs |
| `GLOBAL_ACCESS_TOKEN_AUDIENCE` | empty | `aud` of global access tokens (the global server's `JWT_AUDIENCE`). Turns on token exchange at `POST /oauth/token`. Empty answers 404 |
| `GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE` | empty | `aud` of global MCP agent access tokens. Turns on agent token exchange at `POST /oauth/token` (MCP authorization server `token_endpoint`; `POST /oauth/mcp/token` is the same handler). Empty answers 404 |
| `PROVISIONING_PUBLIC_KEY` | empty | Dashboard provisioning public key (PEM), region role. Empty turns the provisioning API off |
| `PROVISIONING_KEY_ID` | empty | Expected assertion `kid` when set |
| `PROVISIONING_ISSUER` | empty | Expected assertion `iss` (the dashboard) |
| `PROVISIONING_AUDIENCE` | host of `JWT_ISSUER` | Expected assertion `aud` |
| `PROVISIONING_DEFAULT_REDIRECTS` | empty | Origins added to each provisioned company's redirect allowlist |
| `STORAGE_SERVICE_URL` | empty | Public storage-service origin (MCP `list_services`). Unset: skipped with a warning for deletion |
| `STORAGE_SERVICE_INTERNAL_URL` | empty | storage-service origin for company-deletion HTTP. Unset uses `STORAGE_SERVICE_URL`. See [Company deletion](company-deletion.md) |
| `HOSTING_SERVICE_URL` | empty | Public hosting-service origin (MCP `list_services`) |
| `HOSTING_SERVICE_INTERNAL_URL` | empty | hosting-service origin for company-deletion HTTP. Unset uses `HOSTING_SERVICE_URL` |
| `SAAS_SERVICE_URL` | empty | saas-service (dashboard) origin for MCP `list_services` |
| `AI_SERVICE_URL` | empty | ai-service origin for MCP connector and `list_services` |
| `AI_SERVICE_ISSUER` | `AI_SERVICE_URL` | Expected `iss` on ai-service downstream token delegation JWTs |
| `AI_SERVICE_JWKS` | empty | Pinned JWKS JSON for ai-service (alternative to fetching `AI_SERVICE_JWKS_URL`) |
| `AI_SERVICE_JWKS_URL` | `{AI_SERVICE_URL}/.well-known/jwks.json` | JWKS URL when `AI_SERVICE_JWKS` is unset |
| `AI_SERVICE_JWKS_TIMEOUT_SECONDS` | `10` | HTTP timeout when fetching ai-service JWKS |
| `STORAGE_SERVICE_ISSUER` | empty | Expected `iss` on internal MCP assertions signed by storage-service. Unset means storage-service is not trusted |
| `STORAGE_SERVICE_JWKS` | empty | Pinned JWKS JSON for storage-service (alternative to fetching `STORAGE_SERVICE_JWKS_URL`) |
| `STORAGE_SERVICE_JWKS_URL` | `{STORAGE_SERVICE_INTERNAL_URL or STORAGE_SERVICE_URL}/.well-known/jwks.json` | JWKS URL when `STORAGE_SERVICE_JWKS` is unset |
| `HOSTING_SERVICE_ISSUER` | empty | Expected `iss` on internal MCP assertions signed by hosting-service. Unset means hosting-service is not trusted |
| `HOSTING_SERVICE_JWKS` | empty | Pinned JWKS JSON for hosting-service (alternative to fetching `HOSTING_SERVICE_JWKS_URL`) |
| `HOSTING_SERVICE_JWKS_URL` | `{HOSTING_SERVICE_INTERNAL_URL or HOSTING_SERVICE_URL}/.well-known/jwks.json` | JWKS URL when `HOSTING_SERVICE_JWKS` is unset |
| `EMAIL_SERVICE_ISSUER` | empty | Expected `iss` on internal MCP assertions signed by email-service. Unset means email-service is not trusted |
| `EMAIL_SERVICE_JWKS` | empty | Pinned JWKS JSON for email-service (alternative to fetching `EMAIL_SERVICE_JWKS_URL`) |
| `EMAIL_SERVICE_JWKS_URL` | `{EMAIL_SERVICE_INTERNAL_URL or EMAIL_SERVICE_URL}/.well-known/jwks.json` | JWKS URL when `EMAIL_SERVICE_JWKS` is unset |
| `INTERNAL_CALLER_JWKS_TIMEOUT_SECONDS` | `10` | HTTP timeout when fetching a caller JWKS |
| `MCP_RATE_LIMIT_DOWNSTREAM_MINT` | `300` | Global per-minute cap on downstream access token mint requests |
| `COMPANY_DELETION_TIMEOUT_SECONDS` | `10` | Timeout of each call to those services |
| `DASHBOARD_WEBHOOK_URL` | empty | saas-service region webhook (`https://<dashboard>/api/v1/webhooks/<region>`) that receives `identity.company.deleted` |
| `DASHBOARD_WEBHOOK_INTERNAL_URL` | empty | Server-to-server URL for that webhook POST. Unset uses `DASHBOARD_WEBHOOK_URL` |
| `DASHBOARD_WEBHOOK_SECRET` | empty | Signing secret for that webhook. Same value as the region's webhook secret in saas-service |
| `DASHBOARD_PUBLIC_URL` | empty | Optional public Shellui dashboard origin (`https://…`, path-less). When set, `GET /api/v1/mcp/personal/status` includes `global_mcp_url` as `{DASHBOARD_PUBLIC_URL}/mcp` for global account MCP discovery. Independent of regional `mcp_url` |

## Related

- [Local dev stack](local-dev-stack.md): sibling-repo compose, public vs internal URLs
- [Run identity-service](getting-started.md): first start and production checklist
- [Security hardening](security-hardening.md)
- [Upgrade notes](upgrading.md)
