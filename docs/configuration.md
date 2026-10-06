# Configuration

Operators configure identity-service with environment variables (see [`.env.example`](https://github.com/shellui/identity-service/blob/main/.env.example) in the repository root). Copy it to `.env` for local runs; pass the same keys to Docker, Coolify, or your orchestrator in production.

Published docs: [https://docs.shellui.com/identity](https://docs.shellui.com/identity), built from this repository's `docs/` folder by [shellui/shellui](https://github.com/shellui/shellui).

---

## Required in production (`DEBUG=false`)

| Variable | Purpose |
| -------- | ------- |
| `SECRET_KEY` | Django session and CSRF signing (required always) |
| `JWT_PRIVATE_KEY` | RS256 JWT signing PEM (`generate_jwt_keys` management command) |
| `JWT_ISSUER` | `iss` claim on issued JWTs; verifiers should validate |
| `JWT_AUDIENCE` | `aud` claim on issued JWTs |
| `ALLOWED_HOSTS` | Comma-separated hostnames (no scheme) |

Typical browser/OAuth hardening:

| Variable | Purpose |
| -------- | ------- |
| `CSRF_TRUSTED_ORIGINS` | Full HTTPS URLs for admin and OAuth confirmation pages behind TLS |

Details: [JWKS and JWT verification](jwks.md), [Security hardening](security-hardening.md).

---

## JWT and token lifetimes

| Variable | Default / notes |
| -------- | ---------------- |
| `JWT_PUBLIC_KEY`, `JWT_KEY_ID` | Optional; derived from private key when omitted |
| `JWT_PREVIOUS_PUBLIC_KEY`, `JWT_PREVIOUS_KEY_ID` | Optional rotation — previous key stays in JWKS |
| `JWT_ACCEPT_HS256_LEGACY` | `false` in production with RS256; set `true` only while migrating old HS256 tokens |
| `JWT_ACCESS_TOKEN_LIFETIME` | `5m` (supports `s`, `m`, `h`, `d` suffixes) |
| `JWT_REFRESH_TOKEN_LIFETIME` | `7d` |
| `PERSONAL_ACCESS_TOKEN_LIFETIME` | `30d` (default since v0.5.0) |

---

## OAuth token delivery

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `OAUTH_TOKEN_DELIVERY` | `code` | `code` = one-time `shellui_auth_code` + `POST /api/v1/oauth/session`; `fragment` = legacy URL hash tokens |
| `OAUTH_SESSION_CODE_TTL_SECONDS` | `120` | Lifetime of the one-time auth code |
| `OAUTH_ALLOW_LOOPBACK_REDIRECTS` | follows `DEBUG` | Allow `redirect_to` to loopback for CLI/local shells when `true` |
| `OAUTH_SKIP_CONFIRM_PROVIDERS` | `google` when unset | Provider slugs that skip the identity-hosted account confirmation page after callback (comma-separated; empty env disables skips) |

OAuth **account linking** (Shellui `/api/v1/authorize` callback):

- Match an existing user by **provider user id** (`SocialAccount`) first.
- Match by **email** only when the provider proves ownership:
  - **Google:** `email_verified` is true in the userinfo response.
  - **GitHub:** verified **primary** email from `/user/emails`.
  - **Microsoft:** `xms_edov` is true in the ID token, or the OAuth client uses a **dedicated tenant** (not `common`). Shellui does not trust `mail` or `userPrincipalName` from the `common` tenant alone.
- If verification fails, Shellui returns an error and does not attach the sign-in to another user's email.

OAuth **login CSRF:** `/api/v1/authorize` stores a random nonce in the HttpOnly `shellui_oauth_state_nonce` cookie (SameSite=Lax). The callback checks that nonce against signed `state` and rejects reused `state` values.

Flow and allowlist: [OAuth login](oauth-login.md).

---

## Magic link (passwordless email)

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `MAGIC_LINK_ENABLED` | `true` | Global kill switch for magic-link request/verify endpoints |
| `MAGIC_LINK_TTL_SECONDS` | `1800` | One-time link lifetime (seconds) |
| `AUTH_RATE_LIMIT_MAGIC_LINK` | `10` | Requests per minute bucket (per client IP and per email+company) |

Links are built from **`JWT_ISSUER`** (HTTPS when `DEBUG=false`). In local development (`DEBUG=true`) without `JWT_ISSUER`, links fall back to the base URL of the incoming request. See [magic-link.md](magic-link.md).

---

## CORS (browser API calls)

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `CORS_ALLOW_ALL_ORIGINS` | `true` | Bearer JWT APIs from arbitrary shell origins (credentials off) |
| `CORS_ALLOW_CREDENTIALS` | `false` | Must stay `false` with allow-all |
| `CORS_ALLOWED_ORIGINS` | empty | Lock-down: comma-separated origins when allow-all is `false` |
| `CORS_ALLOWED_ORIGIN_REGEXES` | empty | Optional regex allow list |

OAuth **redirect** allowlist (`CompanyOAuthRedirect`) is separate and stricter — see [oauth-login.md](oauth-login.md).

---

## Database and health

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `POSTGRES_DATABASE_URL` | empty | Postgres DSN; omit for SQLite (`SQLITE_PATH` or `/app/data/db.sqlite3` in Docker) |
| `POSTGRES_SSL_REQUIRE` | `true` when not `DEBUG` | TLS to Postgres |
| `POSTGRES_CONNECT_TIMEOUT` | `10` | Seconds; avoids workers stuck on dead TCP |
| `POSTGRES_STATEMENT_TIMEOUT` | `15` | Seconds. Postgres cancels any query that runs longer. `0` turns it off. Not applied to `migrate`. Ignored with SQLite |
| `POSTGRES_LOCK_TIMEOUT` | `5` | Seconds. Postgres gives up waiting for a row or table lock after this. `0` turns it off. Not applied to `migrate`. Ignored with SQLite |
| `GET /health/live` | — | **Liveness probe** — no session/DB; use for load balancers (not `/` alone) |

SQLite uses WAL mode on connect for better single-node concurrency (v0.5.1+).

With Postgres, `CONN_HEALTH_CHECKS` is on, so a connection that died while idle is replaced before the next request uses it.

---

## Gunicorn (Docker entrypoint)

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `GUNICORN_WORKERS` | `4` | Worker processes |
| `GUNICORN_THREADS` | `4` | Threads per worker (`gthread` worker class) |
| `GUNICORN_TIMEOUT` | `60` | Seconds of silence before gunicorn restarts a frozen worker process. See the note below |
| `GUNICORN_GRACEFUL_TIMEOUT` | `30` | Seconds a worker gets to finish open requests on restart or shutdown |
| `GUNICORN_KEEP_ALIVE` | `75` | Seconds an idle keep-alive connection stays open. Keep it above the reverse proxy idle time to avoid random 502s |
| `GUNICORN_MAX_REQUESTS` | `1000` | Restart a worker after this many requests. `0` turns it off |
| `GUNICORN_MAX_REQUESTS_JITTER` | `200` | Random extra requests added to `GUNICORN_MAX_REQUESTS`, so workers do not all restart at once |

Concurrency is about `workers x threads`. Under-provisioned pools can queue even simple requests when OAuth holds workers.

**`GUNICORN_TIMEOUT` does not stop a stuck request.** With the `gthread` worker class, the worker keeps sending heartbeats while one of its threads is blocked (on SMTP, the database or an outbound HTTP call), so gunicorn never kills it. Requests sent to that worker can then wait with no response and no log line. Per-request deadlines come from the app instead: `EMAIL_TIMEOUT`, `POSTGRES_STATEMENT_TIMEOUT`, `POSTGRES_LOCK_TIMEOUT` and the 20 second OAuth HTTP timeouts. Set a response timeout on the reverse proxy as well. `GUNICORN_MAX_REQUESTS` recycles workers over time, which also replaces a worker that still serves some requests.

The entrypoint also sets `--worker-tmp-dir /dev/shm` (heartbeat file in memory, not on the container disk) and writes the gunicorn access and error logs to stdout. Each access log line ends with the request duration and the request id, for example `"GET /api/v1/settings HTTP/1.1" 200 512 "Mozilla/5.0" 182ms req=4f2c9a1e`. The line has the path without the query string and no Referer, because query strings carry magic-link tokens, OAuth codes, `confirm_token` and `setup_token`.

---

## Security, proxies, and rate limits

| Variable | Purpose |
| -------- | ------- |
| `TRUSTED_PROXY_IPS` | Comma-separated IPs/CIDRs; when `REMOTE_ADDR` matches, client IP is the rightmost untrusted hop in `X-Forwarded-For` (see [security-hardening.md](security-hardening.md)) |
| `SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE` | Max age of access JWT `auth_time` (interactive sign-in time) for `DELETE /api/v1/user` (default `5m`; not PATs; refresh preserves `auth_time`) |
| `AUTH_RATE_LIMIT_ENABLED` | `true` — disable only for debugging |
| `AUTH_RATE_LIMIT_OAUTH`, `_TOKEN_REFRESH`, `_SETTINGS`, `_ADMIN_LOGIN`, `_PAT` | Per-endpoint limits (see [security-hardening.md](security-hardening.md)) |
| `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` | HTTPS defaults when `DEBUG=false` |

---

## Shared cache (Redis, v0.6.0+)

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `REDIS_URL` | unset | Django Redis cache backend for auth rate limits, logout access-token denylist, and last-seen throttling |

When unset, Django uses in-process **LocMem** (fine for local dev or a single Gunicorn worker). With **`GUNICORN_WORKERS` > 1**, set `REDIS_URL` so limits and denylists are shared across workers. `manage.py check --deploy` emits **`authapi.W002`** when production uses LocMem with multiple workers.

Examples:

```bash
# Docker Compose / Coolify internal Redis
REDIS_URL=redis://redis:6379/0
```

See [PUBLISH.md](https://github.com/shellui/identity-service/blob/develop/PUBLISH.md) for Coolify Redis setup.

---

## Enterprise SCIM (v0.6.0+)

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `SCIM_ENABLED` | `true` | When `false`, SCIM routes return **404** (emergency kill switch) |

Documented in [SCIM](scim.md). Available on **`develop`** after migrations.

---

## Bootstrap and observability

| Variable | Purpose |
| -------- | ------- |
| `DEBUG` | Development mode; never `true` in production |
| `SETUP_TOKEN` | One-time web superuser bootstrap when `DEBUG=false` (prefer `createsuperuser`) |
| `IDENTITY_SERVICE_PORT` | Local/docker-compose port hint |
| `EMAIL_*`, `DEFAULT_FROM_EMAIL` | SMTP for company access notifications and the email-service fallback ([company-access.md](company-access.md), [email-service.md](email-service.md)) |
| `SENTRY_DSN`, `SENTRY_ENVIRONMENT`, `SENTRY_RELEASE`, `SENTRY_TRACES_SAMPLE_RATE` | Optional error reporting. Sentry starts only when `SENTRY_DSN` is set. No personal data is sent. `SENTRY_TRACES_SAMPLE_RATE` defaults to `0` (errors only); set for example `0.1` to see slow requests |
| `LOG_LEVEL` | Level for app logs on stdout (default `INFO`, or `DEBUG` when `DEBUG=true`). Django errors and warnings (500s, `DisallowedHost`, CSRF failures) are always printed, also when `DEBUG=false` |
| `SLOW_REQUEST_THRESHOLD_SECONDS` | Log a warning for requests slower than this many seconds (default `2`). `0` turns it off |
| `EMAIL_*`, `DEFAULT_FROM_EMAIL` | SMTP for company access notifications and the email-service fallback ([company-access.md](company-access.md), [email-service.md](email-service.md)) |
| `EMAIL_TIMEOUT` | Seconds before an SMTP connect, read or write gives up (default `10`). Without it, a mail server that does not answer can hold a sign-in request forever |
| `EMAIL_SERVICE_URL` | email-service origin (production default `https://email.shellui.com`; local `http://localhost:8003`) |
| `EMAIL_SERVICE_API_KEY` | Service key (`esk_`). Unset keeps SMTP / the console backend |
| `ACTIONS_WEBHOOK_TIMEOUT_SECONDS` | Webhook POST timeout (default `5`) — see [actions.md](actions.md) |
| `ACTIONS_OUTBOX_MAX_ATTEMPTS` | Outbox delivery retries (default `8`) |
| `ACTIONS_WEBHOOK_ALLOW_PRIVATE` | Allow webhooks to private IPs (default `false`) |
| `ACTIONS_WEBHOOK_RETRY_LEASE_SECONDS` | Retry worker lease (default `120`) |
| `ACTIONS_WEBHOOK_DISPATCH_WORKERS` | Post-commit delivery thread pool size (default `4`) |
| `MAGIC_LINK_EMAIL_DEFAULT_LANGUAGE` | Magic-link email locale fallback (default `en`) |

---

## Email service

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `EMAIL_SERVICE_URL` | `https://email.shellui.com` | Origin only. identity-service appends `/api/v1/send` and `/api/v1/events`. Local runs use `http://localhost:8003` (email-service). Containers use `http://host.docker.internal:8003` |
| `EMAIL_SERVICE_API_KEY` | empty | Bearer key issued by email-service. Prefix `esk_` |
| `EMAIL_SERVICE_TIMEOUT_SECONDS` | `5` | Timeout for one HTTP attempt |
| `EMAIL_SERVICE_SEND_ATTEMPTS` | `3` | Attempts for one direct send. Event posts retry on the outbox (8 attempts) |
| `EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS` | `1` | Cap on the pause between direct-send retries |

How the two paths fit together: [Email](email-service.md). email-service `EMAIL_AUTH_LINK_HOSTS` must include the host of `JWT_ISSUER`. `localhost` is kept on that list only while email-service `DEBUG=true`.

---

## Related

- [Email](email-service.md)
- [Introduction](index.md)
- [OAuth login](oauth-login.md)
- [Releases](RELEASES.md)
