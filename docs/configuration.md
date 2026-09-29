# Configuration

Operators configure identity-service with environment variables (see [`.env.example`](https://github.com/shellui/identity-service/blob/main/.env.example) in the repository root). Copy it to `.env` for local runs; pass the same keys to Docker, Coolify, or your orchestrator in production.

Published docs: [https://identity.docs.shellui.com](https://identity.docs.shellui.com) (GitHub Pages `cname` on release tags).

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

Links are built from **`JWT_ISSUER`** (HTTPS when `DEBUG=false`). See [magic-link.md](magic-link.md).

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
| `GET /health/live` | — | **Liveness probe** — no session/DB; use for load balancers (not `/` alone) |

SQLite uses WAL mode on connect for better single-node concurrency (v0.5.1+).

---

## Gunicorn (Docker entrypoint)

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `GUNICORN_WORKERS` | `4` | Sync worker processes |
| `GUNICORN_THREADS` | `4` | Threads per worker (`gthread` worker class) |
| `GUNICORN_TIMEOUT` | `60` | Worker request timeout (OAuth may use long outbound HTTP) |

Concurrency ≈ `workers × threads`. Under-provisioned pools can queue even simple requests when OAuth holds workers.

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

## Shared cache (Redis, `develop` / v0.6.0+)

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

## Enterprise SCIM (`develop` / v0.6.0+)

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
| `SENTRY_DSN`, `SENTRY_ENVIRONMENT`, `SENTRY_RELEASE`, `SENTRY_TRACES_SAMPLE_RATE` | Optional error reporting |
| `EMAIL_*`, `DEFAULT_FROM_EMAIL` | SMTP for company access notifications ([company-access.md](company-access.md)) |
| `ACTIONS_WEBHOOK_TIMEOUT_SECONDS` | Webhook POST timeout (default `5`) — see [actions.md](actions.md) |
| `ACTIONS_OUTBOX_MAX_ATTEMPTS` | Outbox delivery retries (default `8`) |
| `ACTIONS_WEBHOOK_ALLOW_PRIVATE` | Allow webhooks to private IPs (default `false`) |
| `ACTIONS_WEBHOOK_RETRY_LEASE_SECONDS` | Retry worker lease (default `120`) |
| `ACTIONS_WEBHOOK_DISPATCH_WORKERS` | Post-commit delivery thread pool size (default `4`) |
| `MAGIC_LINK_EMAIL_DEFAULT_LANGUAGE` | Magic-link email locale fallback (default `en`) |

---

## Related

- [Introduction](index.md)
- [OAuth login](oauth-login.md)
- [Releases](RELEASES.md)
