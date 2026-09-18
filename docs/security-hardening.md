# Security hardening (auth abuse & transport)

Production deployments should configure the controls below. Defaults follow `DEBUG=false` unless noted.

## Rate limiting

Cache-backed limits apply to abuse-prone endpoints:

| Scope | Default | Endpoints |
|-------|---------|-----------|
| `oauth` | 30/min per IP | `/api/v1/authorize`, OAuth callback/confirm/exchange, social provider login |
| `token_refresh` | 60/min per IP | `POST /api/v1/token?grant_type=refresh_token` |
| `auth_settings` | 30/min per IP | `GET /api/v1/settings` |
| `admin_login` | 10 per 5 min per IP | `POST /admin/login/` |
| `pat` | 30/min per user | `GET/POST /api/v1/personal-access-tokens`, revoke |

Tune with `AUTH_RATE_LIMIT_*` env vars or set `AUTH_RATE_LIMIT_ENABLED=false` to disable (not recommended in production).

## Loopback OAuth redirects

Loopback targets (`127.0.0.1`, `localhost`, `::1`) are allowed when `DEBUG=true` or `OAUTH_ALLOW_LOOPBACK_REDIRECTS=true`. In production, register real shell origins on the company redirect allowlist instead.

## Auth settings enumeration

`GET /api/v1/settings` returns only provider slugs and feature flags to anonymous callers. OAuth client IDs and labels are included only for authenticated company members.

## HTTPS, HSTS, and secure cookies

When `DEBUG=false`:

- `SECURE_SSL_REDIRECT=true` — redirect HTTP to HTTPS (disable only behind TLS-terminating proxies that handle redirects)
- `SECURE_HSTS_SECONDS=31536000` (1 year)
- `SESSION_COOKIE_SECURE=true`, `CSRF_COOKIE_SECURE=true`

Override any flag via env (see `.env.example`).

## Postgres SSL

When `POSTGRES_DATABASE_URL` is set and `DEBUG=false`, connections use `ssl_require=true` by default. Set `POSTGRES_SSL_REQUIRE=false` only for local Postgres without TLS.

## Trusted proxies and client IP

Login audit and rate limits derive client IP from `REMOTE_ADDR` unless the direct peer is listed in `TRUSTED_PROXY_IPS` (comma-separated IPs or CIDRs). When trusted, the first hop of `X-Forwarded-For` is used.

Example (nginx on the same host):

```bash
TRUSTED_PROXY_IPS=127.0.0.1,::1
```

Example (private load balancer subnet):

```bash
TRUSTED_PROXY_IPS=10.0.0.0/8
```

Without trusted proxies, clients cannot spoof audit IPs by sending `X-Forwarded-For` directly.

## Personal access token lifetime

New PATs default to **30 days** (`PERSONAL_ACCESS_TOKEN_LIFETIME=30d`). Existing issued JWTs keep their original expiry until they expire or are revoked; shortening the default does not retroactively shorten active tokens.

## CORS (browser API calls)

Shellui customer shells run on unknown domains and call public `/api/v1/*` endpoints from the browser **before** a Bearer token exists. A static `CORS_ALLOWED_ORIGINS` list does not scale for multi-tenant hosting.

**Default (recommended):** `CORS_ALLOW_ALL_ORIGINS=true` with `CORS_ALLOW_CREDENTIALS=false`. API auth is Bearer JWT in the `Authorization` header, not cookies — permissive CORS is intentional (Supabase-style).

**Token delivery** after OAuth login is **not** governed by CORS. The `CompanyOAuthRedirect` allowlist remains the strict boundary for `redirect_to` targets and one-time code exchange.

**Lock-down (optional):** set `CORS_ALLOW_ALL_ORIGINS=false` and list first-party origins in `CORS_ALLOWED_ORIGINS`.

**Blocked:** `CORS_ALLOW_ALL_ORIGINS=true` with `CORS_ALLOW_CREDENTIALS=true` — startup fails because wildcard origins cannot safely carry credentials.
