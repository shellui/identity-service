---
description: Production security controls in identity-service - rate limits, HTTPS, trusted proxies, CORS, redirects, and sensitive account actions.
---

# Security hardening

With `DEBUG=false`, identity-service turns on HTTPS redirects, HSTS, secure cookies, TLS to PostgreSQL, and rate limits. This page lists those defaults, and the few settings you must adapt to your deployment: trusted proxies and, optionally, CORS.

## Rate limiting

Abuse-prone endpoints are rate limited, with counters in the shared cache (Redis):

| Scope | Default | Endpoints | Variable |
| --- | --- | --- | --- |
| `oauth` | 30 per minute per IP | `/api/v1/authorize`, OAuth callback, confirm, exchange, provider login | `AUTH_RATE_LIMIT_OAUTH` |
| `token_refresh` | 60 per minute per IP | `POST /api/v1/token?grant_type=refresh_token` | `AUTH_RATE_LIMIT_TOKEN_REFRESH` |
| `auth_settings` | 30 per minute per IP | `GET /api/v1/settings` | `AUTH_RATE_LIMIT_SETTINGS` |
| `magic_link` | 10 per minute | `POST /api/v1/magic-link/request`, per IP, per email, and per company | `AUTH_RATE_LIMIT_MAGIC_LINK` |
| `invitation` | 30 per 5 minutes per company | `POST /api/v1/invitations` | `AUTH_RATE_LIMIT_INVITATION` |
| `admin_login` | 10 per 5 minutes per IP | `POST /admin/login/` | `AUTH_RATE_LIMIT_ADMIN_LOGIN` |
| `pat` | 30 per minute per user | `GET` and `POST /api/v1/personal-access-tokens`, revoke | `AUTH_RATE_LIMIT_PAT` |

`AUTH_RATE_LIMIT_ENABLED=false` turns all limits off. Do not do this in production.

## HTTPS and cookies

With `DEBUG=false`, these settings default to on. Each can be overridden with an environment variable of the same name (see `.env.example`):

| Setting | Default in production |
| --- | --- |
| `SECURE_SSL_REDIRECT` | `true`: redirects HTTP to HTTPS. Turn it off only behind a TLS proxy that already redirects |
| `SECURE_HSTS_SECONDS` | `31536000` (one year), with `SECURE_HSTS_INCLUDE_SUBDOMAINS=true` |
| `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` | `true` |
| `POSTGRES_SSL_REQUIRE` | `true` when `POSTGRES_DATABASE_URL` is set. Turn it off only for a local PostgreSQL without TLS |

## Trusted proxies and client IP

Rate limits and the sign-in [event log](event-log.md) use the client IP. By default it is `REMOTE_ADDR`, so a client cannot fake its IP with an `X-Forwarded-For` header.

Behind a reverse proxy (Traefik, Coolify, nginx), list the proxy in `TRUSTED_PROXY_IPS` (IPs or CIDR ranges, comma-separated). When the direct peer is trusted, identity-service reads `X-Forwarded-For` from the right, skips trusted hops, and uses the first untrusted address. A fake address added by the client on the left is ignored.

```bash
# nginx on the same host
TRUSTED_PROXY_IPS=127.0.0.1,::1

# private load balancer subnet
TRUSTED_PROXY_IPS=10.0.0.0/8
```

With Coolify or Traefik, list the Traefik container or ingress subnet.

## CORS (browser API calls)

Shellui shells run on many domains, and call public `/api/v1/*` endpoints from the browser before they have a token. A fixed `CORS_ALLOWED_ORIGINS` list cannot follow multi-tenant hosting, so the default is permissive:

| Setup | Settings |
| --- | --- |
| Default (recommended) | `CORS_ALLOW_ALL_ORIGINS=true` with `CORS_ALLOW_CREDENTIALS=false`. The API uses Bearer tokens in the `Authorization` header, not cookies |
| Locked down | `CORS_ALLOW_ALL_ORIGINS=false`, and first-party origins in `CORS_ALLOWED_ORIGINS` |
| Refused | `CORS_ALLOW_ALL_ORIGINS=true` with `CORS_ALLOW_CREDENTIALS=true`: startup fails, because any origin could then send credentials |

CORS does not control where tokens go after sign-in. The company [redirect allowlist](oauth-login.md#redirect-allowlist) is the strict boundary for `redirect_to` and the one-time code exchange.

## OAuth redirects

Loopback redirect targets (`127.0.0.1`, `localhost`, `::1`) are allowed only with `DEBUG=true` or `OAUTH_ALLOW_LOOPBACK_REDIRECTS=true`. In production, add the real shell origins to the company redirect allowlist.

`GET /api/v1/settings` returns only provider slugs and feature flags to anonymous callers. OAuth client IDs and labels are included only for signed-in members of the company.

## Account deletion

`DELETE /api/v1/user` refuses personal access tokens and the last owner of a company, and requires a recent sign-in: the token's `auth_time` must be within `SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE` (5 minutes by default). A token refresh keeps `auth_time`, so the user must sign in again. See [Account deletion](account-deletion.md).

## Personal access tokens

New PATs last 30 days by default (`PERSONAL_ACCESS_TOKEN_LIFETIME`). Changing the value does not shorten tokens already issued: they keep their expiry until they expire or are revoked. See [Metrics and access tokens](metrics.md).

## Related

- [Configuration](configuration.md): every environment variable
- [JWT and JWKS](jwks.md): signing keys and verification
- [SAML single sign-on](saml.md#security): assertion checks
