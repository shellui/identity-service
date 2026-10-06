# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

<!---
## [Unreleased] - yyyy-mm-dd

### ✨ Feature – for new features
### 🛠 Improvements – for general improvements
### 🚨 Changed – for changes in existing functionality
### ⚠️ Deprecated – for soon-to-be removed features
### 📚 Documentation – for documentation update
### 🗑 Removed – for removed features
### 🐛 Bug Fixes – for any bug fixes
### 🔒 Security – in case of vulnerabilities
### 🏗 Chore – for tidying code

See for sample https://raw.githubusercontent.com/favoloso/conventional-changelog-emoji/master/CHANGELOG.md
-->

## [0.7.0] - 2026-10-06

### 🐛 Bug Fixes

- **No more endless sign-in requests from a slow mail server:** SMTP now gives up after `EMAIL_TIMEOUT` seconds (default 10). Before, Django waited with no limit, so a company access email sent during an OAuth callback could hold the sign-in request forever.
- **Postgres deadlines:** queries are cancelled after `POSTGRES_STATEMENT_TIMEOUT` seconds (default 15) and lock waits after `POSTGRES_LOCK_TIMEOUT` seconds (default 5). Set either to `0` to turn it off. They are not applied to `migrate` and have no effect on SQLite.

### 🛠 Improvements

- **Logs you can see in production:** gunicorn now writes access and error logs to stdout, and each access line ends with the request duration and request id. Django errors and warnings (500s, `DisallowedHost`, CSRF failures) are printed to stdout also when `DEBUG=false`. App log level is set with `LOG_LEVEL`.
- **Request id:** every response carries an `X-Request-ID` header (taken from the incoming request when present, otherwise generated), and every log line includes it as `[req=<id>]`, like the other Shellui services.
- **Slow request warning:** requests slower than `SLOW_REQUEST_THRESHOLD_SECONDS` (default 2) are logged as a warning with method, path, status and duration.
- **Graceful shutdown:** the entrypoint drops privileges with `setpriv` instead of `runuser`. `runuser` killed gunicorn 2 seconds after `docker stop`, which cut `GUNICORN_GRACEFUL_TIMEOUT` short. The entrypoint now passes `SIGTERM` to gunicorn and the worker, and exits when either one exits, so Docker or Coolify restarts the container.
- **Gunicorn:** heartbeat file in `/dev/shm`, workers recycled after `GUNICORN_MAX_REQUESTS` (default 1000) plus up to `GUNICORN_MAX_REQUESTS_JITTER` (default 200) requests, `GUNICORN_GRACEFUL_TIMEOUT` (default 30) and `GUNICORN_KEEP_ALIVE` (default 75).

### 📚 Documentation

- **Docs move to docs.shellui.com/identity:** [shellui/shellui](https://github.com/shellui/shellui) now builds and publishes these docs. This repository no longer deploys a docs site on tags: `deploy-docs.yml`, `tools/docusaurus/` and `tools/generate-docs.sh` are removed, and the sidebar moved to `docs/sidebars.js` (now with n8n and SAML). CI gains a **Docs build** job that builds `docs/` with the shellui docs site and fails on broken links.
- `GUNICORN_TIMEOUT` does not kill a worker whose `gthread` threads are stuck. The docs now say so and list the app timeouts that do bound a request.

### ✨ Feature

- **Scheduled jobs run inside the container:** the Docker image now starts a Celery worker with an embedded beat next to gunicorn. It runs `retry_webhooks` every minute and `purge_expired_data` every hour (at most 5 minutes per run), with Redis (`REDIS_URL`) as the broker. Self-hosted installs no longer need cron or Coolify Scheduled Tasks. A Redis lock skips a run when another container already runs the same job, so replicas are safe. New variables: `SCHEDULER_ENABLED` (default `true`), `CELERY_BROKER_URL` (defaults to `REDIS_URL`) and `CELERY_WORKER_CONCURRENCY` (default `2`). With `DEBUG=true` and no `REDIS_URL`, the container logs a warning and starts the web app only (in production Redis is required, see Changed). The management commands still work for external cron. See [docs/scheduled-jobs.md](docs/scheduled-jobs.md).
- **Scheduled job monitoring:** every `retry_webhooks` and `purge_expired_data` run is recorded, whether the in-container beat (`trigger=celery`) or your own cron (`trigger=command`) started it: status, duration, items processed (deliveries attempted, succeeded, failed, given up; rows purged per type) and a sanitized error. Runs are kept 7 days. Staff get `GET /api/v1/scheduled-jobs` (health per job: `healthy`, `overdue`, `failing`, `disabled`, plus `scheduler_enabled`, `redis_reachable` and a beat heartbeat), `GET /api/v1/scheduled-jobs/<job>/runs` and `GET /api/v1/scheduled-jobs/runs/<id>`; company owners get 403. `GET /api/v1/metrics/all` adds `shellui_auth_scheduled_job_*` metrics (runs, items, last success, last duration, overdue). Each run writes a staff-only platform event (`identity.scheduled_job.succeeded` or `.failed`, `GET /api/v1/events?scope=platform`) that webhook and email rules cannot subscribe to. Webhook delivery attempts now carry `trigger` (`dispatch` or `automatic_retry`) and, for staff, the `scheduled_job_run_id` that made them; email-service event posts keep the run of their last attempt and receive `X-Request-ID: sjr-<run id>`. A failed run logs at ERROR with `[req=sjr-<run id>]`, goes to Sentry when configured, and makes the command exit with status 1. See [docs/scheduled-jobs.md](docs/scheduled-jobs.md#monitoring).
- **Container modes:** the image command selects what runs: `web` (default), `worker` (only the scheduled jobs, for a dedicated container) or any other command, run as `appuser`.
- **Email-service delivery:** magic-link and invitation emails go through Shellui email-service when `EMAIL_SERVICE_API_KEY` is set, with SMTP as fallback, and catalog events are forwarded through the webhook outbox. See [docs/email-service.md](docs/email-service.md).
- **Event log and data retention:** all catalog events and sign-ins are stored in one event log (`GET /api/v1/events`), purged per company `data_retention_days` by `manage.py purge_expired_data`. See [docs/event-log.md](docs/event-log.md) and [docs/scheduled-jobs.md](docs/scheduled-jobs.md).
- **Invitations:** staff and company owners can invite, list, revoke, and delete email invitations (`/api/v1/invitations`), with `identity.user.invited` and `identity.user.invitation_revoked` webhooks. See [docs/company-access.md](docs/company-access.md#invitations).
- **Broadcast audience:** `GET /api/v1/users/audience` lists company members for email broadcasts, filtered by groups, roles, access, join date, and last seen.
- **User management:** staff and company owners can remove a user from their company (`DELETE /api/v1/users/<id>`), and users can edit their display name (`PATCH /api/v1/user`).
- **Magic link:** `POST /api/v1/magic-link/request` accepts a `language`, and the `identity.auth.magic_link.requested` webhook notifies you of each request. See [docs/magic-link.md](docs/magic-link.md).
- **SAML 2.0 SSO:** multiple SAML IdPs per company, with SP metadata, ACS, login, and optional SLO under `/api/v1/saml/<organization_slug>/`. See [docs/saml.md](docs/saml.md).
- **More OAuth providers:** Twitch, LinkedIn, Slack, generic OpenID Connect, Keycloak, Okta, and Auth0 (**15** supported providers plus SAML), with a provider catalog API (`GET /api/v1/oauth-provider-catalog`) and django-allauth 65.19.5. See [docs/oauth-providers.md](docs/oauth-providers.md).

### 🚨 Changed

- **Breaking: Redis is required in production.** With `DEBUG=false` (the Docker image default), the container now refuses to start without `REDIS_URL`: in `web` and `worker` mode the entrypoint logs `REDIS_URL is required when DEBUG is false (example: redis://redis:6379/0)` and exits with status 1, before migrations. This applies also with `SCHEDULER_ENABLED=false` or `CELERY_BROKER_URL` set, because Redis backs the shared cache (auth rate limits, logout access-token denylist, OAuth PKCE state, SAML replay protection) as well as the scheduled jobs. Before, the container only logged a warning and ran with a per-process cache. **Deployments without Redis must add a Redis service and set `REDIS_URL` before upgrading.** `manage.py check --deploy` reports the same problem as the new error `authapi.E004`, which replaces the `authapi.W002` warning. With `DEBUG=true` (local development) Redis stays optional. Other container commands (for example `python manage.py createsuperuser`) are not blocked. See [docs/configuration.md](docs/configuration.md#shared-cache-redis).
- **Account deletion:** self-service deletion only leaves the token company when the user belongs to others, accounts are deleted only once no company link remains, and a company's last owner cannot be removed (`last_company_owner`, `company_owner_required`).
- **No sign-in lock-out:** the Admin API refuses (`login_method_required`) to disable a company's last sign-in method.
- **Magic link:** the verify page signs in without a confirmation click, and new users get a username from their email.
- **Names on sign-in:** OAuth and SAML sign-ins never overwrite an existing user name.
- **OAuth provider catalog v2:** structured `console_url` entries and a language-neutral settings schema; `supported` now follows strict adapter test coverage.

### ⚠️ Deprecated

- `GET /api/v1/login-events` now reads from the event log; use `GET /api/v1/events?event_type=identity.auth.login.succeeded,identity.auth.login.failed` instead.

### 📚 Documentation

- [docs/oauth-providers.md](docs/oauth-providers.md) is generated from the provider catalog, with a CI drift check.

### 🗑 Removed

- The `LoginEvent` model: migration `actions.0005` copies the last 7 days of sign-ins into the event log, and old `/login-events/<id>` links no longer resolve.

### 🐛 Bug Fixes

- **Group events:** group changes made through the admin API and Django admin now emit `identity.group.*` events, so webhooks fire for them.

### 🔒 Security

- **Magic-link webhooks no longer carry the sign-in link (breaking change):** the `identity.auth.magic_link.requested` webhook payload no longer contains `magic_link_url`, the token, or anything else that can be used to sign in, and identity always sends the sign-in email itself, even when the company has a webhook rule for this event. Before, anyone who could read the webhook or its delivery records (for example a company owner) could sign in as the user who owns that email. Migration `actions.0007` removes links already stored in webhook delivery records. If you used the webhook link to deliver magic links yourself (for example from n8n), that no longer works: identity sends the email and the webhook is a notification only.
- **No magic links for staff accounts:** staff (`is_staff`) and superuser accounts can no longer sign in with a magic link. A company that sends mail through its own provider (Resend or SMTP) can read every sign-in link in that provider's dashboard or logs, so a link for a staff member signing in to that company let the company sign in as that staff member. A request for a staff address creates no token and sends a short notice instead (built-in email-service template `identity.auth.magic_link.staff_blocked`, or the EN and FR SMTP templates): magic links are off for staff accounts, sign in with your password or SSO, and a link to the sign-in page, with no token. The API answer and the `identity.auth.magic_link.requested` webhook are the same as for any other address, so neither reveals staff accounts. Verify refuses a token that belongs to a staff account with **403** `magic_link_staff_disabled` (the browser page explains it in English or French), saving an account as staff deletes its unused tokens, and migration `authapi.0017` deletes unused tokens of existing staff accounts. Password sign-in to Django admin and OAuth, OIDC and SAML sign-in are unchanged. See [Staff accounts](docs/magic-link.md#staff-accounts).
- **Company metrics show only that company:** `GET /api/v1/metrics` returned the whole process registry to company owners: process and Python runtime metrics, platform-wide user counts (`shellui_auth_users_*`, `shellui_auth_*_active_users`, as of the last global scrape), `shellui_auth_successful_logins_total` for every company and provider, and the `shellui_auth_company_*` gauges of every other company that process had served. It now builds the response per request with only the token's company series (same metric names and labels, so dashboards keep working). Staff calling it get the same company view. Everything else stays on `GET /api/v1/metrics/all` (staff or `access_global_metrics` token). See [Metrics](docs/metrics.md).
- **No sign-in secrets in logs:** the gunicorn access log records the path without the query string and no longer records the Referer, so magic-link tokens, OAuth codes, `confirm_token` and `setup_token` stay out of the logs. The token refresh log line keeps only the Referer path, and Sentry events drop query strings, request bodies, the Referer and secret-named local variables.
- **Staff flags only in Django admin:** `is_staff` and `is_superuser` can only be changed in Django admin. `PUT /api/v1/users/<id>` no longer accepts `is_staff` and returns **400** `admin_only_field` when the body contains `is_staff` or `is_superuser`.
- **SAML:** signed assertions only, single-use `InResponseTo` and assertion IDs, company-scoped IdPs, and no email auto-linking outside trusted verified domains.
- **OAuth identity:** id_tokens are verified (Google, Apple, OpenID Connect, Okta, Auth0), account ids are scoped by issuer or host, and company IdPs never auto-link by email.
- **OAuth transport:** pinned provider hosts, SSRF-safe HTTP and discovery, server-side PKCE, atomic state consumption, and redacted secrets in API responses.
- **Account id migrations:** `0014` (OpenID Connect) and `0015` (GitLab) rekey existing social accounts; run `manage.py scope_gitlab_social_uids` if `0015` reports ambiguous rows.

## [0.6.0] - 2026-09-29

### ✨ Feature

- **SCIM 2.0 provisioning:** Sync users and groups (including nested groups) from your identity provider at `/api/v1/companies/<company_id>/scim/v2/`. Create a SCIM token in Shellui admin to turn it on for a company, and revoke it to turn it off. See [docs/scim.md](docs/scim.md).
- **Magic link sign-in:** Passwordless email login, on by default for new companies created after upgrade (existing companies stay off until enabled). Toggle it per company with `/api/v1/auth-methods`. Emails ship in English and French. See [docs/magic-link.md](docs/magic-link.md).
- **Webhook actions:** Send `identity.*` events (users, groups, SCIM, magic link) to your own endpoints, such as n8n. Payloads are signed, failed deliveries retry with backoff via `manage.py retry_webhooks`, and admins can send a test event or re-queue deliveries. Closes [#35](https://github.com/shellui/identity-service/issues/35). See [docs/actions.md](docs/actions.md) and [docs/n8n.md](docs/n8n.md).
- **Account deletion:** Users can delete their own account with `DELETE /api/v1/user`, which also revokes their sessions and tokens.
- **Redis cache:** Set `REDIS_URL` to share rate limits, logout denylist, and last-seen data across workers.

### 🛠 Improvements

- **Faster Google sign-in:** Skip the account confirmation page for providers listed in `OAUTH_SKIP_CONFIRM_PROVIDERS` (default `google`).
- **Homepage:** Shellui Identity branding, aligned with the other Shellui services.
- **Django admin:** Browse webhook deliveries and attempts with filters and search.
- **Deploy check:** `authapi.W002` warns when several Gunicorn workers run without Redis.

### 🚨 Changed

- **Company groups:** Groups are either `manual` (managed in admin) or `scim` (managed by your identity provider). Name collisions between the two return **409**.
- **JWT `groups` claim:** Now includes nested parent groups, not only direct memberships.

### 📚 Documentation

- Docs site moved to `identity.docs.shellui.com` with Shellui styling (since replaced by [docs.shellui.com/identity](https://docs.shellui.com/identity)).
- New guides for [SCIM](docs/scim.md), [magic link](docs/magic-link.md), [actions](docs/actions.md), [n8n](docs/n8n.md), and [OAuth providers](docs/oauth-providers.md). Refreshed [configuration](docs/configuration.md) and publish guides.

### 🔒 Security

- **Webhook targets:** Private and loopback addresses are blocked, and delivery connects to the checked IP to prevent DNS rebinding. Non-global addresses (including CGNAT `100.64.0.0/10`) are rejected. Changing a webhook URL clears a superuser-only private-URL allowance.
- **SCIM:** Company SCIM tokens can no longer change global email, username, or password for users shared across companies or for staff accounts. Duplicate-email user creation returns a generic SCIM uniqueness error.
- **SCIM (review 2):** PATCH and PUT cannot copy another user's email. Locked users reject any email or userName change (exact match, including case and spacing). Orphan and internal provisioner accounts cannot be linked via SCIM POST. User and group filters are scoped on company membership with safe SQL precedence. SCIM deprovisioning revokes company-scoped refresh sessions and personal access tokens. Disabled company owners lose admin API access. Admin user PATCH cannot modify SCIM-managed groups. OAuth sign-in uses case-insensitive email lookup when duplicate rows exist. Run `manage.py report_duplicate_emails` to find conflicting addresses.
- **Magic link:** Sign-in links are redeemed with a single atomic update; only a hash of the token is stored. Per-company request rate limits no longer block other clients.
- **Self-service account deletion:** `DELETE /api/v1/user` rejects personal access tokens, requires a recent interactive sign-in (`auth_time` within `SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE`, default 5m; refresh keeps the original `auth_time`), and returns **409** when the user still belongs to more than one company.
- **Client IP behind proxies:** With `TRUSTED_PROXY_IPS` set, audit and rate limits use the rightmost untrusted `X-Forwarded-For` hop instead of the client-controlled leftmost entry.
- **Client IP edge cases:** IPv4-mapped proxy addresses match `TRUSTED_PROXY_IPS` CIDRs, `X-Forwarded-For` hops are normalized (ports, brackets, invalid entries), and IPv6 rate limits bucket by /64 while audit logs keep the full address.
- **Webhook SSRF:** NAT64, 6to4, and IPv4-compatible literal addresses are checked against the embedded IPv4 target.
- **OAuth account linking:** Shellui links social accounts by provider user id first. Email is used to find an existing user only when the provider proves the address (Google `email_verified`, GitHub verified primary email, Microsoft `xms_edov` or a dedicated tenant). Case-insensitive email lookup tolerates duplicate rows (lowest pk wins). OAuth `state` is bound to an HttpOnly cookie nonce and is single-use.
- **Magic link hardening:** Webhook payloads include `user_id` and locale fields only when the user already belongs to that company. Browser verify uses GET for confirmation and POST to consume the token. Plain-text email templates preserve query string characters in sign-in links.
- **Dependencies:** Pin `html2text` to the lockfile version for reproducible installs outside Docker.

## [0.5.1] - 2026-09-24

### 🛠 Improvements

- **Runtime concurrency:** Default Gunicorn workers/threads increased to 4/4 to reduce request queueing when OAuth or token refresh holds workers (symptom: even `GET /` hangs with no response).
- **Liveness probe:** `GET /health/live` bypasses session/DB middleware — point load balancers at this path instead of `/`.
- **SQLite:** Enable WAL journal mode on connect for better read/write concurrency on default single-file SQLite deploys.
- **Postgres:** `POSTGRES_CONNECT_TIMEOUT` (default 10s) and `CONN_HEALTH_CHECKS` so stuck DB TCP does not hold workers indefinitely.

## [0.5.0] - 2026-09-18

### 🛠 Improvements

- **Production CORS:** `CORS_ALLOW_ALL_ORIGINS=true` is allowed when `DEBUG=false` and `CORS_ALLOW_CREDENTIALS=false` (default). Multi-tenant shells on unknown domains can call Bearer JWT APIs without per-origin env lists. The unsafe combo allow-all + credentials still fails at startup.

### 🔒 Security

- **Production JWT/env defaults (H-05, M-03, M-12):** `JWT_ACCEPT_HS256_LEGACY` defaults to `false` when RS256 is configured and `DEBUG=false`. Production requires `JWT_ISSUER` and `JWT_AUDIENCE` (startup check). `.env.example` uses placeholder secrets only.
- **Refresh token rotation and revocation (H-02):** refresh JWTs are registered server-side (`RefreshTokenSession`). Token refresh rotates the pair and revokes the previous refresh; logout revokes the session and denylists the current access token `jti`. Reuse of a revoked refresh revokes the whole token family.
- **OAuth session code delivery (H-03):** default login delivery is a one-time `shellui_auth_code` query parameter exchanged via `POST /api/v1/oauth/session` instead of URL-fragment tokens. Legacy fragment delivery remains available with `token_delivery=fragment` on authorize or `OAUTH_TOKEN_DELIVERY=fragment`.
- Gate public first-run superuser bootstrap at `/`: disabled when `DEBUG=false` unless a valid `SETUP_TOKEN` is provided. Production installs should use `manage.py createsuperuser` or a one-time `SETUP_TOKEN` URL.
- **Hosting redirect sync (H-04):** `PUT`/`DELETE /api/v1/hosting-oauth-redirects` now requires a staff or company-owner JWT. Regular enabled members can no longer widen the OAuth redirect allowlist via hosting sync.
- **Auth rate limits (M-02):** OAuth, token refresh, auth settings, Django admin login, and PAT CRUD endpoints are throttled per IP (or per user for PATs). See [docs/security-hardening.md](docs/security-hardening.md).
- **Legacy OAuth redirect_uri (H-01):** legacy OAuth `redirect_uri` endpoints now use the same company redirect allowlist as primary `redirect_to` (PR #15).
- **Loopback OAuth (M-04):** `redirect_to` loopback targets require `DEBUG=true` or `OAUTH_ALLOW_LOOPBACK_REDIRECTS=true`.
- **Settings enumeration (M-06):** `GET /api/v1/settings` omits OAuth client IDs/labels unless the caller is an authenticated company member.
- **Transport hardening (M-07/M-08):** Production defaults enable SSL redirect, HSTS, and secure session/CSRF cookies; Postgres uses `ssl_require` when `DEBUG=false`.
- **Trusted proxies (M-09):** `X-Forwarded-For` is honored for audit/rate-limit IP only when `REMOTE_ADDR` matches `TRUSTED_PROXY_IPS`.
- **PAT lifetime (M-10):** Default new personal access token lifetime is **30 days** (was 90). Existing JWTs keep their issued expiry.

### 🚨 Changed

- **CORS:** `CORS_ALLOW_ALL_ORIGINS` defaults to `true` (Bearer JWT auth; credentials off). Lock-down installs set `CORS_ALLOW_ALL_ORIGINS=false` and `CORS_ALLOWED_ORIGINS`.
- **JWT claims:** Tokens include `iss`/`aud` when `JWT_ISSUER` / `JWT_AUDIENCE` are set; both are required at startup when `DEBUG=false`.
- **Breaking (Shell clients):** after OAuth login, shells must exchange `shellui_auth_code` at `/api/v1/oauth/session` unless they opt into legacy fragment delivery. Existing refresh tokens issued before this release are rejected until users sign in again.

### 📚 Documentation

- Document production JWT issuer/audience, HS256 legacy default, and CORS lock-down in [docs/jwks.md](docs/jwks.md), [README.md](README.md), [PUBLISH.md](PUBLISH.md), and [docs/oauth-login.md](docs/oauth-login.md).
- Updated [docs/oauth-login.md](docs/oauth-login.md) with session-code flow and migration notes.
- Add [docs/security-hardening.md](docs/security-hardening.md); update `.env.example` and [docs/oauth-login.md](docs/oauth-login.md).

## [0.4.1] - 2026-09-07

### ✨ Feature

- **Hosting redirect sync:** `PUT`/`DELETE /api/v1/hosting-oauth-redirects` (caller's identity JWT, forwarded by hosting-service) upserts/removes `source=hosting` allowlist origins when preview sites are created or deleted. Any enabled company member may sync; company scope comes from the JWT. Admin OAuth setup lists hosting origins separately from manual ones. Owner `POST /api/v1/oauth-redirects` may set `source=hosting` (e.g. one-click repair from hosting admin).

### 🚨 Changed

- **Permissive API CORS:** default `CORS_ALLOW_ALL_ORIGINS=true` with `CORS_ALLOW_CREDENTIALS=false` (Bearer JWT auth, Supabase-style). Random hosting preview origins no longer need CORS env entries. OAuth `redirect_to` allowlist remains the strict boundary for token delivery. Removed `ShelluiCorsMiddleware` (stock `corsheaders` middleware).

### 📚 Documentation

- Document hosting redirect sync and CORS vs redirect allowlist in [README](README.md) and [docs/oauth-login.md](docs/oauth-login.md).
- Refresh [PUBLISH.md](PUBLISH.md) and [docs/RELEASES.md](docs/RELEASES.md) examples for `0.4.1`.

## [0.4.0] - 2026-09-03

### ✨ Feature

- **Identity-hosted OAuth login:** authorize and callback live on identity-service (`/api/v1/authorize`, `/api/v1/oauth/callback`) with a fixed provider redirect URI and signed `state` that carries the shell or CLI `redirect_to` target.
- **Per-company redirect allowlist:** `CompanyOAuthRedirect` rows restrict non-loopback bounce targets; loopback (`127.0.0.1` / `localhost`) is always allowed for CLI login. CRUD at `/api/v1/oauth-redirects` plus Django admin.
- **Sign-in method picker:** when `/api/v1/authorize` is called without `provider`, identity shows a method-selection page (even when only one provider is enabled) before redirecting to the IdP.
- **Account confirmation:** after the provider returns, users confirm the resolved account (or switch provider / same-provider account) before JWTs are issued to `redirect_to#access_token=…`.

### 🛠 Improvements

- In Coolify / Docker secret UIs, paste **only the PEM** (quotes stripped).

### 🐛 Bug Fixes

- `generate_jwt_keys --shell` now prints `export` lines for `eval` (used by pre-release smoke tests).

### 🔒 Security

- Bump dependencies to clear `pip-audit` findings: Django `6.0.8`, cryptography `50.0.0`, django-allauth `65.14.1`, djangorestframework `3.17.2`, requests `2.33.0`.

### 🏗 Chore

- Add GitHub Actions CI on PRs and `main`/`develop`: Django tests, `uv lock --check`, `pip-audit`, gitleaks, lychee link checks, and Docker build.
- Automate PUBLISH.md pre-release checklist via `./tools/pre-release-check.sh` and `.github/workflows/pre-release.yml` (PRs to `main`).

### 📚 Documentation

- Document identity-hosted OAuth and redirect allowlist ([docs/oauth-login.md](docs/oauth-login.md)); fix README provider callback guidance.
- Add Shellui brand favicon (ICO + PNG sizes) to the Docusaurus docs site.
- Sync embedded Swagger UI and ReDoc light/dark mode with shellui appearance (native Swagger UI dark mode and Redoc presets).

## [0.3.0] - 2026-08-16

### ✨ Feature

- **Company access modes:** per-company join rules (`public`, `domain`, or `invite`) with membership `is_enabled`, admin/API controls, owner/user email notifications, and OAuth `access_pending` / `access_denied` responses ([docs/company-access.md](docs/company-access.md)).

### 🛠 Improvements

- Switched dependency management from `requirements.txt` / pip to [uv](https://docs.astral.sh/uv/) (`pyproject.toml` + `uv.lock`). Docker installs with `uv sync --frozen`.
- App `VERSION` (OpenAPI / Sentry release) is read from `project.version` in `pyproject.toml`.

### 🚨 Changed

- Local setup uses `uv sync` / `uv run` instead of `pip install -r requirements.txt`.

### 📚 Documentation

- Updated README, JWKS, and publish guides for uv-based install and Django commands.

## [0.2.0] - 2026-06-27

### ✨ Feature

- RS256 JWT signing with a public JWKS endpoint so other services can verify tokens without sharing secrets.
- Optional Sentry error reporting via `SENTRY_DSN` (Django exceptions and `ERROR`-level logs).

### 🚨 Changed

- OAuth credentials are configured per company; global GitHub, Google, and Microsoft environment variables are removed.
- JWT access and refresh token lifetimes are configurable via `JWT_ACCESS_TOKEN_LIFETIME` and `JWT_REFRESH_TOKEN_LIFETIME` (defaults `5m` and `7d`).
- Token refresh (`POST /api/v1/token`) accepts a valid `refresh_token` without requiring a Bearer access token.

### 📚 Documentation

- Added [docs/jwks.md](docs/jwks.md) and updated setup guides for JWT keys and OAuth configuration.

## [0.1.0] - 2026-05-23

### ✨ Feature

- Initial release of `identity-service`.
- Added **API scaffolding** for **identity endpoints**.
- Added **configuration** for **local development** and **environment variables**.
- Added project setup for future **authentication** and **user management** workflows.
- Added OAuth login support for GitHub, Google, and Microsoft providers.
- Added JWT session lifecycle endpoints (`/api/v1/token`, `/api/v1/logout`) and authenticated user profile APIs.
- Added staff directory endpoints for users and groups administration workflows.

### 🛠 Improvements

- Added OpenAPI documentation with drf-spectacular integration and improved API tagging.
- Expanded local container workflow with migration-on-start entrypoint.

### 🚨 Changed

- Updated Docker runtime to persist SQLite data at `/app/data/db.sqlite3`.
- Added Docker volume declaration to avoid SQLite reset when the container or VM restarts.

### 📚 Documentation

- Added clearer Docker run examples using a named volume (`identity-service-data`) for persistent data.
