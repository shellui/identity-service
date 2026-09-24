# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

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

## [Unreleased] - 2026-09-24

### 🛠 Improvements

- **Runtime concurrency:** Default Gunicorn workers/threads increased to 4/4 to reduce request queueing when OAuth or token refresh holds workers (symptom: even `GET /` hangs with no response).
- **Liveness probe:** `GET /health/live` bypasses session/DB middleware — point load balancers at this path instead of `/`.
- **SQLite:** Enable WAL journal mode on connect for better read/write concurrency on default single-file SQLite deploys.
- **Postgres:** `POSTGRES_CONNECT_TIMEOUT` (default 10s) and `CONN_HEALTH_CHECKS` so stuck DB TCP does not hold workers indefinitely.

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
