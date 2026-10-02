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

## [Unreleased] - 2026-09-29

### ✨ Feature

- **email-service:** magic-link and invitation mail call Shellui email-service `POST /api/v1/send` when `EMAIL_SERVICE_API_KEY` is set (auth templates, stable idempotency keys, TTL 120s and 300s). SMTP remains the path when the key is unset, and the fallback when email-service cannot be reached after the caller retry policy. If both paths fail, the API returns **503** `email_unavailable`. An auth-lane hard bounce returns **422** `recipient_suppressed`. Those JSON bodies contain `error_code` only. Webhook catalog events other than the two direct-send templates are also posted to `POST /api/v1/events` through the existing outbox, retried by `manage.py retry_webhooks`, and do not block the request. See [docs/email-service.md](docs/email-service.md).

- **Event log:** every catalog event (accounts, invitations, SCIM, groups, tokens, magic links) is now stored in one `EventLog` table, with or without a webhook rule, next to sign-ins recorded as `identity.auth.login.succeeded` and `identity.auth.login.failed`. Sign-in events are log-only and cannot trigger webhooks. Rows are compact: empty values dropped, user as a column, secrets such as `magic_link_url` never stored, two indexes only. New admin API: `GET /api/v1/events` (filter by `event_type`, `user_id`, `user` email, date range), `GET /api/v1/events/<id>`, `GET /api/v1/events/types`. See [docs/event-log.md](docs/event-log.md).
- **Data retention:** companies have a `data_retention_days` (default 7), editable in Django admin only and returned read-only by the company API. New `manage.py purge_expired_data` deletes expired event log rows, finished webhook deliveries and SCIM provisioning events in short batches. `GET /api/v1/events/retention` and the Django admin company page report `stale_events` when events are more than one day past retention, which means the job is not scheduled. See [docs/scheduled-jobs.md](docs/scheduled-jobs.md) for recommended schedules (`purge_expired_data` hourly, `retry_webhooks` every minute).

- **Invitations:** `POST /api/v1/invitations` lets staff and company owners invite someone by email, in English or French. The invitation stays pending and no account is created until the invitee signs in with that email, which gives them access in any access mode. `GET /api/v1/invitations` lists open invitations and `POST /api/v1/invitations/<id>/revoke` revokes one: sign-in with a revoked email is refused (`invitation_revoked`) until a new invitation is sent. `DELETE /api/v1/invitations/<id>` deletes a revoked invitation for good, which also lifts the block. New webhook events `identity.user.invited` (replaces the email when the company has an enabled rule for it, like magic link) and `identity.user.invitation_revoked`. See [docs/company-access.md](docs/company-access.md#invitations).
- **Admin user delete:** `DELETE /api/v1/users/<id>` lets staff and company owners remove a user from their company. Accounts that belong to other companies are kept; the account is deleted only when this was its last company. The API refuses to delete yourself, a staff user (unless you are staff), or a company's only owner (409 `last_company_owner`). Emits `identity.user.deleted` with `source=admin`.
- **Safer account deletion scope:** admin and self-service deletes now delete the account row only when the user has no link left to any other company. Ownership and group membership count as links, not just membership rows, so an owner or group member set through Django admin is never wiped from another company. The only-owner guard (409 `last_company_owner`) checks the company being left only; being the only owner of another company no longer blocks the delete.
- **No sign-in lock-out:** the Admin REST API refuses (400 `login_method_required`) to disable magic link, or to deactivate or delete the last OAuth/SAML provider, when that would leave a company with no way to sign in. New companies keep magic link enabled by default. See [docs/magic-link.md](docs/magic-link.md).

- **Magic link webhook URL:** `identity.auth.magic_link.requested` webhooks now include `magic_link_url`, and the admin sample payload shows it. When a company has an enabled webhook rule for this event, identity-service skips its own sign-in email so users don't get two links; without a rule, the built-in email is sent as before. The URL signs the user in until it expires or is used, so send this event only to endpoints you trust. See [docs/magic-link.md](docs/magic-link.md).

- **SAML 2.0 SSO:** Company admins can configure multiple SAML IdPs per company via `oauth-social-apps`. Identity-service exposes SP metadata, ACS, login, and optional SLO under `/api/v1/saml/<organization_slug>/`. See [docs/saml.md](docs/saml.md).
- **Twitch login:** companies can add one Twitch OAuth app. Sign-in uses the Helix user id. A verified Helix email links an existing account. See [Set up Twitch](docs/oauth-login.md#set-up-twitch).
- **OAuth batch 2 providers:** identity-hosted OAuth adds **LinkedIn** (OpenID Connect), **Slack** (OpenID Connect userInfo claims), generic **OpenID Connect** and **Keycloak**, **Okta**, and **Auth0**, each with hand-written strict adapter fixtures and literal uid assertions. Supported release total: **14** providers (`tools/data/oauth_e2e_covered_slugs.json`).
- **OAuth provider catalog:** identity-service ships a checked-in django-allauth provider catalog (`apps/authapi/provider_catalog.json`) with catalog entries for OAuth2/OIDC providers and SAML. Admin API: `GET /api/v1/oauth-provider-catalog`. OAuth app CRUD accepts `docs_slug` plus validated `extra_settings`. Catalog generation tracks the installed django-allauth version and end-to-end adapter test coverage per provider.
- **django-allauth 65.19.5:** dependency upgraded to match the provider dataset.
- **Editable display name:** `PATCH /api/v1/user` with `{"name": "…"}` sets the user's name (first word in `first_name`, the rest in `last_name`). New tokens and `GET /api/v1/user` use it.
- **Magic link email language:** `POST /api/v1/magic-link/request` accepts an optional `language` (`fr`, `fr-FR`, …) that picks the email locale and the webhook `language` field.

### ⚠️ Deprecated

- `GET /api/v1/login-events` and `GET /api/v1/login-events/<id>` keep their response shape but read from the event log. Use `GET /api/v1/events?event_type=identity.auth.login.succeeded,identity.auth.login.failed`.

### 🗑 Removed

- The `LoginEvent` model. Migration `actions.0005` copies the last 7 days of sign-ins into the event log; older rows are dropped, as the default retention would delete them anyway. Event ids change, so links to `/login-events/<id>` from before the upgrade no longer resolve.

### 🚨 Changed

- **Self-service account deletion per company:** `DELETE /api/v1/user` no longer returns **409** for users in several companies. It removes only the token company's membership and company-scoped data, and keeps the account for the other companies. Users with a single company are still fully deleted.
- **Last company owner protection:** `DELETE /api/v1/user` returns **409** `last_company_owner` (with the affected `companies`) when the user is the only owner of a company that would lose them. `PATCH /api/v1/companies/<id>/` with `owner_ids: []` returns **400** `company_owner_required`. Both prevent a company from being left without an owner.
- **Magic link opens without a confirmation click:** `GET /api/v1/magic-link/verify` returns a page that submits itself, so users land in the app straight away. The token is still consumed by POST only, so email link scanners that fetch the URL don't burn it. Without JavaScript a **Continue sign-in** button remains.
- **Names are never overwritten on sign-in:** OAuth and SAML sign-ins that link to an existing user by email only fill the name when the user has none. Previously an empty `last_name` was filled from the provider even when `first_name` was set. `GET` and `PUT /api/v1/user` now always return `name`/`full_name` from the user row instead of cached metadata.
- **Magic link usernames:** new magic link users get a username from their email (`ada` for `ada@acme.com`, with a short suffix when taken) instead of `magic_<name>_<random>`.

### 🐛 Bug Fixes

- **Group events from the admin API:** creating, renaming and deleting a group through `/api/v1/groups`, and changing a user's groups through `PUT /api/v1/users/<id>` (`group_ids`), now emit `identity.group.created`, `identity.group.updated`, `identity.group.deleted` and `identity.group.membership_changed`. Before, only Django admin and SCIM emitted them, so webhooks never fired for groups managed in the admin app. Django admin now also emits `identity.group.membership_changed` when members or nested groups are edited, and `identity.group.deleted` for the bulk **Delete selected** action. Membership changes for a single user are linked to that user in the event log.

### 🔒 Security

- SAML ACS processing requires signed assertions (python3-saml strict mode), single-use `InResponseTo` and assertion IDs, SSRF-pinned metadata import, and company-bound IdP configuration. IdP-initiated SSO and email account linking use explicit opt-in policies.
- SAML never auto-links an existing global user by assertion email unless the domain is in the company `verified_email_domains` field and the IdP has `trusted_for_verified_domains`. IdP `email_verified` attributes are ignored. Conflicts return `saml_email_conflict` (no duplicate user).
- `verified_email_domains` is platform-only (Django admin); company owner API rejects attempts to set it.
- SAML SocialAccount keys are scoped per company IdP (`saml-{social_app_id}`). A SAML SocialApp belongs to one company and cannot be moved. IdP entity IDs are globally unique across companies. ACS enforces strict signed assertions, session-bound single-use `InResponseTo`, and shared-cache assertion replay TTL.
- SAML login accepts `token_delivery` values `code` and `fragment` only, the same rule as authorize. ACS errors are JSON error codes. Transient NameIDs and assertions without an email are rejected (`saml_nameid_transient`, `saml_email_required`). Each completed login writes one login event.
- SAML metadata URLs are imported when the IdP is saved, and only a signing certificate is stored. PUT cannot replace `client_id` with a value another app already uses. A duplicate organization slug returns 404.
- IdP logout revokes the user's refresh sessions for that company.

### 🔒 Security

- Okta, Auth0, and self-hosted GitLab account ids are scoped by issuer or host. gitlab.com accounts stay unscoped. Self-hosted GitLab does not auto-link by email (`oauth_email_conflict`).
- GitLab uid migration `0015` rewrites `SocialAccount` rows, including accounts saved without a `SocialToken`. Ambiguous rows and rows that cannot be prefixed fail the migration and list their ids. `manage.py scope_gitlab_social_uids` binds a row to one GitLab app before migrate is re-run.
- A verified id_token with userinfo that omits `sub` is rejected (`oauth_subject_mismatch`). The account id is not taken from `id` or `mail`.
- OIDC, Google, Okta, and Auth0 id_tokens are verified once by Shellui. allauth's jti replay cache is not used on that path, and userinfo `sub` must match the verified id_token `sub`.
- Okta and Auth0 logins fail closed when the token response omits `id_token` (`oauth_id_token_missing`). Keycloak, generic OpenID Connect, and LinkedIn do the same when the requested scope includes `openid`.
- Company domain join uses only a verified email. A client-sent LinkedIn `server_url` is rejected (`oauth_setting_not_allowed`). URL settings must be https (`oauth_extra_settings_invalid`).
- Auth0 and GitLab profile requests send the access token in the Authorization header.
- OpenID Connect discovery `issuer` must match the configured server, and LinkedIn discovery hosts are pinned (`oauth_discovery_issuer_mismatch`, `oauth_provider_host_not_allowed`).
- Twitch authorize and token hosts are pinned to `id.twitch.tv`. The profile host is pinned to `api.twitch.tv`. Company URL and scope overrides are rejected. Shellui requests `user:read:email` and treats the Helix `email` as verified, because Twitch returns that field only for a verified address. A missing email or user id does not create an account (`oauth_identity_failed`, `token_exchange_failed`).
- OpenID Connect `SocialAccount` keys use per-app `provider_id` and issuer-scoped UIDs to prevent cross-issuer `sub` collisions.
- OAuth SocialApp admin list and attach paths are company-scoped; secret `extra_settings` fields are redacted in API responses.
- PKCE verifiers are stored server-side (nonce cache), not in signed OAuth `state`.
- URL-type provider settings are validated against private/loopback addresses at save time (SSRF mitigation for discovery `server_url`).
- OAuth token exchange failures return a fixed client message instead of exception text.

### 🚨 Changed

- **OAuth provider catalog v2:** `console_url` entries are `{kind, url, form}` with optional `placeholders` (no embedded English). Extra settings schema exposes `name`, `type`, `required`, and `secret` only; Shellui admin translates by field name. `GET /api/v1/oauth-provider-catalog` adds `console_link_kinds` and `console_link_forms` for admin mapping.
- **Honest `supported` count:** `supported: true` for OAuth follows `tools/data/oauth_e2e_covered_slugs.json`, which is regenerated only for providers that pass the strict adapter harness (`tools/audit_oauth_strict_coverage.py`). **15** OAuth providers are supported in this release, plus SAML.

### 🔒 Security

- **Google id_token on callback:** login callback verifies Google id_tokens against JWKS before email linking; wrong issuer, audience, or signing key returns `oauth_id_token_invalid` (no userinfo fallback).
- **LinkedIn OIDC:** fixed LinkedIn discovery and hosts (`www.linkedin.com`, `api.linkedin.com`); companies cannot set a custom `server_url`.
- **Company IdPs:** Keycloak, generic OpenID Connect, Okta, and Auth0 never auto-link by email; conflicting emails return `oauth_email_conflict`.
- **Okta and Auth0 base URLs:** missing `OKTA_BASE_URL` or `AUTH0_URL` fails closed instead of calling `https://None/...` endpoints.
- OpenID Connect migration **0014** rekeys existing `SocialAccount` rows to `(provider_id, issuer|sub)` with audit-backed reverse.
- OAuth uses `request_context` plus a `ContextVar` for the company `SocialApp` (no `allauth_context.request` assignment).
- Apple `form_post` bridges via a single-use cookie; POST `id_token` must verify against Apple JWKS and nonce before use.
- SSRF-safe OAuth HTTP pins resolved IPs; hostname resolution rejects mixed public/private answers.
- PKCE and OAuth state consumption use atomic `cache.add`.

### 📚 Documentation

- Regenerated [docs/oauth-providers.md](docs/oauth-providers.md) from the catalog (CI drift check). English labels for generated docs live in `tools/catalog_doc_strings_en.py`.

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

- Docs site moved to [identity.docs.shellui.com](https://identity.docs.shellui.com) with Shellui styling.
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
