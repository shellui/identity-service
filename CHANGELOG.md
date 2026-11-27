# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

<!---
## [x.y.z] - yyyy-mm-dd

### ✨ Feature - for new features
### 🛠 Improvements - for general improvements
### 🚨 Changed - for changes in existing functionality
### ⚠️ Deprecated - for soon-to-be removed features
### 📚 Documentation - for documentation update
### 🗑 Removed - for removed features
### 🐛 Bug Fixes - for any bug fixes
### 🔒 Security - in case of vulnerabilities
### 🏗 Chore - for tidying code

See for sample https://raw.githubusercontent.com/favoloso/conventional-changelog-emoji/master/CHANGELOG.md
-->

## [Unreleased]

### ✨ Feature

- `GET`, `PUT`, and `DELETE /api/v1/navigation-overlay` store one Shellui navigation overlay per user and company. Installed apps are third-party only: `firstParty` is rejected, `thirdParty` must be true, and the `auth` capability is never accepted. Each app must include `origin`, `url`, `path`, `installedAt`, and `updatedAt`, matching the shared schema in `apps/authapi/schemas/navigation-overlay.v1.json`. App URLs must be https and must not use a loopback or private host. Apps may not claim or hide reserved core paths. The raw body is limited to 64 KB (413 when larger) and `installedApps` to 100 entries. Writes require an enabled company membership, refuse agent tokens and personal access tokens, honor `If-Match` / `ETag` (a `412` carries the current `ETag`; `If-Match: *` needs an existing document and an empty `If-Match` is a `400`), and are rate-limited. Malformed `url`, `icon` or `origin` values are a `400`, and app names cannot contain invisible or blank characters (format characters, C0 and C1 controls, line and paragraph separators, and fillers such as U+3164 or U+2800) and need at least one letter, number, punctuation mark or symbol. ZWNJ and ZWJ (U+200C, U+200D) are accepted only between two visible characters, as in Persian, Indic scripts and emoji sequences. An unknown field name is cut to 40 characters in the error. A document with a lone surrogate (such as `\ud800`) anywhere is a `400`, not a database error. Leaving a company deletes that company overlay. Overlay writes are recorded in the company event log. The migrations are `0024_user_navigation_overlay` (after `0023_stable_social_account_uids`) and `0025_navigation_overlay_drop_user_index`, which drops the user index the unique constraint already covers.

### Upgrade notes

- The shared company membership check (`_required_company_from_request`) now refuses disabled members on every endpoint that uses it (22 call sites, including `GET`, `PUT`, and `DELETE /api/v1/preferences`). A member whose company access has been turned off used to be accepted on those routes and now gets 403.
- When the process starts with `DEBUG=false`, Django staff sign-in at `/admin/login/` requires a confirmed authenticator and locks the account after repeated failures. Every page under `/admin/` also needs a session that signed in with a verified code: any other staff session (one that existed before this release, or one created another way) is signed out and sent to the sign-in page. Sign everyone in again once after you deploy. A process that starts with `DEBUG=true` still asks for the password only. `STAFF_ADMIN_LOGIN_HARDENED` overrides that.
- Enroll with `python manage.py enroll_staff_totp <username> --show-secret` (or `--show-uri`), add the secret to an authenticator app, then confirm with `--code`. The command prints nothing secret unless you pass `--show-secret` or `--show-uri`, and only for an unconfirmed secret. `--rotate` replaces a secret. Defaults are `STAFF_ADMIN_LOCKOUT_FAILURES=5` and `STAFF_ADMIN_LOCKOUT_SECONDS=900`. See [Security hardening](docs/security-hardening.md#django-admin-staff-sign-in).
- Staff TOTP secrets are encrypted in the database. The key is `STAFF_TOTP_ENCRYPTION_KEY` (a Fernet key) when set, and otherwise derived from `SECRET_KEY`. If you rotate `SECRET_KEY`, keep the old one in `SECRET_KEY_FALLBACKS`, or re-enroll the staff accounts.
- An MCP agent access token is accepted as a bearer only on `POST /mcp`. Company admin HTTP routes require an access token whose audience is `JWT_AUDIENCE`. A refresh token is not a bearer, including after its session is revoked. On `/mcp`, the call runs as the creating user and keeps that user's company role.

### 🚨 Changed

- `is_company_admin` is a privileged user_metadata key, like `is_staff` and `is_company_owner`. A client cannot set it through a metadata merge. GET `/api/v1/user` and the admin user payloads always overwrite it to `false`, so a value left in the cache cannot appear in those responses. Identity does not issue a company-admin role today.
- The signed revocation snapshot (`GET /api/v1/mcp/internal/mcp-revocations`) carries `creator_status` on each agent row that has a creator: `owner`, `member` or `gone`. It is the creator's standing in the company right now (an owner is in `Company.owners` and has enabled access; `gone` means the membership was removed or disabled, or the account is inactive). Services read a personal agent's role from it on every poll, so a promotion, demotion or removal applies within the 30 second cache and no token has to expire. The field is left out for global agents and agents with no creator, and it is part of `revocation_policy_version`.
- An agent whose creator is `gone` stops working everywhere: its id is added to `revoked_agent_ids` (so storage, hosting, email and ai refuse it), identity's own `/mcp` refuses it, downstream token minting refuses it, and its refresh sessions are revoked on the next refresh. If the person regains access, an agent whose refresh sessions were revoked needs to be connected again; a personal token works again as soon as access returns.
- A global agent's access token carries no `owner_user_id`, even though its regional row records `created_by`. A global agent is not its creator's personal agent.
- An agent cannot change who owns a company. `PATCH` and `PUT` on a company with `owner_ids` (the `identity_update_companies` and `identity_replace_companies` tools) return 403 `agent_cannot_change_owners` for agent callers in every approval mode, even after a person approves the call. A person using the dashboard is unchanged.
- An agent also cannot remove or disable a company owner: `identity_delete_users` and an `is_active` change through `identity_replace_users` return 403 `agent_cannot_change_owners` when the target is an owner, in every mode and after approval. Other profile fields, and plain members, are unchanged.
- An agent cannot change sign-in or credentials. These return 403 `agent_cannot_manage_credentials` for agent callers in every mode and after approval: `identity_create_scim_tokens`, `identity_list_scim_tokens`, `identity_create_personal_access_tokens`, `identity_rotate_rule_secret`, the redirect allowlist writes (`identity_create_oauth_redirects`, `identity_update_oauth_redirects`, `identity_replace_hosting_oauth_redirects`), a change to `desktop_redirect_schemes` or `allow_desktop_dev_scheme` through `identity_update_companies` or `identity_replace_companies`, the sign-in method switch (`identity_update_auth_methods` and `identity_replace_auth_methods`), social app and OAuth client create and replace (which includes activating a client), and a non-empty `secret` or `authorization_header` or `allow_private_urls: true` on `identity_create_action_rules` and `identity_update_action_rules`. A personal access token acts as the person with no agent limits, and a SCIM token provisions the whole directory. Reads, revokes and deletes stay available to agents, because they only narrow access. Agents can still add members through invitations, `access_mode` and `allowed_email_domains`, which carry no role. A person using the dashboard is unchanged.
- Deleting a user account revokes every non-global agent the user created, before the row is deleted (`delete_user_account`, and a `pre_delete` signal so Django admin deletes are covered). Their ids are in `revoked_agent_ids` and minting stops. `Agent.created_by` is `SET_NULL`, so before this the agents survived with no creator.
- A deleted agent (its company was deleted, or its revoked row was purged by `purge_expired_data`) is remembered in `DeletedAgentRevocation`. It stays in `revoked_agent_ids`, and the snapshot carries a minimal inactive `agents` row for it (id and company id, no creator status, counted in `revocation_policy_version`), so ai and storage also refuse it on a call that names a company. The row records `token_expires_at`, the last moment one of its credentials could still be accepted (the personal token expiry, or a refresh session expiry plus one access token lifetime), and is purged after that. New migration `agents.0027_deletedagentrevocation`.
- Identity's `/mcp` and downstream minting check only the calling agent (one row and its creator) instead of loading every agent in the company. An agent id that does not exist is refused.
- A downstream token minted for ai-service carries `mcp_gateway_delegated` as `{"action": "<tool name>", "exp": <unix seconds>}` only when the signed mint request names the approved tool. The grant `exp` is the signed request's `exp`, capped at 60 seconds from the mint. A claim that is not exactly `{action, exp}` with a plain string action and an integer, unexpired `exp` is refused with a 400. The `true` value is no longer issued, since `shellui-django` 0.6 and later ignore it.
- User token exchange refuses `is_global_staff` the same way it refuses `is_staff` and `is_superuser`.
- Django staff sign-in uses a per-account lockout and a TOTP authenticator when `DEBUG` is false. An accepted code cannot be used again: the last accepted 30 second step is stored (`totp_last_step`, created by migration `0022`) and a code at or below it is refused.
- `shellui-django` 0.8.0 with Django 6.1.3, Django REST framework 3.18.3 and drf-spectacular 0.30.0. The shellui-django pins are exact, so these move together.
- gunicorn 27.0.1. A request whose `Transfer-Encoding` does not end with `chunked` (for example `identity` alone) now gets HTTP 400. No gunicorn setting changed.

### 🐛 Bug Fixes

- Revoking and deleting an invitation no longer fail with a 500 on PostgreSQL. The row lock joined the nullable `invited_by` column, and PostgreSQL refuses `FOR UPDATE` on the nullable side of an outer join. The lock now covers only the invitation row (`select_for_update(of=('self',))`). SQLite ignores row locks, so tests there never showed it.

### 🔒 Security

- Agent access tokens authenticate only on `POST /mcp`. Refresh tokens are refused as bearer tokens, and a revoked refresh session stays refused.
- django-allauth 65.19.6 to 65.23.0 identify accounts by stable ids: Bitbucket and Pinterest now use stable ids, and Tumblr uses the primary blog UUID. Migration `authapi.0023_stable_social_account_uids` rewrites `SocialAccount.uid` for existing `bitbucket_oauth2`, `pinterest`, `tumblr` and `tumblr_oauth2` rows from `extra_data`, as allauth's upgrade notes describe, so existing links keep matching. A row whose `extra_data` has no usable value, or whose new uid is already taken, is left as it was and logged by id. That person links the account again. The migration cannot be reversed (its reverse step does nothing), so to roll back after it ran, restore the database from a backup taken before the deploy. Deploying the previous image alone leaves the rewritten uids in place and those people are offered a new account.
- Django 6.1.3 includes the Django security releases of October and November 2026, among them a fix for memory use when parsing large multipart uploads.

### 🏗 Chore

- The `test_migration_0014_oidc*` tests build their audit table from Django's column types instead of SQLite-only SQL, and CI now runs them, with a new invitation row lock test, against PostgreSQL in the row lock regression step.
- Node.js 26, the current LTS, for the image build stage and CI.
- GitHub Actions: actions/checkout v7, actions/setup-node v7, astral-sh/setup-uv v10.4.0, docker/build-push-action v7, docker/login-action v4, docker/metadata-action v6, docker/setup-buildx-action v4, docker/setup-qemu-action v4, peter-evans/dockerhub-description v5.0.0.
- Python dependencies: django-allauth 65.23.0, drf-spectacular 0.30.0, python-dotenv 1.2.4, requests 2.34.2, sentry-sdk 2.77.0, psycopg 3.3.9, cryptography 50.0.2, django-scim2 0.24.0, redis 8.2.0, celery 5.7.0.
- The SAML ACS tests no longer call `xmlsec.shutdown()` and `xmlsec.init()` between cases. xmlsec 1.3.18 crashes the process on that re-init.
- npm dependencies: @tailwindcss/cli 4.3.5, tailwindcss 4.3.5.
- Django 6.1 requires PostgreSQL 15 or newer, and drops 14. Check the database of any deployment before upgrading. CI runs PostgreSQL 18.
- drf-spectacular 0.30 describes blank URL and slug fields as `oneOf` (the field's format or an empty string) in the OpenAPI schema. Generated clients and the published schema see that change. The API itself does not change.
- CI runs `manage.py makemigrations --check --dry-run`, so a model change without a migration fails the build.
- CI pins Python 3.14.10 and uv 0.13.10, and the Dockerfile copies the same uv, so CI and the image run the same interpreter and the same tool.
- Migrations `agents.0028_sync_model_state` and `companies.0035_sync_data_retention_days_state` record help text, choices, validators and Meta options the models already had. `companies.0035` changes nothing in the database. `agents.0028` also creates three indexes the models already declared with `db_index=True` but the migration history never built: `agents_agent(global_company_id)`, `agents_mcpapprovalrequest(global_agent_id)` and `agents_mcpapprovalrequest(global_company_id)`. The `CREATE INDEX` statements are not concurrent, so each takes a write lock on its table while it builds.

## [0.13.6] - 2026-11-26

### 🐛 Bug Fixes

- Agent token exchange: when an exchange changes an agent's permissions, the access token now carries the stored `grant_version`. Before, the token kept the previous value, so regional gateways refused it until the next exchange.

## [0.13.5] - 2026-11-25

### 🛠 Improvements

- Sign-in, consent, device login, magic link, and related identity pages use the same Shellui header, card, and dark-mode layout as the Identity home and error pages, via `shellui-django` 0.7.2.

## [0.13.4] - 2026-11-25

### ✨ Feature

- Add `GET /api/v1/stats`, returning company-scoped user, active-user, social account, and process-local successful sign-in counts as JSON for staff and enabled company owners.

## [0.13.3] - 2026-11-24

### 🐛 Bug Fixes

- Celery Beat used the default PersistentScheduler, which writes a shelve/dbm file under `/tmp`. On Python 3.14 that file is `dbm.sqlite3`, and Beat can crash with `locking protocol` while the worker stays up, so the container stayed healthy after scheduled jobs had stopped. Beat now uses the in-memory scheduler (`celery.beat.Scheduler`) and runs as its own supervised process. If Beat exits, the entrypoint stops gunicorn and the worker and the container exits, so Coolify restarts it. If a child ignores SIGTERM, the entrypoint sends SIGKILL after 8 seconds so `docker stop` can finish cleanly.

## [0.13.2] - 2026-11-24

### 🐛 Bug Fixes

- Gunicorn workers that had not yet served a traced request exported no `http.server.active_requests` series, because the Django instrumentation creates it on the first request and health checks are not traced. After a restart with little traffic, monitoring that waits for this series saw the service as down. Each web worker now starts the series at 0.

## [0.13.1] - 2026-11-24

### 🐛 Bug Fixes

- The identity and scheduled-job gauges (for example active users and logins) were never registered, because registration waited for `apps.ready`, which Django sets only after every `AppConfig.ready()` has run. Registration now waits for the models. The Celery worker skips these gauges, because its thread pool shares one database connection with the metric reader thread; Gunicorn publishes them.

## [0.13.0] - 2026-11-24

### Upgrade notes

`GET /api/v1/metrics` and `GET /api/v1/metrics/all` are removed. Read traces and metrics from the OpenTelemetry collector instead.

- Set `OTEL_EXPORTER_OTLP_ENDPOINT` to turn telemetry on. Leave it empty and telemetry stays off.
- Set `OTEL_EXPORTER_OTLP_HEADERS` when the collector requires auth (SigNoz basic auth).
- `OTEL_SERVICE_NAME` overrides the default `identity-service`. identity-global and a regional identity both use that name unless you override it.
- `OTEL_RESOURCE_ATTRIBUTES` can set `deployment.environment` and `cloud.region` (for example `deployment.environment=production,cloud.region=eu`).
- `SHELLUI_REGION` sets `cloud.region` when `OTEL_RESOURCE_ATTRIBUTES` does not.
- `shellui.instance_role` is `global` on identity-global, `region` on a regional identity, and `standalone` otherwise.
- `POST /api/v1/personal-access-tokens` rejects `access_global_metrics: true`. New tokens do not include `pat_agm`. Tokens that already carry the claim still authenticate, and the claim is ignored. The `access_global_metrics` column stays.

### ✨ Feature

- OpenTelemetry traces, metrics, and log correlation through `shellui-django[otel]` 0.7.0. Log lines include `trace_id` and `span_id` next to `X-Request-ID`. The upstream token call and the MCP approval notify send W3C `traceparent`. Celery tasks stay on the same trace.

### ⚠️ Deprecated

- `PersonalAccessToken.access_global_metrics` is unused. The column remains so existing rows stay valid. Global metrics access is not issued or accepted.

### 🗑 Removed

- `GET /api/v1/metrics` and `GET /api/v1/metrics/all` (breaking). The `prometheus-client` dependency is gone.
- The `pat_agm` claim is no longer issued. The API and Django admin no longer expose global metrics access.

### 📚 Documentation

- Metrics, configuration, scheduled jobs, JWKS, and the upgrade notes describe OpenTelemetry instead of Prometheus scrape endpoints.


## [0.12.0] - 2026-11-18

### Upgrade notes

A region that accepts global agent tokens during the move to ai-service sets both issuers. A standalone install that does not exchange those tokens needs no new variables.

- Set `GLOBAL_AGENT_ISSUER_URL` and `GLOBAL_AGENT_JWKS` to ai-service global. An empty pair still falls back to `GLOBAL_ISSUER_URL` and `GLOBAL_JWKS`.
- Set `GLOBAL_AGENT_LEGACY_ISSUER_URL` and `GLOBAL_AGENT_LEGACY_JWKS` to the saas-service issuer until cutover. An empty legacy issuer or an empty legacy JWKS adds no second issuer and does not raise.
- Set `GLOBAL_MCP_URL` to `https://ai.shellui.com/mcp` in production. Personal MCP status advertises that URL. An empty value keeps the dashboard hint.
- Provisioning create stores `access_mode` and `allowed_email_domains`. Patch accepts those fields with or without `name` and `status`. Domain mode needs at least one domain. Member add, role change, removal, and ownership transfer use the same assertion and `Idempotency-Key` as the other writes. The routes are `POST /api/v1/provisioning/companies/{id}/members`, `PATCH` and `DELETE` on `/api/v1/provisioning/companies/{id}/members/{global_subject}`, and `POST /api/v1/provisioning/companies/{id}/transfer-ownership`.
- Image push still uses `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. Set the repository secrets `DOCKERHUB_DESCRIPTION_USERNAME` and `DOCKERHUB_DESCRIPTION_TOKEN` to a personal Docker Hub access token (Read, Write, Delete, from an account with Admin on the repository) so the publish workflow can update the overview from `DOCKERHUB.md`. If those secrets are unset, the overview step is skipped and the image still publishes.

### ✨ Feature

- Provisioning create stores `allowed_email_domains` with `access_mode`. Patch accepts `access_mode` and `allowed_email_domains` with or without `name` and `status`. Domain mode needs at least one domain.
- Provisioning can add a member, change a role, remove a member, and transfer ownership. The last owner cannot be removed or demoted. Removing a member revokes that person's refresh sessions and personal access tokens for that company.
- Region identity trusts ai-service global as `GLOBAL_AGENT_ISSUER_URL` and `GLOBAL_AGENT_JWKS`, with the same empty fallback as before. `GLOBAL_AGENT_LEGACY_ISSUER_URL` and `GLOBAL_AGENT_LEGACY_JWKS` keep the saas-service issuer until cutover. An empty legacy JWKS does not raise.
- Personal MCP status can advertise `https://ai.shellui.com/mcp` through `GLOBAL_MCP_URL`. An empty value keeps the dashboard hint.
- identity-global shows a Shellui account sign-in page when the ai-service global OpenID client calls authorize without `prompt=none` (redirect path `/oauth/mcp/signin/complete`, the client listed in `OIDC_CLIENTS`). Staff accounts are refused. Region-only accounts are told to use their region's company MCP URL.

### 🚨 Changed

- Subject tokens stay single use. When `grant_version` is present it must match `company_binding_version`. A provisioned company accepts a token only for its own global company id.
- `DOCKERHUB.md` is published as the Docker Hub overview on each image release.
- The docs build fetches storage, hosting, and email docs so links on the Shellui docs pages still resolve.
- Dependabot version updates for npm, uv, Docker, and GitHub Actions open against `develop`.

### 🐛 Bug Fixes

- Docker Hub overview updates use a personal access token (`DOCKERHUB_DESCRIPTION_USERNAME` and `DOCKERHUB_DESCRIPTION_TOKEN`). Organization access tokens were rejected with 401. If those secrets are unset, the image still publishes and the overview step is skipped.

## [0.11.0] - 2026-11-18

### ✨ Feature

- MCP OAuth for company agents, with sign-in, consent, and agent tokens bound to the company MCP URL.
- Company members can mint, list, and revoke personal MCP agent tokens, and review per-agent activity.
- Headless MCP clients can sign in with OAuth device authorization.
- The Shellui CLI can sign in with a separate OAuth device authorization grant.
- Regional identity can exchange a global MCP agent token for a company-scoped regional token.
- Identity can mint downstream agent tokens for ai-service.
- Consent can offer optional SaaS access, then complete a global Shellui sign-in before the regional code is issued.
- Email-first MCP sign-in routes verified domains to the company identity provider.
- A signed-in browser session on the identity origin can continue into MCP and CLI device pages.
- Company owners can allow or deny a pending agent action.
- MCP approval links open a browser page, and signed-in members can approve without signing in again.
- You can approve a non-destructive agent action in chat, and a destructive action still needs the approval page.
- A downstream ai-service token does not ask for a second approval of the same action.
- Company owners can read a redacted summary of a pending approval.
- Internal APIs let services check live delegated authority, approval state, and revocation lists.
- `GET /api/v1/settings` includes a logout URL, and logout clears only the identity session cookie.

### 🛠 Improvements

- MCP tools use pinned gateway names, flat argument schemas, enums, and risk hints.
- Authorization server metadata advertises the token endpoint and the device grant.
- Agent tokens can carry the company display name and the creating user's id.
- The admin agent list shows who created each agent, and revoked agents are deleted after the company's data retention period.
- Revocation polls include a policy version so gateways drop stale cache when grants change.
- Setup-flow approval sessions can last 10 to 15 minutes when the global token allows it. Destructive actions still need a fresh approval.
- Company MCP URLs can use HTTP on a loopback, private, or CGNAT address.
- A region can verify global MCP agent tokens with a separate issuer.

### 🐛 Bug Fixes

- Approval decide and consume lock only the approval row, so PostgreSQL no longer returns 500 on a joined nullable agent.
- Revocation list responses include the highest active grant version, and they list every regional agent for the company filter.
- `/mcp` accepts RS256 agent tokens without returning 500.
- Token and register endpoints accept form-urlencoded bodies as well as JSON.
- Sign-in and consent pages send a same-origin referrer so CSRF checks succeed in MCP Inspector.
- Invalid MCP clients, redirect URIs, and resources show an error page instead of a redirect.
- After approval, the agent continues, and identity notifies ai-service of the decision.
- `POST /mcp` no longer returns 500 when several clients call it at the same time.
- API docs render in the admin iframe without waiting for shell settings.
- When agent token exchange is off, the token endpoint returns a JSON 404.

### 🔒 Security

- A company OAuth client update is allowed only for an app that company created and that no other client already maps. Listing, updating, or deleting a provider app returns not found when another company owns or maps it.
- MCP redirect URIs allow only https and loopback http, reject fragments and user info, and match exactly.
- Staff cannot use MCP. Staff CLI sessions older than 12 hours, or started with a magic link, must sign in again with a password or SSO.
- Device codes are stored as hashes and are not logged.
- MCP tool results hide one-time secrets.
- Company metrics are not offered as MCP tools.
- The web session exchange endpoint is rate limited.

### 🗑 Removed

- The aggregated Identity MCP gateway at `POST /mcp` is gone. Use ai-service as the single MCP connector.
- Identity no longer stores new MCP tool-call logs. Those now live in ai-service. Existing rows stay readable and the call-log API is deprecated.

### 📚 Documentation

- Local dev stack docs, including a Docker dev target and a dev seed command.
- Docs for personal agent settings, the shell host session exchange, and the live MCP device-login prompts.
- OpenAPI describes the identity admin routes an agent can call.

### 🏗 Chore

- Use `shellui-django[mcp]==0.5.1` instead of a vendored MCP package.
- Internal MCP assertions are verified with RS256 against a registry of trusted callers.

## [0.10.1] - 2026-11-01

### 🐛 Bug Fixes

- Company deletion: a service URL that redirects (for example `http://` to `https://`) is no longer followed, and a refused call logs its status, target and a short response snippet (with an ALLOWED_HOSTS hint on 400), so a stuck purge says why; the skipped-email warning now names `EMAIL_SERVICE_API_KEY` when that is what is missing.
- Access log: every response carries `X-Request-ID`, access lines never include request headers, and a logging error no longer prints request headers or tokens to stderr.

## [0.10.0] - 2026-11-01

### ✨ Feature

- Company deletion: deleting from the dashboard or Django admin flags the company, hides it, refuses its tokens, and a Celery job purges it every 60 seconds across storage, hosting and email, then sends `identity.company.deleted` (set `STORAGE_SERVICE_URL`, `HOSTING_SERVICE_URL`, `EMAIL_SERVICE_URL`).

## [0.9.2] - 2026-10-27

### 🐛 Bug Fixes

- **API docs:** ReDoc at `/api/docs/redoc/` loads again, served from the service's own static files.

### 🛠 Improvements

- **API docs:** Swagger UI and the Shellui SDK no longer load from a CDN.

## [0.9.1] - 2026-10-23

### ✨ Feature

- **Token exchange:** Endpoint for regional sessions from a global access token (RFC 8693, `POST /oauth/token`). See [docs/instance-roles.md](docs/instance-roles.md).

### 🔒 Security

- **Token exchange:** Global staff are refused token exchange and must use local regional accounts.
- **Dependencies:** Updated djangorestframework to 3.18.2.

## [0.9.0] - 2026-10-21

### ✨ Feature

- **Federation:** Identity can run as the global provider or as a region that trusts it (`SHELLUI_INSTANCE_ROLE`, [docs/instance-roles.md](docs/instance-roles.md)).
- **Provisioning API:** A region serves the dashboard's create, update, limits, delete and list calls, signed with its pinned key and bound to each request.
- **Global tokens:** With the `global` role, access tokens carry `sub` and `email_verified`.

### 🔒 Security

- **Federation:** Silent sign-in and provisioning refuse to link or make an owner of an existing staff account.
- **Region hosts:** A region with `DEBUG=false` refuses to start with default `shellui.com` hosts.
- **Security:** Web sign-in requires PKCE (needs shellui 0.6.4 or later).
- **Security:** Session and CSRF cookies use the `__Host-` prefix.
- **PKCE:** Tokens are never sent in the URL fragment without PKCE.
- **Dependencies:** Updated certifi to 2026.10.19.

### 🛠 Improvements

- **Deployment:** `DEBUG` defaults to false, so production no longer needs to set it.
- **Deployment:** `check --deploy` rejects a weak `SECRET_KEY`.
- **Deployment:** Releases publish the Docker image automatically.
- **Errors:** Error pages use the Shellui design, and API errors always return JSON.
- **Deployment:** The Docker image has a built-in health check that Coolify detects.
- **Deployment:** `.env.example` lists only required settings, and optional ones have defaults in code.
- **Deployment:** `manage.py generate_env` prints the required settings with fresh secrets.

### 🗑 Removed

- **Provisioning:** Removed the global-key `companies/plans` endpoint, the federation `provision` and `plan` endpoints, and their webhook events (`identity.federation.provisioning.completed`, `identity.federation.plan.pushed`).

### 🏗 Chore

- **Settings:** Removed duplicated settings in `config/settings.py`.

## [0.8.2] - 2026-10-18

### 🔒 Security

- **Desktop sign-in:** A registered scheme also accepts its `-dev` variant when `DEBUG=true`.

### 🛠 Improvements

- **Desktop sign-in:** Owners and staff can allow the `-dev` variant per company in production.

## [0.8.1] - 2026-10-13

### 🚨 Changed

- **Desktop app sign-in:** custom schemes are a company allowlist (`desktop_redirect_schemes`). An empty list turns desktop sign-in off. `CompanyOAuthClient.desktop_redirect_scheme` is removed.

## [0.8.0] - 2026-10-13

### ✨ Feature

- **Desktop app sign-in:** one custom scheme per OAuth application (`desktop_redirect_scheme`), accepted only for that application, with S256 PKCE and the existing 120s one-time code ([docs/desktop-apps.md](docs/desktop-apps.md)).
- **Sign-in error pages:** English or French HTML in the browser, and **Back to the app** opens `<scheme>://…?error=<error_code>` with no token when that scheme is registered (`Accept: application/json` stays JSON).
- **User profile webhooks:** `identity.user.updated` lists `changed_fields` when a tracked profile field changes through the API, Django admin, or SCIM, omits tokens and sign-in links, and does not fire on an unchanged save.

### 🗑 Removed

- Duplicate `EMAIL_SERVICE_*` settings, unused `html2text`, `django-filter`, `signxml`, and `markdown`, unused helpers, `include_unsupported`, and `CompanyOAuthClient.catalog_slug` (API responses stay JSON; browser sign-in errors stay HTML).
- `GET /api/v1/login-events` and `GET /api/v1/login-events/{id}` (read sign-ins from `GET /api/v1/events`).
- The `OidcSocialAccountKeyMigration` audit table (migration `authapi.0019`; migration `0014` is unchanged).

### 🏗 Chore

- Webhook and email-service retry backoff share one helper next to `compute_retry_delay_seconds`.

### 📚 Documentation

- [docs/desktop-apps.md](docs/desktop-apps.md) covers the scheme, the deep link, the error callback, PKCE, and the Origin rule.

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
- **Docs restructure:** a new overview page with provider logos and feature cards, a [getting started](docs/getting-started.md) guide, and a sidebar grouped by task. New pages for [account deletion](docs/account-deletion.md) and [upgrade notes](docs/upgrading.md), which move out of the OAuth login page. Every page now opens with a summary, and the pages were checked against the code.
- **Provider list matches Shellui admin:** [docs/oauth-providers.md](docs/oauth-providers.md) now lists only the 16 providers you can configure (15 OAuth and OpenID Connect, plus SAML), split into social and company identity providers, with setup steps and the email linking rule for each. The 98 catalog entries that are not available are summarized instead of listed. The homepage logo strip is generated from the same catalog.
- **Doc fixes:** account deletion checks `auth_time`, so the user must sign in again (a token refresh is not enough). Personal access tokens default to 30 days, not 90. The OAuth app endpoint is `/api/v1/oauth-social-apps`, not `/api/v1/admin/oauth-social-apps`. The release smoke test and the published image example now set `REDIS_URL`, `JWT_ISSUER`, and `JWT_AUDIENCE`.

### 🗑 Removed

- The `LoginEvent` model: migration `actions.0005` copies the last 7 days of sign-ins into the event log, and old `/login-events/<id>` links no longer resolve.

### 🐛 Bug Fixes

- **Group events:** group changes made through the admin API and Django admin now emit `identity.group.*` events, so webhooks fire for them.

### 🔒 Security

- **Magic-link webhooks no longer carry the sign-in link (breaking change):** the `identity.auth.magic_link.requested` webhook payload no longer contains `magic_link_url`, the token, or anything else that can be used to sign in, and identity always sends the sign-in email itself, even when the company has a webhook rule for this event. Before, anyone who could read the webhook or its delivery records (for example a company owner) could sign in as the user who owns that email. Migration `actions.0007` removes links already stored in webhook delivery records. If you used the webhook link to deliver magic links yourself (for example from n8n), that no longer works: identity sends the email and the webhook is a notification only.
- **No magic links for staff accounts:** staff (`is_staff`) and superuser accounts can no longer sign in with a magic link. A company that sends mail through its own provider (Resend or SMTP) can read every sign-in link in that provider's dashboard or logs, so a link for a staff member signing in to that company let the company sign in as that staff member. A request for a staff address creates no token and sends a short notice instead (built-in email-service template `identity.auth.magic_link.staff_blocked`, or the EN and FR SMTP templates): magic links are off for staff accounts, sign in with your usual sign-in method, and a link to the sign-in page, with no token. The API answer and the `identity.auth.magic_link.requested` webhook are the same as for any other address, so neither reveals staff accounts. Verify refuses a token that belongs to a staff account with **403** `magic_link_staff_disabled` (the browser page explains it in English or French), saving an account as staff deletes its unused tokens, and migration `authapi.0017` deletes unused tokens of existing staff accounts. Password sign-in to Django admin and OAuth, OIDC and SAML sign-in are unchanged. See [Staff accounts](docs/magic-link.md#staff-accounts).
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
