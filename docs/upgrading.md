---
description: Steps to take when you upgrade identity-service, release by release, newest first.
---

# Upgrade notes

This page lists what you must change when you move to a newer identity-service release. Releases not listed here need no action beyond deploying the new image, which runs the database migrations on start. The full list of changes is in the [changelog](../CHANGELOG.md).

## Upgrade to 0.8.2

0.8.2 accepts a registered scheme's `-dev` variant when `DEBUG=true`. Owners and staff can turn the same variant on per company when `DEBUG=false`.

1. **Apply migration `companies.0030_company_allow_desktop_dev_scheme`.** It adds `allow_desktop_dev_scheme` (default false). With the flag off and `DEBUG=false`, `shellui-playground` does not allow `shellui-playground-dev`. To accept that redirect, an owner or a staff member sets the flag, or you add `shellui-playground-dev` to `desktop_redirect_schemes`. A local identity-service with `DEBUG=true` still accepts the variant without the flag. See [Desktop apps](desktop-apps.md).

## Upgrade to 0.8.1

0.8.1 moves desktop sign-in schemes from each OAuth application onto the company.

1. **Set schemes on the company.** `PATCH /api/v1/companies/{id}/` with `{"desktop_redirect_schemes":["shellui-playground"]}`. An empty list turns desktop sign-in off for every method. Migration `companies.0029_company_desktop_redirect_schemes` copies existing non-empty values onto that list (duplicates dropped) and removes `CompanyOAuthClient.desktop_redirect_scheme`. OAuth client and social app requests no longer accept that field. See [Desktop apps](desktop-apps.md).

## Upgrade to 0.8.0

0.8.0 removes the login-events API and requires a registered scheme plus S256 PKCE for desktop sign-in. Web shells need no change.

1. **Stop calling `/api/v1/login-events`.** `GET /api/v1/login-events` and `GET /api/v1/login-events/{id}` are removed. Use `GET /api/v1/events?event_type=identity.auth.login.succeeded,identity.auth.login.failed`. See [Event log](event-log.md).
2. **Register a scheme before a desktop app signs in.** 0.8.0 stored one `desktop_redirect_scheme` on the OAuth application. 0.8.1 moved that allowlist to the company. Send S256 PKCE on every custom-scheme redirect. See [Upgrade to 0.8.1](#upgrade-to-081) and [Desktop apps](desktop-apps.md). Migration `authapi.0018_desktop_custom_scheme_redirect` adds the PKCE challenge column.

`identity.user.updated` fires when a tracked profile field changes. Add a webhook rule if you want that event. See [Webhooks](actions.md).

## Upgrade to 0.7.0

0.7.0 has two breaking changes: Redis becomes required in production, and magic link webhooks no longer carry the sign-in link. It also changes how staff accounts sign in and what the company metrics endpoint returns.

1. **Add Redis before you deploy.** With `DEBUG=false`, the container now exits at startup without `REDIS_URL`, also with `SCHEDULER_ENABLED=false`. See [Shared cache (Redis)](configuration.md#shared-cache-redis).
2. **Remove your external scheduler.** The container now runs `retry_webhooks` and `purge_expired_data` itself. Delete the Coolify Scheduled Tasks or cron entries, or set `SCHEDULER_ENABLED=false` to keep them. See [Scheduled jobs](scheduled-jobs.md).
3. **Stop delivering magic links from webhooks.** The `identity.auth.magic_link.requested` payload no longer contains `magic_link_url`, and identity-service always sends the sign-in email itself. A workflow that mailed the link (for example in n8n) no longer works. See [Magic link](magic-link.md).
4. **Give staff another sign-in method.** Staff and superuser accounts can no longer sign in with a magic link, and their unused links stop working. Make sure every staff member can sign in with OAuth, OIDC, SAML, or a Django admin password. See [Staff accounts](magic-link.md#staff-accounts).
5. **Point global dashboards at `/api/v1/metrics/all`.** `GET /api/v1/metrics` now returns only the token company's series, also for staff. Process metrics, platform-wide user counts, and other companies' series are only on the global endpoint. See [Metrics](metrics.md).
6. **Change staff flags in Django admin.** `PUT /api/v1/users/{id}` returns **400** `admin_only_field` when the body contains `is_staff` or `is_superuser`.

### Account ID migrations

Migration `0014_migrate_oidc_social_account_keys` rekeys OpenID Connect accounts on its own. Migration `0015_scope_self_hosted_gitlab_uids` prefixes self-hosted GitLab account IDs with the GitLab base URL, so two GitLab hosts cannot share an ID. Accounts on `https://gitlab.com` keep their raw ID. The base URL comes from the account's social token when there is one, otherwise from the user's company when that company has exactly one GitLab app.

The migration stops and lists the `social_account` IDs it cannot place: a row that matches more than one GitLab host, already contains `|`, would exceed 191 characters, or collides with an existing ID. Bind each listed row to its app, then run the migrations again:

```bash
python manage.py scope_gitlab_social_uids
python manage.py scope_gitlab_social_uids --account-id 123 --social-app-id 45
```

The first command lists the rows that still need a choice. The second stores the binding for one row without changing its ID; the migration rewrites it on the next run.

## Upgrade to 0.5.0

0.5.0 changes how the shell receives tokens after OAuth (session code delivery), and rotates refresh tokens. Migration `0010_refresh_rotation_oauth_session_code` adds both.

**Session code delivery.** After sign-in, identity-service now redirects with a one-time `shellui_auth_code` instead of tokens in the URL fragment:

1. Update shells to read `shellui_auth_code` from the login callback query string and call `POST /api/v1/oauth/session` with `{"auth_code": "…", "redirect_to": "<same callback URL>"}`.
2. Until every shell is updated, pass `token_delivery=fragment` on authorize, or set `OAUTH_TOKEN_DELIVERY=fragment` on identity-service.

**Refresh rotation.** Every refresh now returns a new refresh token and revokes the old one:

- Store the new refresh token after each refresh, and stop using the old one
- Logout revokes the refresh session, so discard both tokens on the client
- Refresh tokens issued before the upgrade stop working, and users sign in again once

## Upgrade to 0.4.1

0.4.1 adds hosting preview sync to the redirect allowlist, and makes API CORS permissive by default:

1. Deploy so migration `0014_companyoauthredirect_source` runs. It adds `source` on `CompanyOAuthRedirect`, and existing rows become `manual`.
2. Keep `CORS_ALLOW_ALL_ORIGINS=true` unless you restrict API origins on purpose. Do not list hosting preview origins in `CORS_ALLOWED_ORIGINS`.
3. Make sure hosting-service can call `PUT` and `DELETE` on `/api/v1/hosting-oauth-redirects` with the caller's identity JWT, so preview origins stay on the allowlist. Since 0.5.0, that caller must be staff or a company owner.

## Upgrade to 0.4.0

0.4.0 moves the OAuth callback from the shell to identity-service. If your provider apps still call back to `{shell}/login/callback`:

1. Change each provider app callback to `https://auth.example.com/api/v1/oauth/callback`.
2. Add every production shell origin to the company redirect allowlist, see [OAuth login](oauth-login.md#redirect-allowlist).
3. Deploy so migration `0013_companyoauthredirect` runs.
4. Use a Shellui admin build that shows the identity callback URL in **OAuth setup**.
