---
description: Read Prometheus metrics from identity-service for one company or the whole deployment, with a session token or a personal access token.
---

# Metrics and access tokens

identity-service exposes Prometheus metrics for one company or for the whole deployment. You call them with a Shellui access token or a personal access token (PAT), which is the usual way to connect Prometheus or another scraper. Responses are plain text in the Prometheus exposition format, not JSON.

| Endpoint | Scope | Who can call it |
| --- | --- | --- |
| `GET /api/v1/metrics` | The company of the token, and nothing else | Staff, or an owner of that company |
| `GET /api/v1/metrics/all` | The whole deployment | Staff, or a PAT with global metrics access |

```bash
curl -sS https://auth.example.com/api/v1/metrics \
  -H 'Authorization: Bearer your_access_token_here'

curl -sS https://auth.example.com/api/v1/metrics/all \
  -H 'Authorization: Bearer your_access_token_here'
```

## Company metrics

`GET /api/v1/metrics` returns metrics for the company in the token's `company_id` claim. Passing `company_id` in the query string or body returns **400**. A read-only PAT is enough.

The response is built for each request, with only that company's series:

| Metric | Labels |
| --- | --- |
| `shellui_auth_company_users_total` | `company_id` |
| `shellui_auth_company_users_active` | `company_id` |
| `shellui_auth_company_users_staff` | `company_id` |
| `shellui_auth_company_social_accounts_total` | `company_id` |
| `shellui_auth_company_daily_active_users` | `company_id` |
| `shellui_auth_company_weekly_active_users` | `company_id` |
| `shellui_auth_company_monthly_active_users` | `company_id` |
| `shellui_auth_successful_logins_total` | `company_id`, `provider` (since the answering process started) |

It never includes process or Python runtime metrics, platform-wide user counts, scheduled job metrics, or another company's series. Staff calling this endpoint get the same company-only view.

## Global metrics

`GET /api/v1/metrics/all` accepts:

- a session token of a staff user
- a PAT created by staff with **global metrics access** (`pat_agm: true` in the token)

It returns process and Python runtime metrics, platform-wide user gauges (`shellui_auth_users_*`, `shellui_auth_social_accounts_total`, `shellui_auth_*_active_users`), `shellui_auth_successful_logins_total` for every company, and the scheduled job metrics (`shellui_auth_scheduled_job_*` and `shellui_auth_scheduler_*`). Per-company `shellui_auth_company_*` gauges are only on the company endpoint. Scheduled job metric names, labels, and alert rules are in [Scheduled jobs](scheduled-jobs.md#prometheus-metrics).

Turn global access on in Shellui admin **Access tokens** (a staff-only checkbox), or on the `PersonalAccessToken` row in Django admin. A PAT that already exists does not pick up a change: issue a new one, because the `pat_agm` claim must match the database.

## Personal access tokens

A PAT is a signed JWT with the same claims as a session token, plus `pat_id` and `pat_ro` (see [JWT and JWKS](jwks.md#claims)). Create one in Shellui admin **Access tokens**, or with `POST /api/v1/personal-access-tokens`. The response shows the `access_token` once.

| Type | Allowed |
| --- | --- |
| Read-only (`pat_ro: true`) | `GET`, `HEAD`, and `OPTIONS` on the whole API, including metrics |
| Read and write | The same endpoints and rules as a session token of your user |

PATs expire after `PERSONAL_ACCESS_TOKEN_LIFETIME` (30 days by default). Each request checks the PAT against its database row, so revoking it stops it right away, and every successful use updates `last_used_at`.

Treat PATs like passwords: send them over HTTPS only, keep them in a secret manager, and prefer read-only tokens for monitoring and read APIs. Claims in the JWT are a snapshot taken when it was issued; checks that matter, such as staff status and company membership, use the current database values.

To try the endpoints, open `/api/docs/`, click **Authorize**, choose **bearerAuth**, and paste your token.

## Related

- [JWT and JWKS](jwks.md): token claims and verification
- [Scheduled jobs](scheduled-jobs.md#monitoring): job health and alerting
- [Security hardening](security-hardening.md): PAT rate limits
