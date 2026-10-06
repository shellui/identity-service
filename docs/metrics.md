# Accessing platform metrics

The service exposes **Prometheus-compatible** metrics over HTTP:

| Endpoint | Scope |
| -------- | ----- |
| `GET /api/v1/metrics` | Metrics for **one company** |
| `GET /api/v1/metrics/all` | Metrics **across all companies** (privileged) |

Both endpoints accept a **Bearer token** that is a **Shellui JWT** — either from the normal login/refresh flow or from a **personal access token (PAT)** created in Shellui Admin. PATs are signed JWTs with the same claim shape; they include `pat_id` / `pat_ro` and are validated against a database row (revocation, `jti`).

Responses are **plain text** (OpenMetrics/Prometheus exposition), not JSON.

---

## Company metrics — `GET /api/v1/metrics`

- **Authorization:** `Bearer <JWT or PAT>` — the token **must** include a `company_id` claim; that company is the only scope for this endpoint.
- **Do not** pass `company_id` in the query string (or body); it is rejected with `400`.

**Who may call:** Django `is_staff`, or a user who is an **owner** of that company (the company from the token).

Metrics use **GET** only; a **read-only PAT** (`pat_ro`) is sufficient.

**What it returns:** only series for the token's company, built for each request:

| Metric | Labels |
| ------ | ------ |
| `shellui_auth_company_users_total` | `company_id` |
| `shellui_auth_company_users_active` | `company_id` |
| `shellui_auth_company_users_staff` | `company_id` |
| `shellui_auth_company_social_accounts_total` | `company_id` |
| `shellui_auth_company_daily_active_users` | `company_id` |
| `shellui_auth_company_weekly_active_users` | `company_id` |
| `shellui_auth_company_monthly_active_users` | `company_id` |
| `shellui_auth_successful_logins_total` | `company_id`, `provider` (since the answering process started) |

It never includes process or Python runtime metrics, platform-wide user counts, scheduled job metrics, or any series of another company. Staff calling this endpoint get the same company-only view; use `/api/v1/metrics/all` for everything.

---

## Global metrics — `GET /api/v1/metrics/all`

- **Authorization:** `Bearer <JWT or PAT>`
- **Who may call:**
  - Django **staff** (session JWT: `user.is_staff` when authenticated), or
  - A **personal access token** created with **`access_global_metrics`** by staff (JWT claim `pat_agm: true`, validated against the token row).

**What it returns:** process and Python runtime metrics, platform-wide user gauges (`shellui_auth_users_*`, `shellui_auth_social_accounts_total`, `shellui_auth_*_active_users`), `shellui_auth_successful_logins_total` for every company, and the scheduled job metrics below. Per-company `shellui_auth_company_*` gauges are only on the company endpoint.

Enable global PAT scope in **Shellui Admin → Access tokens** (staff-only checkbox) or in **Django admin** on the `PersonalAccessToken` row. Existing PAT strings do not pick up flag changes until you **re-issue** the PAT: the JWT must include `pat_agm` matching the database.

Example:

```bash
curl -sS 'http://localhost:8000/api/v1/metrics' \
  -H 'Authorization: Bearer <JWT or PAT>'

curl -sS 'http://localhost:8000/api/v1/metrics/all' \
  -H 'Authorization: Bearer <JWT or PAT>'
```

### Scheduled job metrics

The global endpoint also exposes `shellui_auth_scheduled_job_*` and `shellui_auth_scheduler_*` metrics for the `retry_webhooks` and `purge_expired_data` jobs. The company endpoint never includes them. Names, labels and alert rules are in [Scheduled jobs monitoring](scheduled-jobs.md#prometheus-metrics).

---

## Personal access tokens (PAT)

- Created under Admin **Access tokens** (`POST /api/v1/personal-access-tokens`). The response returns `access_token` once.
- **Read-only PAT:** `pat_ro` is true — only safe HTTP methods (GET, HEAD, OPTIONS) are allowed across the API, including this metrics GET.
- **Write PAT:** same endpoints and rules as a session JWT for your user (with `PERSONAL_ACCESS_TOKEN_LIFETIME` expiry).
- Revoking the PAT invalidates the JWT immediately. Successful use updates **`last_used_at`** on the PAT row.

### Security notes

- Treat PATs like passwords: HTTPS only, store in a secret manager, prefer read-only when you only need observability or read APIs.
- JWT claims are **point-in-time** at issuance; authorization that matters (e.g. `is_staff`, membership) is enforced using the **live** `User` from the database where applicable.

For OpenAPI details, open **`/api/docs/`**. Click **Authorize**, choose **bearerAuth**, and paste your access JWT (or PAT); metrics require that scheme like other protected routes.
