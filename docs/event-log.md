# Event log

identity-service records every catalog event in one table, `EventLog`, whether or not a webhook rule exists for it. The Shellui admin panel shows it under **Identity > Log events** and on each user profile.

---

## What is recorded

- Every [webhook catalog event](actions.md#event-catalog-identity) when it fires: account created or deleted, invitations, SCIM provisioning, group changes, SCIM tokens, magic link requests, SCIM conflicts.
- Sign-ins, as two log-only event types:

| Event type | When |
| ---------- | ---- |
| `identity.auth.login.succeeded` | A user signed in with OAuth, SAML, magic link, or the Django admin login form |
| `identity.auth.login.failed` | A sign-in was refused. The user is linked when it could be resolved |

Sign-in events cannot trigger webhook rules: anonymous traffic can produce failed sign-ins, and forwarding them would let anyone flood your endpoints.

`identity.user.updated` is not emitted by default, so it is not logged either.

## Row format

| Column | Content |
| ------ | ------- |
| `id` | Sequential id |
| `company` | Company the event belongs to. Empty for a sign-in that failed before the company was known |
| `user` | User the event is about, when there is one. Cleared when the user is deleted or removed from the company |
| `event_type` | Catalog event type |
| `data` | Event payload, compacted (see below) |
| `created_at` | When the event happened |

To keep rows small, `data` is the webhook payload with:

- empty values (`null`, empty strings and lists, `false`) removed
- `user_id` removed, since it is the `user` column
- secret fields removed: an event type can list fields that are never logged, sent to webhooks or stored. No webhook payload contains a sign-in link or token

Sign-in events store `provider`, `failure_reason`, `is_staff_at_event`, `ip_hash` (salted hash, never the raw IP), `user_agent` (truncated), `client_timezone`, `client_device_id_hash`, `client_country` and `client_city` (GeoIP, when configured).

The table has two indexes, `(company, created_at)` and `(user, created_at)`. They serve every listing, the user timeline, the retention check, and the purge.

## Retention

Each company has a **data retention** in days (`Company.data_retention_days`, default **7**). Only Shellui operators can change it, in Django admin under **Companies > Data retention**. Company owners see the value in the admin panel.

The [`purge_expired_data`](scheduled-jobs.md#purge_expired_data) scheduled job deletes events older than the retention, together with finished webhook deliveries and SCIM provisioning events. Schedule it every hour.

If events older than retention + 1 day are still stored, the job is not running. The admin panel dashboard, the **Log events** page, and the Django admin company page then show an error asking to configure the job.

## Admin REST API

Same authentication as other Shellui admin endpoints: Bearer JWT (or PAT) plus `company_id`. Callers must be Django staff or a company owner.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET` | `/api/v1/events` | Event log, newest first, paginated |
| `GET` | `/api/v1/events/<id>` | One event |
| `GET` | `/api/v1/events/types` | Event types with `label`, `description` and `webhook` (false for sign-ins) |
| `GET` | `/api/v1/events/retention` | `data_retention_days`, `oldest_event_at`, `stale_events` |

`GET /api/v1/events` filters:

| Parameter | Meaning |
| --------- | ------- |
| `event_type` | One type, or several separated by commas |
| `user_id` | User id |
| `user` | Case-insensitive part of the user email (also matches `data.email`, for invitations) |
| `created_after` | ISO 8601 datetime, inclusive |
| `created_before` | ISO 8601 datetime, exclusive |
| `page`, `page_size` | Pagination, `page_size` up to 100 (default 20) |

Example row:

```json
{
  "id": 1042,
  "company_id": 1,
  "created_at": "2026-10-02T09:14:03.120Z",
  "event_type": "identity.auth.login.failed",
  "label": "Sign-in failed",
  "user_id": 42,
  "user_email": "ada@acme.com",
  "data": {
    "provider": "github",
    "failure_reason": "Company access is disabled.",
    "ip_hash": "b5bb9d80…",
    "user_agent": "Mozilla/5.0 …"
  }
}
```

### Deprecated: `/api/v1/login-events`

`GET /api/v1/login-events` and `GET /api/v1/login-events/<id>` still answer with the former login audit shape (`outcome`, `provider`, `client_country`, …), reading sign-in rows from the event log. Use `GET /api/v1/events?event_type=identity.auth.login.succeeded,identity.auth.login.failed` instead.

## Related docs

- [Scheduled jobs](scheduled-jobs.md)
- [Shellui webhooks](actions.md)
