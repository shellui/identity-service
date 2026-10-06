# Action triggers (domain events → webhooks)

Company owners (and Django staff) can react when identity events happen (SCIM access changes, account create/delete, group changes, SCIM conflicts, token lifecycle) using **webhook Action rules** in the **Shellui admin API** or **Django admin**. Each rule maps a **catalog event type** (for example `identity.scim.user.provisioned`) to an HTTPS **webhook** endpoint.

Shellui identity stays the source of truth for domain events. Automation (n8n, Make, custom workers) consumes **outbound webhooks** on your URLs.

---

## How it works

```text
Business code calls emit_event(type, company, payload)
        │
        ▼
Record the event in the event log (always, rule or not)
        │
        ▼
Match enabled webhook ActionRule rows for that company + event type
        │
        ▼
Insert ActionOutbox row(s) in the same DB transaction
        │
        ▼
transaction.on_commit → best-effort delivery (timeout-bounded HTTP, off the request thread)
        │
        ▼
DeliveryAttempt audit log; retries by the retry_webhooks scheduled job
```

- The outbox lives in Postgres (or SQLite locally). Retries run every minute on the built-in scheduler, which uses Redis (`REDIS_URL`). See [Scheduled jobs](scheduled-jobs.md).
- **SCIM and API paths never block** on slow external HTTP: delivery runs only after commit, with short webhook timeouts (default 5s).
- Delivery is **at-least-once**; dedupe on the envelope `id` (same value as the `webhook-id` header).

Every event is also stored in the [event log](event-log.md), shown in the admin panel under **Log events** and kept for the company data retention.

Magic-link sign-in emails are **not** Action rules. Identity sends them directly when a user requests a link (see [magic-link.md](magic-link.md)).

---

## Event catalog (`identity.*`)

| Event type | When it fires | Notes |
| ---------- | ------------- | ----- |
| `identity.scim.user.provisioned` | SCIM user create or re-enable (`active: true`) | Company **access** only; not account creation |
| `identity.scim.user.deprovisioned` | SCIM deprovision / `active: false` | Disables membership; user row remains |
| `identity.user.created` | First OAuth, SAML or magic link sign-in creates a User (including an invitee's first sign-in), or Django admin adds a user with company membership | **Company-scoped** |
| `identity.user.invited` | `POST /api/v1/invitations` (admin panel **Invite user**) | No account exists yet: payload has `invitation_id`, `email`, `language` (invitation language), `invited_by`, `invitation_url` (app URL, not a credential), no `user_id`. While an enabled rule exists, identity-service skips its own invitation email |
| `identity.user.invitation_revoked` | `POST /api/v1/invitations/<id>/revoke` | Same payload plus `revoked_by`. Sign-in with that email is refused until a new invitation |
| `identity.user.deleted` | Django admin deletes a User, `DELETE /api/v1/users/<id>` (admin panel), or `DELETE /api/v1/user` (self-service) | Admin panel and self-service deletes emit for the current company only and keep accounts linked to other companies; Django admin emits **once per membership** before deleting the account |
| `identity.user.updated` | — | Registered; **`emit_by_default=false`** |
| `identity.group.created` | SCIM or Django admin group create | |
| `identity.group.updated` | Display name / external id change | |
| `identity.group.deleted` | Group removed | |
| `identity.group.membership_changed` | SCIM group members add/remove/replace | |
| `identity.scim.token.created` | Admin REST or Django admin token create | No secret in payload |
| `identity.scim.token.revoked` | Token revoke | |
| `identity.scim.provisioning_conflict` | SCIM 409 / displayName collision | Ties to `ScimProvisioningEvent` |
| `identity.auth.magic_link.requested` | User requested a passwordless email sign-in link | Notification only. Payload has `request_id`, `email`, `expires_at`, `source` and `language`, but never the sign-in link or token. Identity-service always sends the sign-in email itself, whether or not a rule exists |

Sign-ins are recorded in the [event log](event-log.md) as `identity.auth.login.succeeded` and `identity.auth.login.failed`. They are log-only and cannot be used in webhook rules.

### Envelope shape (webhooks)

CloudEvents-inspired JSON:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "identity.scim.user.provisioned",
  "time": "2026-09-24T13:30:00+00:00",
  "company": { "id": 1, "slug": "acme", "name": "Acme" },
  "data": {
    "user_id": 42,
    "email": "ada@acme.com",
    "username": "ada@acme.com",
    "source": "scim",
    "language": "en",
    "region": "UTC"
  }
}
```

Payloads never include secrets, bearer tokens, or password hashes.

---

## Configuring rules

### Django admin

1. Run migrations (`apps.actions` is in `INSTALLED_APPS`).
2. Open **Action rules** in Django admin.
3. Create a rule: company, **event type**, webhook URL, signing secret, optional Authorization header.

### Webhook config (stored JSON)

```json
{
  "url": "https://your-n8n.example.com/webhook/abc",
  "secret": "whsec_…",
  "authorization_header": "Bearer optional-static-token"
}
```

**Private / localhost webhooks:** Per-rule `allow_private_urls` is **not** available to regular staff — only a **superuser** can enable it in Django admin, or operators set deployment-wide `ACTIONS_WEBHOOK_ALLOW_PRIVATE=true`.

---

## Webhook signing (Standard Webhooks style)

Each POST includes:

| Header | Meaning |
| ------ | ------- |
| `webhook-id` | Same as envelope `id` (stable across retries for one delivery) |
| `webhook-timestamp` | Unix seconds |
| `webhook-signature` | `v1,<base64(hmac_sha256)>` |
| `X-Shellui-Event` | Catalog event type (for example `identity.user.created`) |
| `X-Shellui-Delivery-Attempt` | Attempt number for this outbox row (1 on first try) |
| `User-Agent` | `shellui-identity-actions/1.0` |

Signed content: `{webhook-id}.{webhook-timestamp}.{raw_body}` (UTF-8), HMAC-SHA256 with your signing key.

JSON body: compact separators, keys sorted, UTF-8 (`ensure_ascii=false`). Verify signatures against the **raw HTTP body**, not a re-serialized JSON object.

**Secrets:** prefer Standard Webhooks form `whsec_<base64>` (identity decodes the suffix as the HMAC key). Plain string secrets still work for existing rules.

Step-by-step n8n setup: [Using Shellui webhooks with n8n](n8n.md).

Reject requests with timestamps too far from clock skew if you enforce replay protection.

### SSRF protections

Before delivery, identity **resolves the webhook hostname once**, rejects private/link-local/reserved targets (unless private URLs are explicitly allowed), and opens the TCP connection to that resolved address while sending the original hostname in the `Host` header and TLS SNI.

---

## Delivery, retries, and scheduling

- After commit, identity attempts delivery once in a background thread (**5s** default timeout via `ACTIONS_WEBHOOK_TIMEOUT_SECONDS`; errors never fail the user request).
- Failed deliveries schedule `next_attempt_at` with exponential backoff: **30s * 2^(attempt-1)**, capped at **1 hour**, unless **429** or **503** returns **Retry-After** (then the larger of backoff and Retry-After applies, still capped at 1 hour).
- Up to **`ACTIONS_OUTBOX_MAX_ATTEMPTS`** (default **8**), then status **`dead`**.

| Outcome | Retry? |
| ------- | ------ |
| 2xx | No (delivered) |
| 404, 408, 409, 425, 429 | Yes (404 covers inactive n8n workflows) |
| 400, 401, 403, 405, 410, 413, 422 | No (dead) |
| 5xx | Yes |
| Timeouts, connection errors | Yes |
| SSRF block (private URL not allowed) | No (dead) |
| Disabled/deleted rule | No (dead) |

Each attempt is logged in **Delivery attempts** (HTTP status, error excerpt, duration).

The Docker image retries pending rows every minute with the `retry_webhooks` job, so there is nothing to schedule when `REDIS_URL` is set. To run it from your own scheduler instead, set `SCHEDULER_ENABLED=false` and run every minute:

```bash
python manage.py retry_webhooks --batch-size 50 --max-seconds 50 --concurrency 4
```

Keep `--max-seconds` below 60 so overlapping runs stay safe (skip-locked claims + lease).

Finished deliveries (`delivered`, `dead`) are deleted after the company data retention by `purge_expired_data`. See [Scheduled jobs](scheduled-jobs.md) for both jobs.

Flags:

- `--batch-size` (default 50)
- `--max-seconds` (default 50)
- `--concurrency` (default 4)
- `--dry-run` (claim only, no HTTP)

Re-queue a **dead** row from Django admin or `POST /api/v1/actions/deliveries/<uuid>/requeue`.

---

## Company admin REST API (`/api/v1/actions/`)

Same authentication as other Shellui admin endpoints: Bearer JWT (or PAT) plus `company_id` query parameter. Callers must be **Django staff** or a **company owner** for that company.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET` | `/api/v1/actions/events` | Event catalog with `payload_fields` and `sample_envelope` |
| `GET` | `/api/v1/actions/rules` | List webhook rules (secrets redacted) |
| `POST` | `/api/v1/actions/rules` | Create a webhook rule |
| `GET` | `/api/v1/actions/rules/<id>` | Rule detail |
| `PATCH` | `/api/v1/actions/rules/<id>` | Update fields or config |
| `DELETE` | `/api/v1/actions/rules/<id>` | Delete a rule |
| `POST` | `/api/v1/actions/rules/<id>/send-test` | POST a sample envelope to the rule URL (no outbox row) |
| `POST` | `/api/v1/actions/rules/<id>/rotate-secret` | Generate a new `whsec_` signing secret (returned once) |
| `GET` | `/api/v1/actions/deliveries` | Paginated delivery log |
| `GET` | `/api/v1/actions/deliveries/<uuid>` | Delivery detail with `envelope` and `attempts` |
| `POST` | `/api/v1/actions/deliveries/<uuid>/requeue` | Re-queue a row |

### Example: create a webhook rule

Omit `secret` (or send a blank value) to auto-generate a Standard Webhooks secret (`whsec_…`). The **create** response matches rule GET plus top-level `secret` with the stored plaintext (generated or client-provided). List, GET, and PATCH never include top-level `secret`.

```json
POST /api/v1/actions/rules?company_id=1
{
  "name": "n8n user hook",
  "event_type": "identity.user.created",
  "url": "https://n8n.example.com/webhook/abc"
}
```

Example **201** body (same fields as GET `/rules/<id>`, plus `secret`):

```json
{
  "id": 1,
  "company_id": 1,
  "name": "n8n user hook",
  "event_type": "identity.user.created",
  "enabled": true,
  "action_kind": "webhook",
  "secret": "whsec_…",
  "config": {
    "url": "https://n8n.example.com/webhook/abc",
    "has_secret": true,
    "secret_hint": "abcd",
    "authorization_header_set": false
  },
  "created_at": "…",
  "updated_at": "…"
}
```

### Rotate signing secret

```json
POST /api/v1/actions/rules/1/rotate-secret?company_id=1
```

**200** response uses the same flat shape as create and GET, with a new top-level `secret` (update n8n before the next delivery):

```json
{
  "id": 1,
  "company_id": 1,
  "name": "n8n user hook",
  "event_type": "identity.user.created",
  "enabled": true,
  "action_kind": "webhook",
  "secret": "whsec_…",
  "config": {
    "url": "https://n8n.example.com/webhook/abc",
    "has_secret": true,
    "secret_hint": "wxyz",
    "authorization_header_set": false
  },
  "created_at": "…",
  "updated_at": "…"
}
```

List, detail, and update responses never include top-level `secret`. Webhook `config` includes `has_secret`, optional `secret_hint` (last four characters), and `authorization_header_set` instead of plaintext values.

**Removed (admin UI):** email rule fields, email template endpoints, and `email_context_fields` on the events catalog. Company email for catalog events is a separate call to email-service. See [email-service.md](email-service.md). Magic-link and invitation mail still skip the built-in send while an enabled webhook rule for that event exists.

---

## Adding a new event type (developers)

1. Register the type in `apps/actions/identity_events.py`. List payload keys that are live credentials in `sensitive_fields` so they are never written to the event log, and set `webhook=False` for log-only events.
2. Call `emit_event(...)` or `emit_event_if_rules(...)` from the business path inside a transaction when appropriate.
3. Document the payload in this file and add tests under `apps/actions/tests/`.

To copy this pattern to **storage-service** or **hosting-service**, reuse the self-contained modules under `apps/actions/` (`emit.py`, `event_log.py`, `retention.py`, `delivery.py`, `handlers/webhook.py`, `webhook_signing.py`, `webhook_transport.py`, `ssrf.py`, `management/commands/retry_webhooks.py`, `management/commands/purge_expired_data.py`, `tasks.py`, models, and admin API views, plus `config/celery.py` and `config/task_lock.py` for the scheduler), register service-specific events, and wire `emit_event` from domain code.

---

## Related docs

- [Event log](event-log.md)
- [Scheduled jobs](scheduled-jobs.md)
- [SCIM](scim.md)
- [Configuration](configuration.md)
- [Magic link](magic-link.md)
