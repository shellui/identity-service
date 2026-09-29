# Action triggers (domain events → webhooks)

Company owners (and Django staff) can react when identity events happen (SCIM access changes, account create/delete, group changes, SCIM conflicts, token lifecycle) using **webhook Action rules** in the **Shellui admin API** or **Django admin**. Each rule maps a **catalog event type** (for example `identity.scim.user.provisioned`) to an HTTPS **webhook** endpoint.

Shellui identity stays the source of truth for domain events. Automation (n8n, Make, custom workers) consumes **outbound webhooks** on your URLs.

---

## How it works

```text
Business code calls emit_event(type, company, payload)
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
DeliveryAttempt audit log; retries via manage.py retry_webhooks
```

- **No Celery / Redis required** for actions — the outbox lives in Postgres (or SQLite locally).
- **SCIM and API paths never block** on slow external HTTP: delivery runs only after commit, with short webhook timeouts (default 5s).
- Delivery is **at-least-once**; dedupe on the envelope `id` (same value as the `webhook-id` header).

Magic-link sign-in emails are **not** Action rules. Identity sends them directly when a user requests a link (see [magic-link.md](magic-link.md)).

---

## Event catalog (`identity.*`)

| Event type | When it fires | Notes |
| ---------- | ------------- | ----- |
| `identity.scim.user.provisioned` | SCIM user create or re-enable (`active: true`) | Company **access** only; not account creation |
| `identity.scim.user.deprovisioned` | SCIM deprovision / `active: false` | Disables membership; user row remains |
| `identity.user.created` | First OAuth sign-in creates a User, or Django admin adds a user with company membership | **Company-scoped** |
| `identity.user.deleted` | Django admin or `DELETE /api/v1/user` (self-service) deletes a User | One emit **per company membership** before delete |
| `identity.user.updated` | — | Registered; **`emit_by_default=false`** |
| `identity.group.created` | SCIM or Django admin group create | |
| `identity.group.updated` | Display name / external id change | |
| `identity.group.deleted` | Group removed | |
| `identity.group.membership_changed` | SCIM group members add/remove/replace | |
| `identity.scim.token.created` | Admin REST or Django admin token create | No secret in payload |
| `identity.scim.token.revoked` | Token revoke | |
| `identity.scim.provisioning_conflict` | SCIM 409 / displayName collision | Ties to `ScimProvisioningEvent` |
| `identity.auth.magic_link.requested` | User requested a passwordless email sign-in link | Payload has `request_id`, `email`, `expires_at` — no secret or sign-in URL |

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
| `webhook-id` | Same as envelope `id` |
| `webhook-timestamp` | Unix seconds |
| `webhook-signature` | `v1,<base64(hmac_sha256)>` |

Signed content: `{webhook-id}.{webhook-timestamp}.{raw_body}` (UTF-8), HMAC-SHA256 with your `secret`.

Example verification (Python):

```python
import base64
import hashlib
import hmac


def verify_webhook(secret: str, webhook_id: str, timestamp: str, body: bytes, signature_header: str) -> bool:
    prefix = "v1,"
    if not signature_header.startswith(prefix):
        return False
    expected = hmac.new(
        secret.encode("utf-8"),
        f"{webhook_id}.{timestamp}.".encode("utf-8") + body,
        hashlib.sha256,
    ).digest()
    got = base64.b64decode(signature_header[len(prefix) :])
    return hmac.compare_digest(expected, got)
```

Reject requests with timestamps too far from clock skew if you enforce replay protection.

### SSRF protections

Before delivery, identity **resolves the webhook hostname once**, rejects private/link-local/reserved targets (unless private URLs are explicitly allowed), and opens the TCP connection to that resolved address while sending the original hostname in the `Host` header and TLS SNI.

---

## Delivery, retries, and cron

- After commit, identity attempts delivery once in a background thread (bounded timeout; errors never fail the user request).
- Failed deliveries schedule `next_attempt_at` with exponential backoff: **30s × 2^(attempt−1)**, capped at **1 hour**, up to **`ACTIONS_OUTBOX_MAX_ATTEMPTS`** (default **8**), then status **`dead`**.
- **Permanent failures** (most HTTP 4xx except **408** and **429**, SSRF block, disabled/deleted rule) go **dead** without further retries.
- Each attempt is logged in **Delivery attempts** (HTTP status, error excerpt, duration).

Retry pending rows with:

```bash
python manage.py retry_webhooks --batch-size 50 --max-seconds 50 --concurrency 4
```

Cron example (every minute):

```text
* * * * * cd /app && python manage.py retry_webhooks >> /var/log/retry_webhooks.log 2>&1
```

On **Coolify**, add a **Scheduled Task** on the same identity-service image with that command and a 1-minute interval. Keep `--max-seconds` below 60 so overlapping runs stay safe (skip-locked claims + lease).

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
| `GET` | `/api/v1/actions/deliveries` | Paginated delivery log |
| `GET` | `/api/v1/actions/deliveries/<uuid>` | Delivery detail with `envelope` and `attempts` |
| `POST` | `/api/v1/actions/deliveries/<uuid>/requeue` | Re-queue a row |

### Example: create a webhook rule

```json
POST /api/v1/actions/rules?company_id=1
{
  "name": "n8n user hook",
  "event_type": "identity.user.created",
  "url": "https://n8n.example.com/webhook/abc",
  "secret": "whsec_…"
}
```

List and detail responses expose webhook `secret_set` and `authorization_header_set` instead of plaintext secrets.

**Removed (admin UI):** email rule fields, email template endpoints, and `email_context_fields` on the events catalog. Magic-link email is always sent by identity on request (not configurable via Actions).

---

## Adding a new event type (developers)

1. Register the type in `apps/actions/identity_events.py`.
2. Call `emit_event(...)` or `emit_event_if_rules(...)` from the business path inside a transaction when appropriate.
3. Document the payload in this file and add tests under `apps/actions/tests/`.

To copy this pattern to **storage-service** or **hosting-service**, reuse the self-contained modules under `apps/actions/` (`emit.py`, `delivery.py`, `handlers/webhook.py`, `webhook_signing.py`, `webhook_transport.py`, `ssrf.py`, `management/commands/retry_webhooks.py`, models, and admin API views), register service-specific events, and wire `emit_event` from domain code.

---

## Related docs

- [SCIM](scim.md)
- [Configuration](configuration.md)
- [Magic link](magic-link.md)
