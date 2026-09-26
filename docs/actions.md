# Action triggers (domain events → email / webhook)

Company owners (and Django staff) can react when identity events happen (SCIM access changes, account create/delete, group changes, SCIM conflicts, token lifecycle) using **Action rules** in the **Shellui admin API** or **Django admin**. Each rule maps a **catalog event type** (for example `identity.scim.user.provisioned`) to either **email** or **webhook** delivery.

Shellui identity stays the source of truth for domain events. Automation (n8n, Make, custom workers) consumes **outbound webhooks**; identity does not run a central action microservice.

---

## How it works

```text
Business code calls emit_event(type, company, payload)
        │
        ▼
Match enabled ActionRule rows for that company + event type
        │
        ▼
Insert ActionOutbox row(s) in the same DB transaction
        │
        ▼
transaction.on_commit → best-effort delivery (timeout-bounded HTTP / email)
        │
        ▼
DeliveryAttempt audit log; retries via manage.py drain_action_outbox
```

- **No Celery / Redis required** for actions — the outbox lives in Postgres (or SQLite locally).
- **SCIM and API paths never block** on slow external HTTP: delivery runs only after commit, with short webhook timeouts.
- Delivery is **at-least-once**; use the envelope `id` field as an idempotency key in downstream systems.

---

## Event catalog (`identity.*`)

| Event type | When it fires | Notes |
| ---------- | ------------- | ----- |
| `identity.scim.user.provisioned` | SCIM user create or re-enable (`active: true`) | Company **access** only; not account creation |
| `identity.scim.user.deprovisioned` | SCIM deprovision / `active: false` | Disables membership; user row remains |
| `identity.user.created` | First OAuth sign-in creates a User, or Django admin adds a user with company membership | **Company-scoped** — see below |
| `identity.user.deleted` | Django admin or `DELETE /api/v1/user` (self-service) deletes a User | One emit **per company membership** before delete; `data.source` is `admin` or `self` |
| `identity.user.updated` | — | Registered; **`emit_by_default=false`** — no call sites; use `emit_event(..., force=True)` if added later |
| `identity.group.created` | SCIM or Django admin group create | |
| `identity.group.updated` | Display name / external id change | |
| `identity.group.deleted` | Group removed | |
| `identity.group.membership_changed` | SCIM group members add/remove/replace | |
| `identity.scim.token.created` | Admin REST or Django admin token create | No secret in payload |
| `identity.scim.token.revoked` | Token revoke | |
| `identity.scim.provisioning_conflict` | SCIM 409 / displayName collision | Ties to `ScimProvisioningEvent` |
| `identity.auth.magic_link.requested` | User requested a passwordless email sign-in link | Webhook payload has `request_id`, `email`, `expires_at` — no secret; email templates get `magic_link_url` at send time |

### Envelope shape (webhooks and email context)

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

### SCIM access vs account lifecycle

- **`identity.scim.user.*`** — IdP-driven **company access** (membership enable/disable). SCIM may create a Django user on first provision; that still emits `identity.scim.user.provisioned`, not `identity.user.created`.
- **`identity.user.created` / `deleted`** — **Account** lifecycle (OAuth registration, admin user CRUD, self-service `DELETE /api/v1/user`).

**When `identity.user.created` fires:** OAuth flows are always company-scoped (`company_id`). Identity emits when `User.objects.get_or_create` creates a **new** user row for that OAuth company (even if company join is later denied). It does **not** fire when an existing user joins another company. Django admin emits after a new user is saved **if** at least one company membership exists on save (via the admin M2M step); users created without a company are skipped until membership is added manually (no retroactive emit).

**When `identity.user.deleted` fires:** Before the user row is removed, identity emits once per `CompanyMembership` (`source` `admin` or `self`).

#### Example `data` fields by type

- **User / SCIM user events:** `user_id`, `email`, `username`, `source` (`scim`, `oauth`, `admin`, `self`, …), `language` and `region` from the user’s `UserPreference` (defaults `en` / `UTC` when unset); OAuth create may include `oauth_provider`
- **Group events:** `group_id`, `display_name`, `source`, `external_id`; updates add `changed_fields`
- **Membership:** above plus `change`, `user_ids`, `nested_group_ids`
- **SCIM token:** `token_id`, `name`, `token_prefix` (not the bearer secret)
- **Provisioning conflict:** `display_name`, `operation`, `conflicting_group_id`, `conflicting_group_source`, `http_status`, `channel`

---

## Configuring rules in Django admin

1. Run migrations (`apps.actions` is in `INSTALLED_APPS`).
2. Open **Action rules** in Django admin.
3. Create a rule: company, **event type** from the catalog, **email** or **webhook**, then fill the structured email or webhook fields.

### Email config

The admin form exposes:

- **Also send to email from event payload** — maps to `include_payload_email` in stored config. When checked, delivery also goes to the catalog’s payload email field (usually `data.email` on user / SCIM user events). Help text updates when the selected event type supports this. Has no effect for event types without a payload email field.
- **Fixed email recipients (To:)** — comma-separated addresses always included; optional if payload email alone is enough for your event type.

Stored JSON shape:

```json
{
  "recipients": ["ops@example.com", "security@example.com"],
  "include_payload_email": true,
  "email_templates": {
    "en": {
      "subject": "Optional override subject",
      "html": "<!DOCTYPE html><html><body>...</body></html>"
    }
  }
}
```

#### Email language (i18n)

Action emails are **locale-aware**. **English (`en`)** and **French (`fr`)** ship for **every catalog event**, each with a **full HTML body** plus a subject line. Subject `.txt` files alone are not sufficient — the HTML template is the content source of truth.

- **HTML body (required):** `apps/actions/templates/actions/emails/<language>/<event_type>.html` — multipart emails attach this as `text/html`.
- **Subject line:** `apps/actions/templates/actions/emails/<language>/subjects/<event_type>.txt` (Django template syntax; same context as the body: `data`, `envelope`)

Additional locales follow the same layout (HTML body + subject per event).

Legacy flat paths `apps/actions/templates/actions/emails/<event_type>.html` are still tried as a last resort for custom deployments.

**Resolution order** (body and subject use the same chain):

1. **Per-rule override** — when the rule’s `config.email_templates[<language>]` includes `html` (and `subject`), that content wins for that locale (Django template syntax; same context as filesystem templates).
2. **Recipient user’s preferred language** — from `data.language` on the event payload (`UserPreference.language`), when the message is sent to the address from **Also send to email from event payload** (`include_payload_email`).
3. **Deployment default language** — `ACTIONS_EMAIL_DEFAULT_LANGUAGE` (default `en`).
4. **`en`** — always the final fallback when a template file is missing for the preferred language.

**Fixed ops recipients** (the comma-separated **To:** list) always use the deployment default language chain (steps 2 → 3), not the end user’s preference. When both fixed recipients and payload email are configured, identity sends **separate messages** so each audience gets the correct locale.

**Plain text** is not authored separately: it is generated from the rendered HTML at send time via `html2text` (`apps/actions/html_plain.py`). Multipart `alternative` delivery includes both the derived plain part and the HTML part.

Add further locales by copying the `en` (or `fr`) tree under `…/emails/<language>/` with matching `subjects/` files.

### Webhook config

Django admin uses structured fields (not raw JSON) so secrets are write-only. Stored JSON shape:

```json
{
  "url": "https://your-n8n.example.com/webhook/abc",
  "secret": "whsec_…",
  "authorization_header": "Bearer optional-static-token"
}
```

- `url` — HTTPS (or HTTP) endpoint; must resolve to a public address (see SSRF below).
- `secret` — HMAC signing key (stored in DB; treat as sensitive). Blank on edit in admin = unchanged.
- `authorization_header` — optional full `Authorization` header value for tools that require static bearer tokens.

**Private / localhost webhooks:** Per-rule `allow_private_urls` is **not** available to regular staff — only a **superuser** can enable it in Django admin, or operators set deployment-wide `ACTIONS_WEBHOOK_ALLOW_PRIVATE=true` in the environment. This prevents SSRF bypass via rule config alone.

---

## Webhook signing (n8n / Standard Webhooks style)

Each POST includes:

| Header | Meaning |
| ------ | ------- |
| `webhook-id` | Same as envelope `id` |
| `webhook-timestamp` | Unix seconds |
| `webhook-signature` | `v1,<base64(hmac_sha256)>` |

Signed content: `{webhook-id}.{webhook-timestamp}.{raw_body}` (UTF-8), HMAC-SHA256 with your `secret`.

Verify in n8n or a small function node before trusting the body. Reject requests with timestamps too far from clock skew if you enforce replay protection.

### SSRF protections

Before delivery, identity **resolves the webhook hostname once**, rejects private/link-local/reserved targets (unless private URLs are explicitly allowed), and opens the TCP connection to that resolved address while sending the original hostname in the `Host` header and TLS SNI. Validation and connect therefore use the same IP for that resolution.

**Residual limits:** DNS could in theory change between resolve and connect if a record’s TTL expires in that window (we do not re-resolve on connect). Redirect-following is not performed. Prefer HTTPS endpoints with stable public DNS.

---

## Outbox, drain, and local development

- After commit, identity attempts delivery once in-process.
- Failed or pending rows retry when you run:

```bash
python manage.py drain_action_outbox --batch-size 50
```

Schedule that via cron or a second container using the **same app image** (optional; not required for local dev).

**Local DX:** SQLite or Postgres + `runserver` is enough. Set:

```bash
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
# or locmem for tests
```

Optional settings (see [configuration.md](configuration.md)):

- `ACTIONS_WEBHOOK_TIMEOUT_SECONDS` (default `10`)
- `ACTIONS_OUTBOX_MAX_ATTEMPTS` (default `5`)
- `ACTIONS_WEBHOOK_ALLOW_PRIVATE` (default `false`)
- `ACTIONS_EMAIL_DEFAULT_LANGUAGE` (default `en`) — fallback locale for ops recipients and when a user’s preferred template is missing

---

## Company admin REST API (`/api/v1/actions/`)

Same authentication as other Shellui admin endpoints: Bearer JWT (or PAT) plus `company_id` query parameter. Callers must be **Django staff** or a **company owner** for that company. Regular members receive **403**.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET` | `/api/v1/actions/events` | Registered event catalog (`type`, `label`, `description`, `emit_by_default`, `payload_email_field`, `supported_action_kinds`). |
| `GET` | `/api/v1/actions/events/<event_type>/email-template?language=en` | Default filesystem subject and HTML for create/edit (`source`: `filesystem`; unrendered template source, not sample data). |
| `GET` | `/api/v1/actions/rules` | List action rules for the company (webhook secrets redacted). |
| `POST` | `/api/v1/actions/rules` | Create a rule. |
| `GET` | `/api/v1/actions/rules/<id>` | Rule detail. |
| `PATCH` | `/api/v1/actions/rules/<id>` | Update fields or config. Blank webhook `secret` or `authorization_header` keeps existing values. |
| `DELETE` | `/api/v1/actions/rules/<id>` | Delete a rule. |
| `GET` | `/api/v1/actions/rules/<id>/email-template?language=en` | Effective subject and HTML for an existing rule (`source`: `override` or rendered `filesystem` preview). |
| `GET` | `/api/v1/actions/deliveries` | Paginated delivery log (`status`, `event_type`, `action_rule_id`, `created_after`, `created_before`, `page`, `page_size`). |
| `GET` | `/api/v1/actions/deliveries/<uuid>` | Delivery detail with `envelope` and `attempts`. |
| `POST` | `/api/v1/actions/deliveries/<uuid>/requeue` | Re-queue a row (same as Django admin re-queue). |

### Example: create an email rule

```json
POST /api/v1/actions/rules?company_id=1
{
  "name": "Notify ops on new users",
  "event_type": "identity.user.created",
  "action_kind": "email",
  "recipients": ["ops@example.com"],
  "include_payload_email": true,
  "email_templates": {
    "en": {
      "subject": "New user {{ data.email }}",
      "html": "<!DOCTYPE html><html><body><p>User {{ data.email }} joined.</p></body></html>"
    }
  }
}
```

List and detail responses expose webhook `secret_set` and `authorization_header_set` instead of plaintext secrets. Per-language HTML overrides must be standalone (no `<script>` tags or remote stylesheets). When `html` is set, `subject` is required for that locale.

### Example: webhook rule (create)

```json
POST /api/v1/actions/rules?company_id=1
{
  "name": "n8n user hook",
  "event_type": "identity.user.created",
  "action_kind": "webhook",
  "url": "https://n8n.example.com/webhook/abc",
  "secret": "whsec_…"
}
```

Only **superusers** may set `allow_private_urls` on create or update (same policy as Django admin).

---

### Debugging delivery in Django admin

Delivery history lives in Postgres and is also available via **`GET /api/v1/actions/deliveries`**. In Django admin, open **Action deliveries** for one row per fired rule (outbox) or **Delivery attempts** for each HTTP or email try.

| Outbox status | Meaning |
| ------------- | ------- |
| `pending` | Waiting for the next delivery attempt (including after re-queue). |
| `delivered` | Last attempt succeeded; see `delivered_at`. |
| `failed` | Last attempt failed; will retry until max attempts. |
| `dead` | Gave up after max attempts; fix the rule or payload, then re-queue. |

On an **Action delivery** detail page, **Delivery attempts** are listed inline (newest first). Each attempt is `success` or `failure`. Email actions usually leave `http_status` empty on success. Webhook attempts record `http_status` when the HTTP client got a response.

To retry failed or dead rows: select them on the **Action deliveries** list, choose **Re-queue selected outbox rows for delivery**, then run `manage.py drain_action_outbox` (or wait for in-process delivery on new events).

On an **Action rule** change page, **Recent deliveries** shows up to 20 latest outbox rows for that rule so you can see whether it fired.

---

## Adding a new event type (developers)

1. Register the type in `apps/actions/identity_events.py` (or a sibling module imported from `AppsConfig.ready()`).
2. Add HTML and subject templates under `apps/actions/templates/actions/emails/en/<event_type>.html` and `…/en/subjects/<event_type>.txt` (plus other locales as needed).
3. Call `emit_event(...)` or `emit_event_if_rules(...)` from the business path inside a transaction when appropriate.
4. Document the payload in this file and add tests under `apps/actions/tests/`.

Use `emit_event_if_rules` on hot paths where missing registry entries should not break requests.

---

## Related docs

- [SCIM](scim.md) — provisioning paths that emit many identity events
- [Configuration](configuration.md) — email backend and action settings
