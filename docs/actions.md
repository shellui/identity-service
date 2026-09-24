# Action triggers (domain events → email / webhook)

Company admins can react when identity events happen (SCIM access changes, account create/delete, group changes, SCIM conflicts, token lifecycle) using **Action rules** configured in **Django admin**. Each rule maps a **catalog event type** (for example `identity.scim.user.provisioned`) to either **email** or **webhook** delivery.

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
| `identity.user.deleted` | Django admin deletes a User | One emit **per company membership** before delete |
| `identity.user.updated` | — | Registered; **`emit_by_default=false`** — no call sites; use `emit_event(..., force=True)` if added later |
| `identity.group.created` | SCIM or Django admin group create | |
| `identity.group.updated` | Display name / external id change | |
| `identity.group.deleted` | Group removed | |
| `identity.group.membership_changed` | SCIM group members add/remove/replace | |
| `identity.scim.token.created` | Admin REST or Django admin token create | No secret in payload |
| `identity.scim.token.revoked` | Token revoke | |
| `identity.scim.provisioning_conflict` | SCIM 409 / displayName collision | Ties to `ScimProvisioningEvent` |

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
    "source": "scim"
  }
}
```

Payloads never include secrets, bearer tokens, or password hashes.

### SCIM access vs account lifecycle

- **`identity.scim.user.*`** — IdP-driven **company access** (membership enable/disable). SCIM may create a Django user on first provision; that still emits `identity.scim.user.provisioned`, not `identity.user.created`.
- **`identity.user.created` / `deleted`** — **Account** lifecycle (OAuth registration, admin user CRUD). There is no self-service delete API in identity today; admin delete is wired in Django admin.

**When `identity.user.created` fires:** OAuth flows are always company-scoped (`company_id`). Identity emits when `User.objects.get_or_create` creates a **new** user row for that OAuth company (even if company join is later denied). It does **not** fire when an existing user joins another company. Django admin emits after a new user is saved **if** at least one company membership exists on save (via the admin M2M step); users created without a company are skipped until membership is added manually (no retroactive emit).

**When `identity.user.deleted` fires:** Before the user row is removed, identity emits once per `CompanyMembership` (source `admin` today).

#### Example `data` fields by type

- **User / SCIM user events:** `user_id`, `email`, `username`, `source` (`scim`, `oauth`, `admin`, …); OAuth create may include `oauth_provider`
- **Group events:** `group_id`, `display_name`, `source`, `external_id`; updates add `changed_fields`
- **Membership:** above plus `change`, `user_ids`, `nested_group_ids`
- **SCIM token:** `token_id`, `name`, `token_prefix` (not the bearer secret)
- **Provisioning conflict:** `display_name`, `operation`, `conflicting_group_id`, `conflicting_group_source`, `http_status`, `channel`

---

## Configuring rules in Django admin

1. Run migrations (`apps.actions` is in `INSTALLED_APPS`).
2. Open **Action rules** in Django admin.
3. Create a rule: company, **event type** from the catalog, **email** or **webhook**, JSON **config**.

### Email config

```json
{
  "recipients": ["ops@example.com", "security@example.com"],
  "include_payload_email": false
}
```

- `recipients` — required list of addresses.
- `include_payload_email` — when `true`, also sends to the event’s documented email field (for user events, `data.email`) when present.

Default **HTML** templates ship under `apps/actions/templates/actions/emails/<event_type>.html`. Plain text is generated from the rendered HTML at send time (multipart `alternative` still includes both parts).

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

View **Action outbox** and **Delivery attempts** in Django admin; use the admin action **Retry delivery** on failed rows.

---

## Adding a new event type (developers)

1. Register the type in `apps/actions/identity_events.py` (or a sibling module imported from `AppsConfig.ready()`).
2. Add one HTML template under `apps/actions/templates/actions/emails/<event_type>.html`.
3. Call `emit_event(...)` or `emit_event_if_rules(...)` from the business path inside a transaction when appropriate.
4. Document the payload in this file and add tests under `apps/actions/tests/`.

Use `emit_event_if_rules` on hot paths where missing registry entries should not break requests.

---

## Related docs

- [SCIM](scim.md) — provisioning paths that emit many identity events
- [Configuration](configuration.md) — email backend and action settings
