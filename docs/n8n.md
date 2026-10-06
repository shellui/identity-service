# Using Shellui webhooks with n8n

Shellui identity-service (and sibling hosting-service and storage-service) can POST signed JSON to an n8n **Webhook** node when domain events fire. This page shows a production-ready n8n setup, signature verification, and how retries behave when a workflow is inactive.

---

## Before you start

You need a Shellui company with at least one **webhook rule** in the Shellui admin API or Django admin. Each delivery uses Standard Webhooks headers plus `X-Shellui-Event` and `X-Shellui-Delivery-Attempt`. Dedupe on `webhook-id` (same id on every retry for one outbox row).

Identity uses a **5s** HTTP timeout by default (`ACTIONS_WEBHOOK_TIMEOUT_SECONDS`). In n8n, set the Webhook node **Respond** to **Immediately** so the workflow returns before long-running steps.

---

## Create the Webhook node

1. Add a **Webhook** node to your workflow.
2. Set **HTTP Method** to **POST**.
3. Copy the **Production URL** into your Shellui webhook rule (stable while the workflow stays active).
4. For first-time wiring, open **Listen for test event** and use **Send test event** in Shellui admin (`POST /api/v1/actions/rules/<id>/send-test`). n8n shows **404** when nothing is listening; that is retryable once the workflow is active.
5. **Activate** the workflow before you rely on production traffic.

Optional **Authorization**: paste a static header value into the Shellui rule (for example `Bearer your_n8n_static_token`) and configure n8n **Header Auth** or **Basic Auth** on the Webhook node to match.

Enable **Raw Body** (or equivalent) in n8n so signature verification reads the exact bytes Shellui signed, not a re-parsed JSON object.

---

## Verify the signature in n8n (Code node)

Add a **Code** node immediately after the Webhook node. Use **JavaScript** and pass the signing secret from an n8n credential or environment variable.

```javascript
const crypto = require("crypto");

const MAX_AGE_SECONDS = 300;
const secret = $env.SHELLUI_WEBHOOK_SECRET; // or $credentials.shelluiWebhookSecret

function signingKey(raw) {
  const trimmed = String(raw || "").trim();
  if (trimmed.startsWith("whsec_")) {
    return Buffer.from(trimmed.slice("whsec_".length), "base64");
  }
  return Buffer.from(trimmed, "utf8");
}

const webhookId = $headers["webhook-id"];
const timestamp = $headers["webhook-timestamp"];
const signature = $headers["webhook-signature"];
const rawBody = $json.bodyRaw ?? Buffer.from(JSON.stringify($json.body)).toString("utf8");

if (!webhookId || !timestamp || !signature) {
  throw new Error("Missing Standard Webhooks headers");
}

const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
if (age > MAX_AGE_SECONDS) {
  throw new Error("Webhook timestamp too old");
}

const prefix = "v1,";
if (!String(signature).startsWith(prefix)) {
  throw new Error("Unsupported signature version");
}

const signed = Buffer.concat([
  Buffer.from(`${webhookId}.${timestamp}.`, "utf8"),
  Buffer.from(rawBody, "utf8"),
]);

const expected = crypto.createHmac("sha256", signingKey(secret)).update(signed).digest();
const got = Buffer.from(String(signature).slice(prefix.length), "base64");

if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) {
  throw new Error("Invalid webhook signature");
}

return [{ json: JSON.parse(rawBody) }];
```

Shellui serializes JSON with compact separators and UTF-8 (`ensure_ascii=false`). n8n may still re-serialize if you verify against `$json` instead of raw bytes. Always verify the **raw request body**.

Reference script (same algorithm): [docs/examples/verify-shellui-webhook.mjs](examples/verify-shellui-webhook.mjs).

---

## Node.js verifier (outside n8n)

```javascript
import crypto from "node:crypto";

function signingKey(secret) {
  const s = secret.trim();
  if (s.startsWith("whsec_")) {
    return Buffer.from(s.slice("whsec_".length), "base64");
  }
  return Buffer.from(s, "utf8");
}

export function verifyShelluiWebhook({
  secret,
  webhookId,
  timestamp,
  signatureHeader,
  rawBody,
  maxAgeSeconds = 300,
}) {
  const prefix = "v1,";
  if (!signatureHeader.startsWith(prefix)) return false;
  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (age > maxAgeSeconds) return false;
  const signed = Buffer.concat([
    Buffer.from(`${webhookId}.${timestamp}.`, "utf8"),
    rawBody,
  ]);
  const expected = crypto.createHmac("sha256", signingKey(secret)).update(signed).digest();
  const got = Buffer.from(signatureHeader.slice(prefix.length), "base64");
  return got.length === expected.length && crypto.timingSafeEqual(got, expected);
}
```

---

## Signing secrets (`whsec_`)

New secrets can use Standard Webhooks form: `whsec_` plus base64 key material. Identity accepts:

- `whsec_<base64>` (decoded bytes used as HMAC key)
- Legacy plain strings (UTF-8 bytes as key)

Existing rules keep working with plain secrets. No database migration is required when you rotate to `whsec_`.

When you create a webhook rule through the Shellui admin API, the **201** response is the same shape as rule GET plus top-level `secret` (auto-generated when you omit `secret`, or echoing the value you sent). Store it in n8n (credential or environment variable). Rotate with `POST /api/v1/actions/rules/<id>/rotate-secret`: the **200** body matches GET plus a new top-level `secret`. List, GET, and PATCH rule calls never include top-level `secret`.

You can also generate a secret in Python (Django shell):

```python
from apps.actions.webhook_signing import generate_webhook_signing_secret
generate_webhook_signing_secret()
```

---

## Retry behavior (n8n-specific)

| HTTP result | Shellui action |
| ----------- | -------------- |
| 2xx | Delivered |
| 404 (inactive workflow, test URL not listening) | Retry with backoff |
| 408, 409, 425, 429 | Retry (429/503 honor `Retry-After`, capped at 1 hour) |
| 5xx | Retry |
| 400, 401, 403, 405, 410, 413, 422 | Dead (fix config, then requeue) |
| Timeouts, connection errors | Retry |

identity-service retries every minute with its built-in `retry_webhooks` job (see [Scheduled jobs](scheduled-jobs.md)).

Re-queue dead rows from the delivery log in Shellui admin or `POST /api/v1/actions/deliveries/<uuid>/requeue`.

---

## Self-hosted n8n on a private network

Cloud identity cannot reach `http://n8n:5678/...` unless you allow it:

- Deployment-wide: `ACTIONS_WEBHOOK_ALLOW_PRIVATE=true`
- Per rule (superuser): `allow_private_urls` on the webhook rule

Use this only for Docker/Coolify networks you control.

---

## Example envelopes

### `identity.user.created`

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "identity.user.created",
  "time": "2026-09-24T13:30:00+00:00",
  "company": { "id": 1, "slug": "acme", "name": "Acme" },
  "data": {
    "user_id": 42,
    "email": "ada@acme.com",
    "username": "ada@acme.com",
    "source": "oauth",
    "language": "en",
    "region": "UTC"
  }
}
```

### `identity.user.invited`

```json
{
  "id": "880e8400-e29b-41d4-a716-446655440003",
  "type": "identity.user.invited",
  "time": "2026-09-24T13:30:30+00:00",
  "company": { "id": 1, "slug": "acme", "name": "Acme" },
  "data": {
    "invitation_id": 7,
    "email": "ada@acme.com",
    "language": "fr",
    "invited_by": "grace@acme.com",
    "invitation_url": "https://app.acme.com/",
    "source": "invitation"
  }
}
```

While this rule is enabled, identity-service does not send its own invitation email, so your workflow must notify the user. `invitation_url` only opens the app; the user still signs in normally, and the account is created on that first sign-in (`identity.user.created`). `identity.user.invitation_revoked` has the same payload plus `revoked_by`.

### `identity.scim.user.provisioned`

```json
{
  "id": "660e8400-e29b-41d4-a716-446655440001",
  "type": "identity.scim.user.provisioned",
  "time": "2026-09-24T13:31:00+00:00",
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

### `identity.auth.magic_link.requested`

```json
{
  "id": "770e8400-e29b-41d4-a716-446655440002",
  "type": "identity.auth.magic_link.requested",
  "time": "2026-09-24T13:32:00+00:00",
  "company": { "id": 1, "slug": "acme", "name": "Acme" },
  "data": {
    "request_id": "00000000-0000-0000-0000-000000000001",
    "email": "ada@acme.com",
    "expires_at": "2026-09-25T10:00:00+00:00",
    "source": "magic_link",
    "language": "en",
    "region": "UTC"
  }
}
```

This event is a notification. Identity-service always sends the sign-in email itself, and the payload never contains the sign-in link or the token, so a workflow cannot deliver or use the link. Use it for alerts or analytics, for example to count sign-in requests per company.

---

## Related docs

- [Action triggers (webhooks)](actions.md)
- [Configuration](configuration.md)
