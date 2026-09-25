# Magic link (passwordless email) login

Company-scoped **magic link** sign-in complements OAuth. Users request a one-time link by email; clicking the link (or calling the consume API) yields Shellui JWTs using the same session delivery options as OAuth (`OAUTH_TOKEN_DELIVERY`).

---

## Enablement

| Layer | Control |
| ----- | ------- |
| **Deployment** | `MAGIC_LINK_ENABLED=true` (default). Set `false` to disable all magic-link endpoints globally. |
| **Company** | `Company.enable_magic_link` (default **true** for new companies). Toggle via **Admin REST** (below) or Django admin → Company. |
| **Capabilities API** | `GET /api/v1/settings?company_id=…` returns `enable_magic_link` and includes `magic_link` in `methods` when enabled. |

OAuth providers remain independent — a company can use magic link only, OAuth only, or both.

---

## API

### Request a link

`POST /api/v1/magic-link/request`

```json
{
  "company_id": 1,
  "email": "ada@acme.com",
  "redirect_to": "https://app.example.com/login/callback",
  "client_timezone": "Europe/Paris",
  "client_device_id": "optional-device-id"
}
```

- **`redirect_to`** must match the company OAuth redirect allowlist (same rules as OAuth login).
- When magic link is **disabled**, the API returns **403** with `error_code: magic_link_disabled`.
- When enabled, the API always returns **200** with a generic message (does not reveal whether the email exists).
- Emits **`identity.auth.magic_link.requested`** when Action rules are configured — configure email delivery in Django admin to send the link (see [actions.md](actions.md)).

Rate limits: `AUTH_RATE_LIMIT_MAGIC_LINK` (default 10/min) per client IP, email+company, and company.

### Verify (browser)

`GET /api/v1/magic-link/verify?token=…&company_id=…`

Validates the token, applies company join rules (public / domain / invite — same as OAuth), records a login event with provider `magic_link`, and redirects to `redirect_to` with tokens (session code or fragment).

### Consume (JSON)

`POST /api/v1/magic-link/verify`

```json
{
  "token": "…",
  "company_id": 1
}
```

Returns the same JWT payload as `POST /api/v1/token` / OAuth finalize on success; **403** when company access is pending or denied.

---

## Security

| Topic | Behavior |
| ----- | -------- |
| **TTL** | `MAGIC_LINK_TTL_SECONDS` (default **1800** = 30 minutes) |
| **One-time use** | Token invalidated on successful consume |
| **Link URL** | Built from **`JWT_ISSUER`** (HTTPS required when `DEBUG=false`) |
| **Secrets in Actions** | Webhook payloads include `request_id`, `email`, `expires_at` — **not** the raw token. Email templates receive `magic_link_url` only at send time. |
| **Privacy** | Request endpoint does not enumerate valid emails |

---

## Admin REST (Shellui admin)

Staff or **company owner** JWT with the usual company scope (`company_id` query/body or `company_id` claim in the access token). Same authorization as `/api/v1/scim` and `/api/v1/oauth-clients`. The **shellui/admin** SPA can call these endpoints; a settings UI may ship later — this API is the contract.

| Method | Path | Notes |
| ------ | ---- | ----- |
| GET | `/api/v1/auth-methods` | Company magic-link + OAuth flags: `enable_magic_link`, `magic_link_effective`, `magic_link_globally_enabled`, `enable_oauth`, `oauth_providers`, `methods` |
| PATCH, PUT | `/api/v1/auth-methods` | Body `{ "enable_magic_link": true \| false }` — persists on the company; when `false`, magic-link request/verify return **403** (`magic_link_disabled`) |

Example GET response:

```json
{
  "enable_magic_link": true,
  "magic_link_effective": true,
  "magic_link_globally_enabled": true,
  "enable_oauth": true,
  "oauth_providers": ["github"],
  "methods": ["magic_link", "oauth"]
}
```

When `MAGIC_LINK_ENABLED=false` on the deployment, `magic_link_globally_enabled` and `magic_link_effective` are false even if the company flag stays true (company setting is preserved for when the kill switch is lifted).

---

## Disabling for a company

1. **Admin REST:** `PATCH /api/v1/auth-methods?company_id=…` with `{ "enable_magic_link": false }`, or Django admin → **Companies** → uncheck **Enable magic link**.
2. Optionally remove `magic_link` Action rules.

New companies default to magic link **enabled** (`enable_magic_link=true`).

---

## Related docs

- [OAuth login](oauth-login.md) — redirect allowlist and token delivery
- [Action triggers](actions.md) — `identity.auth.magic_link.requested`
- [Configuration](configuration.md) — environment variables
