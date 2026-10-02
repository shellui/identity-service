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
  "client_device_id": "optional-device-id",
  "language": "fr"
}
```

- **`language`** (optional) is the requester's UI language (`fr`, `fr-FR`, …). It selects the email locale and is sent as `language` in the webhook payload. Unsupported values are ignored.
- **`redirect_to`** must match the company OAuth redirect allowlist (same rules as OAuth login).
- When magic link is **disabled**, the API returns **403** with `error_code: magic_link_disabled`.
- When the message is accepted, the API returns **200** with a generic message (it does not reveal whether the email exists).
- When the company has an enabled webhook Action rule for **`identity.auth.magic_link.requested`**, the event is sent to that webhook with `magic_link_url`, and identity-service does **not** send the sign-in email. Your webhook (for example an n8n workflow) delivers the link. See [actions.md](actions.md).
- Otherwise identity-service sends the sign-in email. With `EMAIL_SERVICE_API_KEY` set, that is `POST /api/v1/send` on email-service (`identity.auth.magic_link.requested`, TTL 120s). With no key, or when email-service cannot be reached, it uses the static templates in `apps/authapi/templates/authapi/magic_link/` (EN and FR). Locale order: request `language`, then the saved language, then `MAGIC_LINK_EMAIL_DEFAULT_LANGUAGE` (EN by default). If both paths fail, the API returns **503** `email_unavailable`. A hard bounce on the auth lane returns **422** `recipient_suppressed`. Those bodies are an `error_code` only. See [email-service.md](email-service.md).

Rate limits: `AUTH_RATE_LIMIT_MAGIC_LINK` (default 10/min) per client IP, email+company, and company.

### Verify (browser)

`GET /api/v1/magic-link/verify?token=…&company_id=…`

Returns a page that submits itself with **POST** to the same URL (with `company_id` in the query string) as soon as it loads. The user is signed in and redirected to `redirect_to` with tokens (session code or fragment) without clicking anything; company join rules apply as usual. The GET itself **does not consume** the token, so email link scanners that only fetch the URL do not burn it. Without JavaScript, the page shows a **Continue sign-in** button.

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
| **Link URL** | Built from **`JWT_ISSUER`** (HTTPS required when `DEBUG=false`). With `DEBUG=true` and no `JWT_ISSUER`, the request base URL is used instead (local development only) |
| **Secrets in webhooks** | Webhook payloads include `request_id`, `email`, `expires_at`, and `magic_link_url` (the one-time sign-in link). Anyone with the URL can sign in until it expires or is used, so only point this rule at endpoints you trust. The raw token is never stored; only its hash is. |
| **Webhook user fields** | `user_id`, `language`, and `region` are included only when the email matches a user who already has membership in that company. |
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

The Admin REST API keeps at least one sign-in method per company. It returns **400** (`login_method_required`) when a request would leave the company with no magic link and no active OAuth or SAML provider:

- disabling magic link with no active provider configured
- deactivating (`is_active: false`) or deleting the last OAuth client, or deleting the last social app, while magic link is disabled

Enable another method first, then remove the old one. Django admin edits and the global `MAGIC_LINK_ENABLED` switch are not checked.

---

## Related docs

- [OAuth login](oauth-login.md) — redirect allowlist and token delivery
- [Action triggers](actions.md) — `identity.auth.magic_link.requested`
- [Configuration](configuration.md) — environment variables
