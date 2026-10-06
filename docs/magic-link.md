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
- Identity-service always sends the sign-in email itself. With `EMAIL_SERVICE_API_KEY` set, that is `POST /api/v1/send` on email-service (`identity.auth.magic_link.requested`, TTL 120s). With no key, or when email-service cannot be reached, it uses the static templates in `apps/authapi/templates/authapi/magic_link/` (EN and FR). Locale order: request `language`, then the saved language, then `MAGIC_LINK_EMAIL_DEFAULT_LANGUAGE` (EN by default). If both paths fail, the API returns **503** `email_unavailable`. A hard bounce on the auth lane returns **422** `recipient_suppressed`. Those bodies are an `error_code` only. See [email-service.md](email-service.md).
- A webhook rule for **`identity.auth.magic_link.requested`** is a notification only. Its payload has `request_id`, `email`, `expires_at`, `source` and `language` (plus `user_id` and `region` for members), but never the sign-in link, the token or anything else that can be used to sign in. The rule does not replace the email. See [actions.md](actions.md).

- A staff account gets no link. See [Staff accounts](#staff-accounts).

Rate limits: `AUTH_RATE_LIMIT_MAGIC_LINK` (default 10/min) per client IP, email+company, and company.

### Verify (browser)

`GET /api/v1/magic-link/verify?token=…&company_id=…`

Returns a page that submits itself with **POST** to the same URL (with `company_id` in the query string) as soon as it loads. The user is signed in and redirected to `redirect_to` with tokens (session code or fragment) without clicking anything; company join rules apply as usual. The GET itself **does not consume** the token, so email link scanners that only fetch the URL do not burn it. Without JavaScript, the page shows a **Continue sign-in** button.

When the token belongs to a staff account, the page does not submit. It answers **403** and explains, in English or French (browser language first, then the account language), that staff accounts can't use email sign-in links and should sign in with their usual sign-in method, with a **Go to sign-in** link to the app the request came from. The card carries `data-error-code="magic_link_staff_disabled"`.

### Consume (JSON)

`POST /api/v1/magic-link/verify`

```json
{
  "token": "…",
  "company_id": 1
}
```

Returns the same JWT payload as `POST /api/v1/token` / OAuth finalize on success; **403** when company access is pending or denied.

A token that belongs to a staff account returns **403** with `error_code: magic_link_staff_disabled` (and an English `error` sentence). The token is used up and no session is issued. The browser form post (no JSON) redirects to `redirect_to` with `shellui_oauth_error` and `shellui_oauth_error_code=magic_link_staff_disabled`, like other sign-in errors. Show your own translated text for the code.

---

## Security

| Topic | Behavior |
| ----- | -------- |
| **TTL** | `MAGIC_LINK_TTL_SECONDS` (default **1800** = 30 minutes) |
| **One-time use** | Token invalidated on successful consume |
| **Link URL** | Built from **`JWT_ISSUER`** (HTTPS required when `DEBUG=false`). With `DEBUG=true` and no `JWT_ISSUER`, the request base URL is used instead (local development only). email-service `EMAIL_AUTH_LINK_HOSTS` must include that host. `localhost` stays on the list only while email-service `DEBUG=true`. See [email-service.md](email-service.md) |
| **Token storage** | Only a SHA-256 hash of the token is stored (`MagicLinkToken.token_hash`). The raw token and the link exist in memory while the request runs, in the email sent to the user (rendered by identity for SMTP, or handed to email-service in the `/api/v1/send` request), and in the verify request. They are not in webhook payloads, webhook delivery records (`ActionOutbox`, `DeliveryAttempt`), the event log, Django admin, cache entries or app logs (with `DEBUG=true` the default console email backend prints the email, link included, for local development). The gunicorn access log has the path without the query string, and Sentry events drop query strings, request bodies and the Referer |
| **Webhooks** | The `identity.auth.magic_link.requested` payload never contains the link or the token. Before 0.7.0 it carried `magic_link_url`; migration `actions.0007` removes it from stored delivery records |
| **Webhook user fields** | `user_id`, `language`, and `region` are included only when the email matches a user who already has membership in that company. |
| **Privacy** | Request endpoint does not enumerate valid emails or staff accounts |
| **Staff accounts** | No magic link for `is_staff` or `is_superuser`. See [Staff accounts](#staff-accounts) |

---

## Staff accounts

Staff accounts (`is_staff` or `is_superuser`) cannot sign in with a magic link. A company that sends mail through its own provider (Resend or SMTP) can read every email it sends in that provider's dashboard or logs, sign-in links included. A link for a staff member signing in to that company would let the company sign in as that staff member. Staff sign in with a password (Django admin) or with OAuth, OIDC, or SAML instead.

When someone asks for a link for a staff address:

- identity-service creates no token and sends no link
- the address gets a short notice instead: magic links are off for staff accounts, sign in with your usual sign-in method, and a **Go to sign-in** button to the app the request came from (the origin of `redirect_to`). It has no token and no sign-in link. A loopback `redirect_to` (CLI sign-in) gives no button
- the notice goes through the same auth path as the magic link: email-service `POST /api/v1/send` with the built-in template `identity.auth.magic_link.staff_blocked` (one recipient, Shellui copy that companies cannot edit or put rules on), or the static templates in `apps/authapi/templates/authapi/magic_link_staff/` (EN and FR) over SMTP. An email-service that does not know the template yet (`template_not_found`) also falls back to SMTP
- the same rate limits apply as for a magic link
- unused tokens already issued for the account are deleted

The answer to the caller is the same as for any other address: same status, same body, same webhook. The request endpoint does not create a token for staff, so its timing is close to a normal request but not identical. A delivery refusal maps to the same code as for any other address (for example **422** `recipient_suppressed` after a hard bounce, **429** when email-service rate-limits the recipient). Those codes already tell the caller something about an address, staff or not.

The `identity.auth.magic_link.requested` webhook and event log entry are emitted as for any other request, with the same fields. `request_id` is a random id with no token behind it. Emitting nothing would show staff addresses by their missing notification. The company can still see that a notice was sent instead of a link in its own provider logs and in email-service, and sign-in events already record `is_staff_at_event`.

Tokens issued before this release, or before the account became staff, are refused too:

- verify checks the account at use time (the token's user, or any account with the token's address) and returns `magic_link_staff_disabled`
- saving an account as staff or superuser (Django admin, `createsuperuser`, code) deletes its unused tokens
- migration `authapi.0017_delete_staff_magic_link_tokens` deletes unused tokens of existing staff accounts

Password sign-in to Django admin and OAuth, OIDC, and SAML sign-in work as before for staff.

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
2. Optionally remove webhook rules for `identity.auth.magic_link.requested`.

New companies default to magic link **enabled** (`enable_magic_link=true`).

The Admin REST API keeps at least one sign-in method per company. It returns **400** (`login_method_required`) when a request would leave the company with no magic link and no active OAuth or SAML provider:

- disabling magic link with no active provider configured
- deactivating (`is_active: false`) or deleting the last OAuth client, or deleting the last social app, while magic link is disabled

Enable another method first, then remove the old one. Django admin edits and the global `MAGIC_LINK_ENABLED` switch are not checked.

---

## Related docs

- [OAuth login](oauth-login.md) — redirect allowlist and token delivery
- [Webhooks](actions.md): `identity.auth.magic_link.requested`
- [Configuration](configuration.md) — environment variables
