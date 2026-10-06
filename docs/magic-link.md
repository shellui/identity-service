---
description: Passwordless email sign-in with identity-service - turning magic links on or off, the request and verify API, and the security model.
---

# Magic link

A magic link is a one-time sign-in link sent by email. The user clicks it and is signed in, with no password and no OAuth provider. identity-service returns the same tokens as OAuth, with the same delivery options (`OAUTH_TOKEN_DELIVERY`). Magic link and OAuth are independent: a company can use either one or both.

## Turn magic links on or off

Magic links are on by default, at two levels:

| Level | Control |
| --- | --- |
| Deployment | `MAGIC_LINK_ENABLED=true` (default). `false` turns off every magic link endpoint |
| Company | `Company.enable_magic_link`, `true` for new companies. Change it with the [admin API](#admin-api) or in Django admin |

`GET /api/v1/settings?company_id=…` returns `enable_magic_link` and lists `magic_link` in `methods` when it is on. The shell login page reads this.

### Keep one sign-in method

The admin API keeps at least one sign-in method per company. It returns **400** `login_method_required` when a request would leave the company with no magic link and no active OAuth or SAML provider, for example:

- turning off magic link while no provider is configured
- deactivating (`is_active: false`) or deleting the last OAuth client, or deleting the last provider app, while magic link is off

Enable the other method first, then remove the old one. Django admin edits and the `MAGIC_LINK_ENABLED` switch are not checked.

## Request a link

The shell asks identity-service to email a link with `POST /api/v1/magic-link/request`:

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

The fields and responses work as follows:

- **`redirect_to`**: must pass the company [redirect allowlist](oauth-login.md#redirect-allowlist), as for OAuth
- **`language`** (optional): the UI language (`fr`, `fr-FR`, …). It picks the email language and is sent as `language` in the webhook payload. Unsupported values are ignored
- **200**: a generic message, whether or not the email has an account, so the endpoint cannot be used to find accounts. A staff address gets the same answer, but a notice instead of a link, see [Staff accounts](#staff-accounts)
- **403** `magic_link_disabled`: magic links are off for the company or the deployment
- **422** `recipient_suppressed`: the address hard-bounced earlier
- **503** `email_unavailable`: neither email-service nor SMTP could send the message

Rate limit: `AUTH_RATE_LIMIT_MAGIC_LINK` (10 per minute by default), counted per client IP, per email and company, and per company.

### How the email is sent

identity-service always sends the sign-in email itself. With `EMAIL_SERVICE_API_KEY` set, it calls email-service `POST /api/v1/send` with the `identity.auth.magic_link.requested` template. With no key, or when email-service cannot be reached, it renders the templates in `apps/authapi/templates/authapi/magic_link/` (English and French) and sends them over SMTP. The language is the request `language`, then the user's saved language, then `MAGIC_LINK_EMAIL_DEFAULT_LANGUAGE` (`en` by default). See [Email delivery](email-service.md).

A webhook rule on `identity.auth.magic_link.requested` is a notification only. Its payload has `request_id`, `email`, `expires_at`, `source`, and `language` (plus `user_id` and `region` for existing members), never the link or the token. See [Webhooks](actions.md).

## Verify the link

The link in the email opens `GET /api/v1/magic-link/verify?token=…&company_id=…`. That page posts itself to the same URL as soon as it loads, signs the user in, and redirects to `redirect_to` with tokens (session code or fragment). Company join rules apply as usual.

The `GET` alone does not use up the token, so email security scanners that only fetch the URL do not break the link. Without JavaScript, the page shows a **Continue sign-in** button instead.

To consume a token from code, call `POST /api/v1/magic-link/verify`:

```json
{
  "token": "…",
  "company_id": 1
}
```

It returns the same token payload as `POST /api/v1/token` and OAuth, or **403** when company access is pending or denied.

### Tokens of staff accounts

A token that belongs to a staff account never signs in:

| Where | Result |
| --- | --- |
| Verify page (`GET`) | Does not submit. Answers **403** with a page that explains, in English or French (browser language first, then the account language), that staff accounts sign in with their usual method, and a **Go to sign-in** link to the app the request came from. The card carries `data-error-code="magic_link_staff_disabled"` |
| `POST` with JSON | **403** `magic_link_staff_disabled`, with an English `error` sentence. The token is used up and no session is issued |
| `POST` from the page form | Redirects to `redirect_to` with `shellui_oauth_error` and `shellui_oauth_error_code=magic_link_staff_disabled`, like other sign-in errors |

Shells should show their own translated text for `magic_link_staff_disabled`.

## Security

Magic link tokens are short-lived, single-use, and never stored in plain text:

| Topic | Behavior |
| --- | --- |
| Lifetime | `MAGIC_LINK_TTL_SECONDS`, 1800 seconds (30 minutes) by default |
| Single use | The token stops working after a successful sign-in |
| Link host | Built from `JWT_ISSUER`, which must be HTTPS when `DEBUG=false`. With `DEBUG=true` and no `JWT_ISSUER`, the request URL is used (local development only). email-service `EMAIL_AUTH_LINK_HOSTS` must include that host |
| Storage | Only a SHA-256 hash of the token is stored (`MagicLinkToken.token_hash`) |
| Webhooks | The `identity.auth.magic_link.requested` payload never contains the link or the token. Before 0.7.0 it carried `magic_link_url`; migration `actions.0007` removes it from stored delivery records |
| Webhook user fields | `user_id`, `language`, and `region` appear only when the email belongs to an existing member of the company |
| Account discovery | The request endpoint gives the same answer for known, unknown, and staff emails |
| Staff accounts | No magic link for `is_staff` or `is_superuser` accounts. See [Staff accounts](#staff-accounts) |

The raw token and the link exist only in memory during the request, in the email itself, and in the verify request. They are not written to webhook payloads, delivery records (`ActionOutbox`, `DeliveryAttempt`), the event log, Django admin, the cache, or app logs. The gunicorn access log keeps the path without the query string, and Sentry events drop query strings, request bodies, and the Referer. One exception: with `DEBUG=true`, the console email backend prints the email, link included, for local development.

## Staff accounts

Staff accounts (`is_staff` or `is_superuser`) cannot sign in with a magic link. A company that sends mail through its own provider (Resend or SMTP) can read every email it sends in that provider's dashboard or logs, sign-in links included. A link for a staff member would let that company sign in as them. Staff sign in with a password (Django admin) or with OAuth, OIDC, or SAML instead, which work as before.

### What happens on a request

When someone asks for a link for a staff address:

- identity-service creates no token and sends no link
- unused tokens already issued for the account are deleted
- the same rate limits apply as for a magic link
- the address gets a short notice instead: magic links are off for staff accounts, sign in with your usual method, and a **Go to sign-in** button to the app the request came from (the origin of `redirect_to`). The notice has no token and no sign-in link. A loopback `redirect_to` (CLI sign-in) gives no button

The notice is sent the same way as a magic link: email-service `POST /api/v1/send` with the built-in template `identity.auth.magic_link.staff_blocked`, or the static templates in `apps/authapi/templates/authapi/magic_link_staff/` (English and French) over SMTP. Companies cannot edit that template or put rules on it. An email-service that does not know the template yet (`template_not_found`) also falls back to SMTP.

### What the caller sees

The answer is the same as for any other address: same status, same body, same webhook. Since no token is created, the timing is close to a normal request but not identical. A delivery refusal maps to the same code as for any other address, for example **422** `recipient_suppressed` after a hard bounce, or **429** when email-service rate-limits the recipient.

The `identity.auth.magic_link.requested` webhook and event log entry are emitted with the usual fields, and `request_id` is a random id with no token behind it. Emitting nothing would reveal staff addresses by the missing notification. The company can still see in its own provider logs and in email-service that a notice went out instead of a link, and sign-in events already record `is_staff_at_event`.

### Older tokens

Tokens issued before 0.7.0, or before the account became staff, are refused too:

- verify checks the account at use time (the token's user, or any account with the token's address) and returns `magic_link_staff_disabled`, see [Tokens of staff accounts](#tokens-of-staff-accounts)
- saving an account as staff or superuser (Django admin, `createsuperuser`, code) deletes its unused tokens
- migration `authapi.0017_delete_staff_magic_link_tokens` deletes unused tokens of existing staff accounts

## Admin API

Staff and company owners manage sign-in methods with a JWT scoped to the company (`company_id` in the query, body, or token). This is the same authorization as `/api/v1/scim` and `/api/v1/oauth-clients`:

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/auth-methods` | Magic link and OAuth flags for the company |
| `PATCH`, `PUT` | `/api/v1/auth-methods` | Body `{"enable_magic_link": true}` or `false`. When `false`, request and verify return **403** `magic_link_disabled` |

A `GET` response looks like this:

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

With `MAGIC_LINK_ENABLED=false`, `magic_link_globally_enabled` and `magic_link_effective` are `false` even when the company flag stays `true`. The company setting is kept for when the deployment switch comes back on.

## Related

- [OAuth login](oauth-login.md): redirect allowlist and token delivery
- [Email delivery](email-service.md): email-service and the SMTP fallback
- [Configuration](configuration.md): environment variables
