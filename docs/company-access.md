# Company access control (join modes)

Companies control how new OAuth users gain access after a successful provider login.

Access is **per company** via `CompanyMembership.is_enabled`. The same Django user may be enabled in one company and disabled in another. Global `User.is_active` is not used for company join policies.

## Access modes

| Mode | Value | Behavior |
|------|--------|----------|
| **Public** (default) | `public` | Any successful login joins the company with access enabled and receives tokens. |
| **Domain** | `domain` | Emails whose domain is listed in `allowed_email_domains` join enabled. Other domains create a disabled membership, block tokens, and email company owners. |
| **Invitation only** | `invite` | New users are created as disabled members; tokens are blocked until an owner/staff enables membership for that company. Owners are emailed on first join. |

Configure via:

- **Django admin → Companies → Company** — join mode, allowed domains, Members inline (`is_enabled`)
- **Django admin → Company memberships** — list/edit per-company enable flags
- `PATCH /api/v1/companies/<id>/` with `access_mode` and optional `allowed_email_domains` (company owners only)
- Shellui admin **Organization** panel

## Enable / disable (per company)

Staff and company owners can set `is_active` on `PUT /api/v1/users/<id>` for the **current JWT company**. That field updates `CompanyMembership.is_enabled` for that company only (it does not change Django `User.is_active`). Enabling a previously disabled membership emails the user.

## Invitations

Staff and company owners can invite someone with `POST /api/v1/invitations` (admin panel: **Invite user** on the Users page, or in Company access when **Invitation only** is selected). Body: `email`, `language` (`en` or `fr`), and optional `app_url`.

- The account with that email is reused, or created with an unusable password (username from the email, like magic link). A new account gets `language` as its UI language.
- Access to the company is enabled right away, which also approves a pending access request. Returns **409** `already_member` when the user already has access.
- The invitation email is sent in `language` from `apps/authapi/templates/authapi/invitation/` and links to `app_url`. It holds no sign-in credential: the user signs in with magic link or any OAuth provider that matches the email.
- `app_url` must match the company OAuth redirect allowlist (**400** `invalid_app_url` otherwise). The admin panel sends the shell origin. Without it the email has no link.
- `identity.user.invited` is emitted. When the company has an enabled webhook rule for it, identity-service skips its own email (same as magic link).
- Rate limit: `AUTH_RATE_LIMIT_INVITATION` (default 30 per 5 minutes) per company.

## OAuth error codes

When access is blocked for the requested company, OAuth responses include `error_code`:

- `access_pending` — invitation-only or disabled membership waiting for approval
- `access_denied` — domain mode with a non-matching email

Shellui shows a pending-review screen for these codes (query params `shellui_oauth_error` / `shellui_oauth_error_code`, or JSON on `/api/v1/oauth/exchange`).

SCIM provisioning sets `CompanyMembership.is_enabled` via the `active` attribute — see [SCIM](scim.md) when enterprise provisioning is enabled.

## Email

Notifications use Django's email backend. Locally, messages print to the console by default (`EMAIL_BACKEND`). Set `EMAIL_HOST`, `DEFAULT_FROM_EMAIL`, and related env vars for SMTP in production.
