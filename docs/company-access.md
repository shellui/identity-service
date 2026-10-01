# Company access control (join modes)

Companies control how new OAuth users gain access after a successful provider login.

Access is **per company** via `CompanyMembership.is_enabled`. The same Django user may be enabled in one company and disabled in another. Global `User.is_active` is not used for company join policies.

## Access modes

| Mode | Value | Behavior |
|------|--------|----------|
| **Public** (default) | `public` | Any successful login joins the company with access enabled and receives tokens. |
| **Domain** | `domain` | Emails whose domain is listed in `allowed_email_domains` join enabled. Other domains create a disabled membership, block tokens, and email company owners. |
| **Invitation only** | `invite` | Invited emails get access on first sign-in (see [Invitations](#invitations)). Others are created as disabled members; tokens are blocked until an owner/staff enables membership for that company. Owners are emailed on first join. |

Configure via:

- **Django admin → Companies → Company** — join mode, allowed domains, Members inline (`is_enabled`)
- **Django admin → Company memberships** — list/edit per-company enable flags
- `PATCH /api/v1/companies/<id>/` with `access_mode` and optional `allowed_email_domains` (company owners only)
- Shellui admin **Organization** panel

## Enable / disable (per company)

Staff and company owners can set `is_active` on `PUT /api/v1/users/<id>` for the **current JWT company**. That field updates `CompanyMembership.is_enabled` for that company only (it does not change Django `User.is_active`). Enabling a previously disabled membership emails the user.

## Invitations

Staff and company owners can invite someone with `POST /api/v1/invitations` (admin panel: **Invite user** on the Users page, or in Company access when **Invitation only** is selected). Body: `email`, `language` (`en` or `fr`), and optional `app_url`.

- A pending `CompanyInvitation` is stored; **no user account is created**. Returns **409** `already_member` when someone with this email already has access, or `already_invited` when an invitation is pending.
- The invitation email is sent in `language` from `apps/authapi/templates/authapi/invitation/` and links to `app_url`. It holds no sign-in credential.
- `app_url` must match the company OAuth redirect allowlist (**400** `invalid_app_url` otherwise). The admin panel sends the shell origin. Without it the email has no link.
- Only `identity.user.invited` is emitted. When the company has an enabled webhook rule for it, identity-service skips its own email (same as magic link). The payload has no `user_id`, so it never reveals whether the email has an account in another company.
- Rate limit: `AUTH_RATE_LIMIT_INVITATION` (default 30 per 5 minutes) per company.

**Accepting.** The first sign-in to the company with that email accepts the invitation and enables access, whatever the access mode, and approves a pending access request. The email must be proven: magic link, SAML, or an OAuth provider that reports it as verified. The account is created at that moment if needed (`identity.user.created` with the real sign-in `source`), and a user with no other company gets `language` as their UI language.

**Listing and revoking.** `GET /api/v1/invitations` returns pending invitations, plus revoked ones that still block sign-in (the admin panel shows them on the Users page). `POST /api/v1/invitations/<id>/revoke` revokes a pending invitation (**409** `invitation_not_pending` otherwise) and emits `identity.user.invitation_revoked`. `DELETE /api/v1/invitations/<id>` removes a revoked invitation from the database, together with older revoked invitations for that email (**409** `invitation_not_revoked` for other statuses). Deleting lifts the sign-in block: the email is treated as never invited.

**Revoked invitations block sign-in.** While the latest invitation for an email is revoked and nobody with that email has enabled access, sign-in to that company is refused with `invitation_revoked`, in every access mode. Magic link requests get the usual generic reply but no email, and OAuth/SAML stop before creating an account. Sending a new invitation, or deleting the revoked one, lifts the block.

## OAuth error codes

When access is blocked for the requested company, OAuth responses include `error_code`:

- `access_pending` — invitation-only or disabled membership waiting for approval
- `access_denied` — domain mode with a non-matching email
- `invitation_revoked` — the latest invitation for this email was revoked (shown as a regular sign-in error with the backend message)

Shellui shows a pending-review screen for these codes (query params `shellui_oauth_error` / `shellui_oauth_error_code`, or JSON on `/api/v1/oauth/exchange`).

SCIM provisioning sets `CompanyMembership.is_enabled` via the `active` attribute — see [SCIM](scim.md) when enterprise provisioning is enabled.

## Email

Notifications use Django's email backend. Locally, messages print to the console by default (`EMAIL_BACKEND`). Set `EMAIL_HOST`, `DEFAULT_FROM_EMAIL`, and related env vars for SMTP in production.
