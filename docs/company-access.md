---
description: Control who can join a Shellui company after sign-in - public, email domain, or invitation-only access, member approval, and invitations.
---

# Company access

Each company decides who gets in after a successful sign-in: anyone, people with an allowed email domain, or invited people only. The rule applies to every sign-in method (OAuth, SAML, and magic link). People who are not allowed in get a disabled membership and no tokens, until an owner enables them.

Access is per company, stored in `CompanyMembership.is_enabled`. The same user can be enabled in one company and disabled in another. The global `User.is_active` flag is not used by these rules.

## Access modes

| Mode | Value | Who gets access on first sign-in | Everyone else |
| --- | --- | --- | --- |
| Public (default) | `public` | Everyone | |
| Domain | `domain` | Emails whose domain is in `allowed_email_domains` | Disabled membership, `access_denied`, owners are emailed |
| Invitation only | `invite` | People with a pending [invitation](#invitations) | Disabled membership, `access_pending`, owners are emailed |

Set the mode in any of these places:

- Shellui admin, **Organization** panel
- `PATCH /api/v1/companies/{id}/` with `access_mode` and, for domain mode, `allowed_email_domains` (company owners)
- Django admin, **Companies**: mode, allowed domains, and members

## Enable or disable a member

Staff and company owners enable or disable a member with `is_active` on `PUT /api/v1/users/{id}`, for the company of their token. This changes the membership in that company only, never the global account. Enabling a disabled member emails them.

[SCIM provisioning](scim.md) sets the same flag through the `active` attribute.

## Invitations

Staff and company owners invite someone with `POST /api/v1/invitations`, or with **Invite user** on the Users page of Shellui admin:

```json
{
  "email": "ada@acme.com",
  "language": "fr",
  "app_url": "https://app.example.com"
}
```

identity-service stores a pending invitation and emails it. It does not create an account yet.

- **`language`**: `en` or `fr`, the language of the email
- **`app_url`**: the link in the email. It must pass the company [redirect allowlist](oauth-login.md#redirect-allowlist), otherwise the request returns **400** `invalid_app_url`. Shellui admin sends the shell origin
- **409** `already_member`: someone with this email already has access. **409** `already_invited`: an invitation is pending
- **503** `email_unavailable`: neither email-service nor SMTP could send the email. The invitation is not stored, so you can retry
- Rate limit: `AUTH_RATE_LIMIT_INVITATION`, 30 per 5 minutes per company

The email holds no sign-in credential, only the app link. It goes through email-service when `EMAIL_SERVICE_API_KEY` is set, otherwise through SMTP. When the company has an enabled webhook rule on `identity.user.invited`, identity-service does not send the email and your endpoint delivers it. The payload has no `user_id`, so it never reveals whether the person has an account elsewhere. See [Email delivery](email-service.md).

### Accept an invitation

The first sign-in to the company with the invited email accepts the invitation and enables access, in every access mode. It also approves a pending access request. The email must be proven: magic link, SAML, or an OAuth provider that reports it as verified.

The account is created at that moment if needed, which emits `identity.user.created` with the real sign-in `source`. A user with no other company gets the invitation `language` as their UI language.

### List and revoke invitations

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/invitations` | Pending invitations, plus revoked ones that still block sign-in |
| `POST` | `/api/v1/invitations/{id}/revoke` | Revokes a pending invitation and emits `identity.user.invitation_revoked`. **409** `invitation_not_pending` otherwise |
| `DELETE` | `/api/v1/invitations/{id}` | Removes a revoked invitation, and older revoked ones for that email. **409** `invitation_not_revoked` otherwise |

A revoked invitation blocks sign-in. While the latest invitation for an email is revoked and nobody with that email has access, sign-in to the company fails with `invitation_revoked`, in every access mode. Magic link requests get the usual generic reply but no email, and OAuth and SAML stop before creating an account. A new invitation, or deleting the revoked one, lifts the block.

## Error codes

When access is blocked, the sign-in response includes an `error_code`:

| Code | Meaning |
| --- | --- |
| `access_pending` | Invitation-only company, or a disabled membership waiting for approval |
| `access_denied` | Domain mode, and the email domain is not allowed |
| `invitation_revoked` | The latest invitation for this email was revoked |

After OAuth, the shell receives them as `shellui_oauth_error` and `shellui_oauth_error_code` query parameters, or in the JSON of `/api/v1/oauth/exchange`. Shellui shows a pending review screen for `access_pending` and `access_denied`, and a regular sign-in error for `invitation_revoked`.

## Owner notifications

Emails to owners and members (access requests, membership enabled) use Django's email backend. Locally, they print to the console. In production, set `EMAIL_HOST` and `DEFAULT_FROM_EMAIL`, see [Configuration](configuration.md#email).

## Related

- [OAuth login](oauth-login.md): the sign-in flow
- [SCIM provisioning](scim.md): manage memberships from an IdP
- [Webhooks](actions.md): `identity.user.created`, `identity.user.invited`, and other events
