---
description: How users delete their own identity-service account with DELETE /api/v1/user, what data is removed, and which guards apply.
---

# Account deletion

Signed-in users can delete their own account with `DELETE /api/v1/user`. Deletion is scoped to the company in the access token: a user who belongs to several companies only leaves that one. Use this endpoint for right-to-erasure requests (GDPR).

## Delete your account

Send the request with a session access token from a recent sign-in, and `"confirm": true` in the body:

```http
DELETE /api/v1/user?company_id=1
Authorization: Bearer your_access_token_here
Content-Type: application/json

{"confirm": true, "refresh_token": "your_refresh_token_here"}
```

`refresh_token` is optional. When present, it is revoked like a logout. A successful request returns `204 No Content`.

## Guards

identity-service refuses the request in three cases:

| Case | Response |
| --- | --- |
| The token is a personal access token | **403** |
| The user is the only owner of the token company | **409** `last_company_owner`, with `companies: [{id, name}]` |
| The last interactive sign-in is older than `SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE` (5 minutes by default) | **403** `recent_login_required` |

The sign-in age comes from the token `auth_time` claim. A token refresh keeps the original `auth_time`, so the user has to sign in again, not refresh. The owner check runs first.

To unblock a last owner, make another member an owner. Owning another company never blocks the delete: the account and that other ownership are kept. Company owners also cannot clear the owner list with `PATCH /api/v1/companies/{id}/` (`owner_ids: []` returns **400** `company_owner_required`).

## What is removed

What happens depends on whether the user belongs to other companies:

- **Other companies remain**: only this company's membership and company-scoped data are removed. That covers refresh sessions, personal access tokens, OAuth delivery codes, magic link tokens, group memberships, ownership, and provider links (`SocialAccount`) for apps that only this company owns. The account and the other memberships stay
- **This was the last company**: the `User` row is deleted, as in Django admin. Cascades remove memberships, provider links, preferences, personal access token records, refresh sessions, and SCIM fields tied to the user

A full delete also revokes every refresh session and personal access token of the user, in every company. In both cases, the current access token goes on the logout denylist, and sign-in events for the company stay in the [event log](event-log.md) without the user link.

## Webhook and notification

identity-service emits [`identity.user.deleted`](actions.md) once per removed company membership, with `data.source: "self"`. Use a webhook rule on that event to confirm the deletion to the user or to start cleanup in other systems. Deletions by staff or company owners (`DELETE /api/v1/users/{id}`) emit the same event with `data.source: "admin"`.

This endpoint supports erasure workflows. It is not legal advice: operators can still keep data under billing, security, or legal-hold policies.
