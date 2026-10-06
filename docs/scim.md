---
description: Provision users and groups into a Shellui company from Okta, Microsoft Entra ID, or another SCIM 2.0 identity provider.
---

# SCIM provisioning

identity-service is a SCIM 2.0 service provider, so an identity provider (IdP) such as Okta or Microsoft Entra ID can create, update, and disable users and groups in a company. Each company has its own SCIM base URL and bearer token. SCIM users are regular users with a company membership, and SCIM groups are company groups that show up in the JWT `groups` claim.

SCIM is available on every deployment. A company turns provisioning on by creating a SCIM token, and off by revoking it. `SCIM_ENABLED=false` is an emergency switch for the whole deployment: every SCIM URL then returns **404**.

## Set up provisioning

1. In Shellui admin, open **SCIM** setup and create a token (or use the [admin API](#admin-api)). Copy the secret: it is shown once.
2. In the IdP, set the base URL and the header `Authorization: Bearer your_scim_token_here`.
3. Assign users and push groups from the IdP, then check them in Shellui admin.

The base URL is:

```text
https://auth.example.com/api/v1/companies/{company_id}/scim/v2/
```

`{company_id}` is the numeric company ID. `GET /api/v1/scim` returns this `base_url` for the selected company.

To rotate a token, create a new one, update the IdP, then revoke the old one.

## Endpoints

All paths are relative to the base URL. The token and the company ID in the URL must belong to the same company.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `ServiceProviderConfig` | Discovery |
| `GET` | `ResourceTypes` | User and Group |
| `GET` | `Schemas` | Exposed schemas |
| `GET`, `POST` | `Users` | List, create |
| `GET`, `PUT`, `PATCH`, `DELETE` | `Users/{id}` | Read, replace, patch, deprovision |
| `GET`, `POST` | `Groups` | List, create |
| `GET`, `PUT`, `PATCH`, `DELETE` | `Groups/{id}` | Read, replace, patch, delete |

## Users

SCIM user attributes map to the user and to the membership in the token's company:

| SCIM | identity-service |
| --- | --- |
| `id` | User ID (string) |
| `userName` | Username |
| `name.givenName`, `name.familyName` | First name, last name |
| `emails[].value` | Email |
| `active` | Membership enabled in the token's company |
| `externalId` | `UserScimAttributes.scim_external_id` |
| `groups[]` | Direct membership in SCIM groups only |

### Deprovision a user

`DELETE`, or `active: false`, disables the user's membership in the company. The user row stays, and memberships in other companies are not touched. identity-service also revokes the user's refresh sessions and personal access tokens for that company, so a deprovisioned owner cannot keep calling admin APIs.

### Existing accounts

When the IdP creates a user whose email or username already exists on the deployment, identity-service returns **409** with a generic uniqueness error and does not link the account. This blocks account takeover across companies. A retry with the same email can reveal that the address is registered, but not which company owns it. Handle a **409** in the IdP or in Shellui admin.

### Email and username rules

Emails are stored normalized (Unicode NFKC, lowercase), and non-ASCII local parts are rejected. A company SCIM token cannot:

- assign an email that another user already has
- change the email or username of staff, superusers, users who belong to several companies, users with no membership, or the internal SCIM account

## Groups

SCIM groups are company groups (`CompanyGroup`). Their `displayName` is the name in the JWT `groups` claim, and must be unique in the company.

| SCIM | `CompanyGroup` |
| --- | --- |
| `displayName` | `display_name` |
| `externalId` | `external_id` (unique per company when set) |
| `members[]` of type `User` | `members` |
| `members[]` of type `Group` | `member_groups` (nested groups, same company) |

### Shellui and IdP groups side by side

A company can have groups created in Shellui admin and groups pushed by the IdP at the same time. The `source` field tells them apart:

| `source` | Created by | Seen by the IdP | Admin API `/api/v1/groups` |
| --- | --- | --- | --- |
| `manual` | Shellui admin, and every group created before SCIM | No | Create, rename, delete |
| `scim` | The IdP | Yes, fully managed by the IdP | **403** on `PUT`, `PATCH`, `DELETE` |

Turning SCIM on does not change existing groups: they stay `manual`. A SCIM group never becomes `manual`. The SCIM `groups` of a user list only SCIM groups, while the JWT `groups` claim includes both kinds.

### Name conflicts

`display_name` is unique per company across both sources, because the JWT `groups` claim and access rules rely on the name. When the IdP creates or renames a group to the name of a `manual` group, identity-service returns **409** and never takes over the manual group. Creating or renaming a manual group to the name of a SCIM group also returns **409**.

IdP sync for that name keeps failing until you rename or delete the manual group, or change the name in the IdP. Each conflict is logged, stored as a `group_display_name_conflict` provisioning event, and shown by `GET /api/v1/scim` in `last_provisioning_error` and `recent_provisioning_events`.

### Nested groups

A group's `members` can include users (`type: "User"`, the user ID, already in the company) and SCIM groups of the same company (`type: "Group"`). A group cannot contain itself, directly or through a cycle: the request returns **400**. Deleting a group removes its links, but not its child groups.

The SCIM `groups` of a user list direct memberships only. The JWT `groups` claim, `GET /api/v1/user`, and admin user payloads list effective groups: direct memberships plus every parent group reached through nesting. Services that read the claim, such as files-backend, should treat it as transitive membership. See [JWT and JWKS](jwks.md#groups-claim).

Company access depends on the membership, not on groups.

## Admin API

Staff and company owners manage SCIM with a JWT scoped to the company (`company_id` in the query, body, or token), the same authorization as `/api/v1/oauth-redirects` and `/api/v1/groups`:

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/scim` | `enabled` (deployment), `base_url`, `configured`, `active_token_count`, `scim_groups_read_only` (`true` with an active token), `last_provisioning_error`, `recent_provisioning_events` |
| `GET` | `/api/v1/scim/tokens` | Tokens with ID, name, prefix, timestamps, and `is_active`. No secret |
| `POST` | `/api/v1/scim/tokens` | Body `{"name": "Okta prod"}` (optional). The response contains the full `token` once. **403** when SCIM is off for the deployment |
| `POST` | `/api/v1/scim/tokens/{id}/revoke` | Revokes the token. Idempotent, also works when SCIM is off |

```bash
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://auth.example.com/api/v1/scim?company_id=1"

curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Okta prod"}' \
  "https://auth.example.com/api/v1/scim/tokens?company_id=1"
```

## Tenant isolation

Every SCIM request is scoped to the company of its token:

- **Token binding**: the token fixes the company. A token used with another company's URL gets **401** before any handler runs
- **Users**: only members of the token's company are visible. A user from another company returns **404**
- **Groups**: only SCIM groups of the token's company are visible. Manual groups and other companies' IDs return **404**, also as group members
- **Users in several companies**: each company has its own token. Deprovisioning disables only the membership in the token's company
- **Filters**: the SQL for filters adds the company constraints, so a raw filter cannot bypass them

Regression tests for cross-company access are in `apps/scim/tests/test_scim_tenant_isolation.py`.

## Limitations

- Filters and `.search` are advertised as unsupported; use the list endpoints
- Bulk, `/Me`, and ETag are not implemented
- `PATCH` follows [django-scim2](https://pypi.org/project/django-scim2/) semantics
- Use PostgreSQL in production; SQLite is only used for CI tests

Some IdPs, depending on their settings, flatten nested groups when they push them. After provisioning, read the parent group with `GET Groups/{id}` to check nested membership.

## Related

- [Company access](company-access.md): access modes and memberships
- [SAML single sign-on](saml.md): sign-in from the same IdP
- [Security hardening](security-hardening.md)
