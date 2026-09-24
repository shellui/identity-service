# Enterprise SCIM (user and group provisioning)

Shellui identity-service can act as a **SCIM 2.0 service provider** for **per-company** user and group provisioning. Each company has its own SCIM base URL and bearer token; provisioned users are normal Django users with **company membership** (`CompanyMembership.is_enabled`), and groups map to **`CompanyGroup`** (SCIM field names, same company scope).

This feature is **opt-in**: set `SCIM_ENABLED=true` on the deployment. When disabled, SCIM URLs return **404**.

---

## Library choice

| Package | Role |
| -------- | ----- |
| **[django-scim2](https://pypi.org/project/django-scim2/)** (v0.23+) | SCIM 2.0 provider (Users/Groups CRUD, PATCH, discovery). Custom adapters + company-scoped URLs. |
| **[scim2-filter-parser](https://pypi.org/project/scim2-filter-parser/)** | Filter parsing (dependency). |

**Alternatives considered:** mitol-django-scim (Keycloak-centric); browniebroke/django-scim2-server (early-stage); from-scratch RFC 7644 (high maintenance).

---

## Enable on Coolify / Docker

1. Set **`SCIM_ENABLED=true`** on the identity-service container.
2. Run migrations (`apps.scim`, `CompanyGroup` SCIM fields, nested `member_groups`).
3. **Django admin → Company SCIM tokens** — create a token; copy the bearer secret once.
4. Configure IdP with base URL + `Authorization: Bearer <token>`.

---

## Base URL and endpoints

```text
https://{host}/api/v1/companies/{company_slug}/scim/v2/
```

| Method | Path | Notes |
| ------ | ---- | ----- |
| GET | `ServiceProviderConfig` | Discovery |
| GET | `ResourceTypes` | **User** and **Group** |
| GET | `Schemas` | Exposed schemas |
| GET/POST | `Users` | List / create |
| GET/PUT/PATCH/DELETE | `Users/{id}` | Read / replace / patch / deprovision (disable membership) |
| GET/POST | `Groups` | List / create |
| GET/PUT/PATCH/DELETE | `Groups/{id}` | Read / replace / patch / delete group row |

**Authentication:** `Authorization: Bearer <company-scim-token>` — token and URL slug must match the same company.

---

## Django model vocabulary (`CompanyGroup`)

Operators and migrations use SCIM-aligned names on the company-scoped group model:

| SCIM | Django (`CompanyGroup`) |
| ---- | ------------------------ |
| `displayName` | `display_name` (unique per company) |
| `externalId` | `external_id` (unique per company when set) |
| `members[]` type **User** | `members` M2M → `User` |
| `members[]` type **Group** | `member_groups` M2M → `CompanyGroup` (nested, same company) |
| (tenant) | `company` FK — not exposed in SCIM payloads |

**Rename note:** the former `name` field is now **`display_name`**. Admin REST group APIs use `display_name` in JSON.

---

## Nested groups

SCIM Group **`members`** may include:

- **`type: "User"`** — `value` = user SCIM id (Django user pk string); user must already belong to the company.
- **`type: "Group"`** — `value` = nested group id in the **same company**.

**Cycle policy:** self-membership and cycles (e.g. A contains B and B contains A) are rejected with **400 Bad Request**.

**DELETE group:** removes the `CompanyGroup` row and M2M links; **does not** cascade-delete nested child groups (children remain; they are only unlinked from the deleted parent).

**User `groups` in SCIM:** lists groups where the user is a **direct** `members` M2M member (not groups inferred only via nesting). IdPs may flatten or nest on their side.

**Effective membership:** `apps.companies.group_graph.effective_user_ids_for_group()` (and `effective_users_for_group()`) returns all users in a group including users in nested member groups, transitively and cycle-safe. OAuth/login access today still uses direct company membership; the expander is available for tests and future access rules.

---

## Attribute mapping (Users)

| SCIM | Shellui / Django |
| ---- | ---------------- |
| `userName` | `User.username` |
| `name.givenName` / `name.familyName` | `User.first_name` / `User.last_name` |
| `emails[].value` | `User.email` |
| `active` | `CompanyMembership.is_enabled` for the token’s company |
| `externalId` | `UserScimAttributes.scim_external_id` |
| `id` | Django user pk (string) |
| `groups[]` | Direct `CompanyGroup` memberships only |

**Deprovision user:** `DELETE` or `active: false` disables company membership; user row retained.

---

## IdP notes (sketch)

**Okta / Entra ID:** SCIM base URL as above; bearer token; map groups with optional nested group push/pull depending on IdP (some flatten). Test nested membership with GET Group on parent after provisioning.

---

## Limitations

- **Filters / `.search`:** Advertised unsupported (django-scim2 default); use list endpoints.
- **Bulk, Me, ETag:** Not implemented.
- **PATCH:** Partial semantics per django-scim2 upstream docs.
- **Postgres** recommended in production for filter SQL; CI uses SQLite for CRUD smoke tests.

---

## Token rotation

Create a new Company SCIM token, update IdP, revoke the old row in admin.

---

## Tenant isolation (security)

SCIM is **strictly scoped to one company** per request:

1. **Bearer token binding** — The `CompanyScimToken` row fixes the tenant. The URL segment `<company_slug>` must match that company’s slug; otherwise the response is **401** (no handler logic runs on a mismatched pair).
2. **Users** — List/get/update paths filter with `companies=<token company>` (and membership post-checks). A user id that exists globally but **not** in the token company returns **404**, not another tenant’s payload.
3. **Groups** — All queries use `company=<token company>`. Nested group members and user members are resolved only within that company; foreign ids return **404**.
4. **Multi-company users** — The same Django user may appear in SCIM for company A and B with separate tokens. `active` / deprovision affects **only** `CompanyMembership` for the token’s company; other companies are unchanged and the user row is not deleted.
5. **User `groups` in SCIM** — Only `CompanyGroup` rows for the **current** SCIM company where the user is a direct member.
6. **Effective membership helper** — `group_graph.effective_user_ids_for_group()` walks nested groups **only** when `member_groups.company_id` matches the root group’s company (defense in depth).
7. **Filter / `.search`** — SQL extras append company/membership constraints so raw filter queries cannot bypass ORM scoping.

Cross-tenant access attempts are covered by regression tests in `apps/scim/tests/test_scim_tenant_isolation.py`.

---

## Related

- [Company access modes](company-access.md)
- [Security hardening](security-hardening.md)
