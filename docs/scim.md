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

1. Set **`SCIM_ENABLED=true`** on the identity-service container (see [Configuration](configuration.md)).
2. Run migrations (`apps.scim`, `CompanyGroup` SCIM fields, nested `member_groups`).
3. Create a **Company SCIM token** (Shellui admin **SCIM** setup or Django admin); copy the bearer secret once.
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
| (provenance) | `source` — `manual` (Shellui admin) or `scim` (IdP); stored on the row, not in SCIM payloads |

**Rename note:** the former `name` field is now **`display_name`**. Admin REST group APIs use `display_name` in JSON.

### Hybrid groups (`source`)

Companies may hold **both** Shellui-managed and IdP-managed groups at once:

| `source` | Created by | SCIM Groups list/get | Admin REST `/api/v1/groups` |
| -------- | ---------- | -------------------- | --------------------------- |
| `manual` | Admin REST (always), legacy rows before SCIM | **Hidden** — not visible to the IdP | Create, rename, delete allowed |
| `scim` | SCIM create/update adapters | Visible and fully managed by IdP | **403** on PATCH/PUT/DELETE |

When SCIM is first enabled, **existing `CompanyGroup` rows stay `manual`**; nothing is deleted or reclassified. New groups from the IdP get `source=scim`. SCIM adapters never downgrade `scim` → `manual`.

**Nested groups:** SCIM `members` with `type: "Group"` may reference only **`source=scim`** groups in the same company (keeps the IdP graph free of Shellui-only groups).

**User `groups` in SCIM:** only direct membership in **`source=scim`** groups for the token company (manual Shellui groups are omitted from User resources).

**JWT / Shellui login `groups`:** unchanged — **effective** membership includes **both** manual and scim groups (direct + nested ancestors). See below.

**`display_name` uniqueness (one namespace):** `display_name` remains **unique per company across both sources** (required for JWT `groups` / files ACL). SCIM create or rename that collides with an existing **manual** group returns **409 Conflict** with a message that the name is taken by a Shellui-managed group — the manual row is never adopted or overwritten. Admin create/rename that collides with a **scim** group returns **409** with a distinct message. Until the conflict is resolved (rename or delete the manual group in Shellui admin, or change the IdP push name), IdP sync for that display name will keep failing. Automatic adoption of manual groups into SCIM is **not** supported.

**409 observability:** Each collision is written to structured logs and an append-only **`ScimProvisioningEvent`** (`group_display_name_conflict`), and updates **`CompanyScimProvisioningState.last_error_*`** for the company. Shellui admin **`GET /api/v1/scim`** returns `last_provisioning_error` and a short `recent_provisioning_events` list so operators can diagnose name clashes without IdP logs. The IdP may retry provisioning; responses stay **409** until the name clash is fixed.

---

## Nested groups

SCIM Group **`members`** may include:

- **`type: "User"`** — `value` = user SCIM id (Django user pk string); user must already belong to the company.
- **`type: "Group"`** — `value` = nested group id in the **same company**.

**Cycle policy:** self-membership and cycles (e.g. A contains B and B contains A) are rejected with **400 Bad Request**.

**DELETE group:** removes the `CompanyGroup` row and M2M links; **does not** cascade-delete nested child groups (children remain; they are only unlinked from the deleted parent).

**User `groups` in SCIM:** lists groups where the user is a **direct** `members` M2M member (not groups inferred only via nesting). IdPs may flatten or nest on their side.

**JWT / Shellui login `groups` (OAuth tokens, `GET /api/v1/user`, admin user payloads):** **effective** company groups — every group where the user is a direct member **plus** every ancestor reached via nested `member_groups` (walk `parent_groups` upward, same company, cycle-safe). Downstream services (for example files-backend authorization) should treat this claim as transitive membership.

**Effective membership helpers** (`apps.companies.group_graph`):

| Direction | Functions |
| --------- | --------- |
| Group → users | `effective_user_ids_for_group()`, `effective_users_for_group()` |
| User → groups | `effective_group_ids_for_user()`, `effective_group_display_names_for_user()` |

Company login access still uses `CompanyMembership`, not group membership.

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
| `groups[]` | Direct membership in **`source=scim`** groups only |

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

## Admin REST (Shellui admin)

Staff or **company owner** JWT with the usual company scope (`company_id` query/body or `company_id` claim in the access token). Same authorization as `/api/v1/oauth-redirects` and `/api/v1/groups`.

**Directory groups (`/api/v1/groups`):** list/retrieve include `source`. POST always creates `source=manual` (allowed even when SCIM tokens are active). PUT/PATCH/DELETE return **403** when `source=scim`.

| Method | Path | Notes |
| ------ | ---- | ----- |
| GET | `/api/v1/scim` | Deployment `enabled` (`SCIM_ENABLED`), company `base_url`, `configured` / `active_token_count`, `directory_read_only` (always `false` under hybrid), `scim_groups_read_only` (`true` when an active token exists — SCIM-sourced rows only), `last_provisioning_error`, `recent_provisioning_events` |
| GET | `/api/v1/scim/tokens` | List tokens (`results[]`: id, name, token_prefix, timestamps, `is_active`; no secret) |
| POST | `/api/v1/scim/tokens` | Body `{ "name": optional }`; response includes full `token` **once** (403 when SCIM disabled on deploy) |
| POST | `/api/v1/scim/tokens/<uuid>/revoke` | Revoke token (idempotent; allowed when SCIM disabled) |

Example (owner JWT):

```bash
curl -s -H "Authorization: Bearer $ACCESS" \
  "https://auth.example.com/api/v1/scim?company_id=1"

curl -s -X POST -H "Authorization: Bearer $ACCESS" -H "Content-Type: application/json" \
  -d '{"name":"Okta prod"}' \
  "https://auth.example.com/api/v1/scim/tokens?company_id=1"
```

---

## Token rotation

Create a new Company SCIM token (admin REST or Django admin), update IdP, revoke the old row.

---

## Tenant isolation (security)

SCIM is **strictly scoped to one company** per request:

1. **Bearer token binding** — The `CompanyScimToken` row fixes the tenant. The URL segment `<company_slug>` must match that company’s slug; otherwise the response is **401** (no handler logic runs on a mismatched pair).
2. **Users** — List/get/update paths filter with `companies=<token company>` (and membership post-checks). A user id that exists globally but **not** in the token company returns **404**, not another tenant’s payload.
3. **Groups** — All queries use `company=<token company>` and **`source=scim`**. Manual Shellui groups are invisible on the SCIM surface. Nested group members and user members are resolved only among scim-sourced groups in that company; foreign or manual ids return **404**.
4. **Multi-company users** — The same Django user may appear in SCIM for company A and B with separate tokens. `active` / deprovision affects **only** `CompanyMembership` for the token’s company; other companies are unchanged and the user row is not deleted.
5. **User `groups` in SCIM** — Only **`source=scim`** `CompanyGroup` rows for the **current** SCIM company where the user is a direct member.
6. **Effective membership helper** — `group_graph.effective_user_ids_for_group()` walks nested groups **only** when `member_groups.company_id` matches the root group’s company (defense in depth).
7. **Filter / `.search`** — SQL extras append company/membership constraints so raw filter queries cannot bypass ORM scoping.

Cross-tenant access attempts are covered by regression tests in `apps/scim/tests/test_scim_tenant_isolation.py`.

---

## Related

- [Configuration](configuration.md) — `SCIM_ENABLED` and runtime env
- [Company access modes](company-access.md)
- [Security hardening](security-hardening.md)
