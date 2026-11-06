---
description: Connect MCP clients to Shellui with OAuth, agent access levels, approvals, revocation, and call logs.
---

# MCP and agents

Shellui Identity is the OAuth authorization server for MCP clients. Each connected client receives a company-scoped **agent** with explicit access rules. Storage, hosting, email, SaaS, AI, and other services reuse the same MCP layer from the [shellui-django](https://github.com/shellui/django-commons) package (`shellui_django.mcp`) for their `/mcp` endpoint.

Identity exposes its **own** MCP tools at `POST /mcp` on the identity origin (for example `list_services`). Multi-service MCP clients connect through **ai-service**, which holds one OAuth session per agent and requests short-lived downstream access tokens from Identity when calling another service's `/mcp`. Identity never holds an ai-service secret; ai-service never holds Identity's signing key.

## Connect a client (one URL per company)

Each company has its own MCP URL on ai-service: `{AI_SERVICE_URL}/c/your_company_id_here/mcp` (for example `https://ai.example.com/c/42/mcp`). The company comes from the URL, so the user never picks one and there is no default company. Plain `{AI_SERVICE_URL}/mcp` answers with an error that points to the per-company URL.

`GET /api/v1/mcp/personal/status` (company member Bearer token) returns `mcp_enabled` and optional regional `mcp_url` as today, plus optional `global_mcp_url`. When `DASHBOARD_PUBLIC_URL` is set to the trusted Shellui dashboard origin (https, no path), `global_mcp_url` is `{DASHBOARD_PUBLIC_URL}/mcp`. It does not depend on whether the regional gateway URL is configured.

The authorization server metadata lists `token_endpoint` as `POST /oauth/token` on the Identity host. `POST /oauth/mcp/token` is the same MCP handler for clients that still use the old path.

1. Add the per-company URL as a connector in ChatGPT, Claude, Grok, MCP Inspector, or another MCP client.
2. The client reads protected resource metadata from ai-service (`/.well-known/oauth-protected-resource/c/<company_id>/mcp`), then authorization server metadata on identity (`/.well-known/oauth-authorization-server`).
3. The client registers with **dynamic client registration** (`POST /oauth/mcp/register`) unless an operator disabled it (`MCP_DYNAMIC_CLIENT_REGISTRATION=false` or `Company.mcp_allow_dynamic_registration=false`). Registration is limited to `AUTH_RATE_LIMIT_MCP_REGISTER` per hour per IP.
4. The browser opens `GET /oauth/mcp/authorize` with PKCE S256 and RFC 8707 `resource={AI_SERVICE_URL}/c/your_company_id_here/mcp`. A signed-out user lands on identity's own sign-in page (`/oauth/mcp/signin`) and asks for an email sign-in link. That page never shows the company name or its sign-in methods, and it looks the same for every company id, known or not, so nobody can map ids to companies. The link is sent only when the company exists and turned the email link on. Staff accounts can't use the email link and can't authorize MCP clients. The page is limited to `AUTH_RATE_LIMIT_MCP_SIGNIN` requests per 5 minutes per IP.
5. After sign-in, identity checks that the user is a member of the company, then shows the consent page with the company name. An unknown company answers 404 only at this point. The user picks services, access level, and read level, then clicks **Approve**. Identity never approves on its own.
6. The client exchanges the code at `POST /oauth/token` (or `POST /oauth/mcp/token`) with the same `resource`. Send **RFC 6749 form** (`application/x-www-form-urlencoded`); repeated keys are preserved. JSON bodies are also accepted. The access token's `aud` is the per-company URL and its `company_id` is that company. Refresh tokens stay bound to the same resource.

### What the sign-in and consent pages show

Both pages exist to stop phishing, so they show before anything else:

- why the user is here: "the MCP client wants to access your company through the Shellui MCP connector" before sign-in, and with the company name on consent;
- the client name, marked as chosen by the client and not verified;
- the full host of the return address, before sign-in;
- a warning not to continue if the user didn't start the connection.

### Rules identity enforces

- Redirect URIs use https, or http on a loopback host (`127.0.0.1`, `localhost`, `::1`). Every other scheme (`javascript:`, `data:`, custom app schemes) is rejected, and so are fragments and user info. Authorize compares the value to the registered list exactly, with no wildcards.
- An unknown client, a redirect URI that doesn't match, or an invalid resource gets an error page on identity. Identity never redirects in that case.
- An unknown company looks like a known one until sign-in, then answers 404.
- The only saved return value is a relative `/oauth/mcp/authorize?...` path on identity.
- Every page sends `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`. Forms use CSRF tokens.
- Each approval writes a `oauth.authorize.approved` row to the agent call log, with the client, return host, resource, and chosen access. It holds no code or token.

Company ids in the URL are integers. Companies have no public non-sequential id yet (the slug comes from the name), so moving the URL to one is left for later.

Downstream services keep their own `{origin}/mcp` resource. ai-service reaches them with short-lived downstream tokens, so clients only need the per-company URL.

## Global agent token exchange (region role)

Global MCP OAuth bound the user to a SaaS company (company binding on the global agent token). There is no second regional browser consent for exchanging that token: the subject proves they already completed global MCP consent. The regional server still checks enabled membership for `company_id`.

The flow uses OAuth 2.0 Token Exchange (RFC 8693) at `POST /oauth/token` on the regional identity server (`POST /oauth/mcp/token` is the same handler). The endpoint answers **404** unless the role is `region` and `GLOBAL_ISSUER_URL`, `GLOBAL_JWKS`, and `GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE` are set.

Export a shell variable to the global MCP agent access JWT (for example `GLOBAL_MCP_AGENT_JWT`), then run:

```bash
curl -sS -X POST "https://identity.example.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "company_id=42" \
  --data-urlencode "resource=https://ai.example.com/c/42/mcp" \
  --data-urlencode "access_mode=read_only" \
  --data-urlencode "read_level=safe" \
  --data-urlencode "allow_destructive=false" \
  --data-urlencode "services=identity" \
  --data-urlencode "services=storage" \
  --data-urlencode "subject_token=$GLOBAL_MCP_AGENT_JWT"  # gitleaks:allow OAuth RFC 8693 parameter name subject_token; value is a shell variable, not a pasted secret
```

Optional `access_mode`, `read_level`, `allow_destructive`, and repeated `services` keys may only **narrow** the global agent (never broaden). Each `services` value is one MCP tool service id (for example `identity`, `storage`). You do **not** need to repeat `ai` in that list: capability to use the AI gateway comes from the global subject token `scope` (OAuth-style space-separated service ids), not from the exchange body. When `services` is omitted on a later exchange, Identity intersects the new global scope with the regional agent's current `services_allowed` (it does not default back to the full global list). `allow_destructive` must be JSON `true` or `false` when present (string numerics are rejected); regional access tokens never set `mcp_destructive` true for delegated agents. The `resource` must be exactly this region's configured AI gateway for that company (`{AI_SERVICE_URL}/c/your_company_id_here/mcp`, host and path must match `AI_SERVICE_URL`). Identity, storage, hosting, email, dashboard, or another region's host are rejected. The global user must already own or belong to `company_id` in this region (enabled membership). Global staff are refused, same as user token exchange.

`company_id` must be a **JSON integer** in a JSON body, or **digits only** in form bodies (no floats or signed strings).

The global subject token `scope` must include **`ai`** when exchanging for that AI gateway resource. Without `ai` in `scope`, exchange is denied even if the body lists other services.

Identity verifies the subject token offline against `GLOBAL_JWKS` (`iss`, `aud`, `exp`, `jti` replay cache). It creates or reuses one regional `Agent` row per `(company_id, global_agent_id)` and issues the usual MCP access and refresh tokens for the requested `resource`. Paused or revoked regional agents cannot exchange again until an operator unpauses them.

When a global agent is revoked on saas-service, saas must call `POST /api/v1/provisioning/global-agents/revoke` on each region with `{ "global_agent_id": "<uuid>" }` and the usual provisioning assertion. That records the global id as revoked, revokes every linked regional agent and its refresh sessions, and refuses further exchange for that id even when no regional row existed yet. Short-lived global agent JWTs limit exposure if the webhook is delayed.

### Global agent access token claims (saas-service)

Global agent tokens are RS256 JWTs from the global identity issuer. Mint them after global MCP OAuth consent. Required claims:

| Claim | Meaning |
| --- | --- |
| `iss` | Global issuer (`GLOBAL_ISSUER_URL` on regions) |
| `aud` | `GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE` on regions (separate from user `GLOBAL_ACCESS_TOKEN_AUDIENCE`) |
| `sub` | Global user id (agent owner) |
| `agent_id` | Global agent uuid |
| `token_type` | `agent_access` (not `access`; no `sid` or `pat_id`) |
| `mcp_authority` | Always `global_delegated` (required; no legacy omission) |
| `email`, `email_verified` | Owner email; `email_verified` must be boolean `true` |
| `user_metadata.is_staff` | Boolean `false` for non-staff; staff exchange is refused |
| `scope` | Space-separated OAuth-style service ids (`identity`, `storage`, `ai`, …); include `ai` when the user enabled that capability (required for `{AI_SERVICE_URL}/c/your_company_id_here/mcp` exchange) |
| `mcp_access`, `mcp_read`, `mcp_destructive` | Same semantics as regional agent JWTs |
| `jti`, `iat`, `exp` | Short lifetime (match global MCP access TTL) |

Optional: `agent_name` for the regional agent display name.

**Company binding (global subject token):** both `global_company_id` (uuid string) and `company_binding_version` (non-negative integer, `0` allowed) with strict JSON types. Identity rejects exchange when either claim is missing or malformed. Identity stores them on the regional `Agent` and echoes them on regional agent access tokens. Later exchanges must not switch `global_company_id` and must not downgrade `company_binding_version`. Legacy regional agents created before binding may still omit these until the next exchange. Treat a signed token exchange as identity wiring only: MCP consent and membership still follow the OAuth and company flows below.

**New-company setup (global subject token, regional exchange):** optional `setup_flow` as JSON `true` or `false` only. When `setup_flow` is `true`, the global token must also carry `mcp_new_company_grant` as JSON **`true`** (strings, `1`, or omitted values are rejected). Pairing enforces that the global issuer actually selected the first-company setup grant and clients cannot turn it on alone. Require `setup_context_company_id` (JSON positive integer, must equal regional `company_id`), `setup_expires_at` (JSON non-negative unix seconds, strictly after `iat`, not after global `exp`), and `mcp_session_ttl_seconds` in the 600 to 900 band, with strict JSON integer types. Identity rejects legacy `setup_context_exp`. When `setup_flow` is `false`, do not send `mcp_new_company_grant`. When both setup claims are absent on a later exchange, Identity clears any stored setup context on the regional agent. Identity derives **`mcp_new_company_grant` on the regional access token** only after this validation. Regional MCP access tokens echo `setup_context_company_id`, `setup_expires_at`, `setup_flow`, `mcp_new_company_grant`, and `mcp_session_ttl_seconds` while that window is active. The ai-service gateway forwards the same into approval **assertions**. Identity extends session Allow only when the assertion is ai-signed, `mcp_session_ttl_seconds` is in the configured band, the grant is not longer than `exp - iat` on the assertion JWT, **and** both remaining seconds to regional access token `exp` and remaining seconds to `setup_context_expires_at` are at least `MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS` (default 600). If the shorter of those ceilings is under that floor, session Allow stays at the default (typically **60** seconds). If these global claims are absent or wrong, session Allow stays at that default.

**Delegated agents and internal approvals:** agents with `global_agent_id` (token exchange) must use approvals signed by **ai-service**. Storage, hosting, and email get **409** with `error_code` `out_of_sync` if they try to create an approval for that agent.

**Regional agent access tokens (after exchange):** include **`mcp_authority: delegated`** (this is **not** `global_delegated` on the global subject token), **`global_agent_id`**, and the SaaS binding echo **`global_company_id`** / **`company_binding_version`** when the row is company-bound. OAuth-consent agents without `global_agent_id` omit `mcp_authority` (personal long-lived tokens stay unchanged). Regional access tokens minted through `POST /api/v1/mcp/internal/mcp-downstream-access-token` use the same claim builder, so delegated agents keep **`mcp_authority: delegated`** on every downstream resource token.

**Personal regional tokens:** omit `mcp_authority` unless the agent row is delegated; when present, `mcp_authority` is always **`delegated`** (never `global_delegated`).

## Access levels

| Mode | Value | Behavior |
| --- | --- | --- |
| Read only | `read_only` | Safe HTTP methods and tools tagged `x-mcp.read_only` |
| Ask before changes | `ask` (default) | Writes create a pending approval |
| Full access | `full` | Writes run immediately when the tool is not marked destructive |

**Destructive changes:** Identity never runs a destructive tool without a **separate human approval** for that action (delegated agents included: exchange may narrow `allow_destructive` on the body, but regional JWTs keep `mcp_destructive` false and approvals still gate each destructive call). OAuth consent no longer offers "destructive without asking". Settings and the personal-token API reject attempts to enable it; `mcp_destructive` is always `false` on regional JWTs for delegated (`mcp_authority: delegated`) agents. **Staff** accounts cannot complete MCP OAuth or agent flows; use a company human member.

## Read levels

| Level | Value | Behavior |
| --- | --- | --- |
| Safe | `safe` (default) | Masks personal data in tool results |
| Sensitive | `sensitive` | Returns more fields; still never returns stored secrets |

## Approvals

When a write needs human confirmation, the service creates an approval through Identity:

- `POST /api/v1/mcp/internal/mcp-approval-requests` with a short-lived assertion (audience `shellui-mcp-approval`, scope `mcp.approval.create`), same pattern as [company deletion](company-deletion.md). The JSON body is optional for `is_destructive` only. Identity rejects **any** `arguments` key (including `{}`) and rejects `arguments_redacted`, `target`, and `short_action_summary`: `target` is set to `{service}:{action}` and `arguments_redacted` stays `{}`.
  - **Regional row** (normal MCP agent): `company_id` is a JSON **positive** integer (regional tenant). `agent_id` is the regional `Agent` uuid string. Live authority: `grant_version` (JSON integer). If that agent is company-bound (`global_company_id` on the row), the assertion must also carry `global_company_id` (uuid string) and `company_binding_version` (JSON integer, `0` valid) and they must match the live `Agent`. If the agent is not company-bound, omit both binding claims.
  - **Global account row** (SaaS dashboard before a regional `Agent` exists): only **dashboard** (`PROVISIONING_ISSUER` / `PROVISIONING_PUBLIC_KEY`) may create. Use `company_id` **`0`** (JSON integer) and `agent_id` set to the **same** uuid string as `global_agent_id` (the assertion `sub` may be `agent:<global_agent_id>`). Required claims: `global_agent_id` (uuid string), `global_company_id` (uuid string), `global_user_sub` (non-empty string, global IdP `sub` for the acting user), `company_binding_version` (JSON integer), `grant_version` (JSON integer). Identity does **not** trust a forwarded owner flag; it checks ownership by resolving `UpstreamAccount` for `(issuer=GLOBAL_ISSUER_URL, sub=global_user_sub)` and requiring that user in `Company.owners` for the region `ProvisionedCompany` with that `global_company_id`. **Grant authority:** `grant_version` and `company_binding_version` must both equal the region **`ProvisionedCompany.limits_version`** for that `global_company_id`. `GlobalAgentRevocation` for `global_agent_id` blocks create. Optional `setup_expires_at` (JSON non-negative unix seconds, strictly in the future) must match the global subject token when that token carries setup expiry; if present and invalid, create fails. Global rows store `agent_id` and `company_id` as null on the approval row; lookups use the global ids and `global_user_sub`, not a regional agent id. **`allow_session` / session check / session revoke** internal routes return **400** for global bindings (session grants require a regional `Agent`).
  Only **ai-service** may use a longer assertion JWT lifetime (see `MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS`); storage, hosting, and email stay near 60 seconds. ai-service may add `setup_flow` and `mcp_session_ttl_seconds` (600 to 900) on signed assertions during new-company **regional** setup. Identity extends session Allow **only** when the regional `Agent` still has server-stored setup context from global token exchange (`setup_company_id`, `setup_context_expires_at`) and the gateway assertion passes the usual checks (`mcp_session_ttl_seconds` in band, `<= exp - iat`, and grant ends by `setup_context_expires_at`). Other callers and HTTP bodies cannot rely on those claims for a longer grant.
- `POST /api/v1/mcp/internal/mcp-approval-state` with the same approval assertion (no GET). Identity looks up the latest row matching all assertion fields and returns `pending`, `approved`, `denied`, or `expired`. `404` when no row exists. Approved responses include `id` (approval uuid) for consume.
- `POST /api/v1/mcp/internal/mcp-approval-consume` with the same approval assertion. JSON body: `{ "approval_id": "<uuid>" }`. Identity loads the row using the same binding as state (regional: `approval_id` plus `agent_id`, `company_id`, `service`, `arguments_hash`; global: `approval_id` plus global binding fields). Any mismatch returns `404`. Consumption is atomic (`select_for_update`) and single use; `{ "consumed": true }` only while the row is approved and younger than 10 minutes.
- One pending row per binding and arguments hash, **expires after 10 minutes**, runs once, never standing. Regional binding is `(agent_id, company_id, service, action, arguments_hash)`. Global binding is `(global_agent_id, global_company_id, company_binding_version, global_user_sub, service, action, arguments_hash)`.

Storage, hosting, and email must use this contract exactly (assertion fields on state and consume, `approval_id` in the consume body).

**Delegated agents (`global_agent_id` set):** direct internal approval routes from storage, hosting, or email return **409** with `error_code` **`out_of_sync`**. Route those approvals through the **regional ai-service gateway** for that company, or use a **personal** agent credential when a human-owned direct flow is appropriate. That rule is intentional; hosting docs that describe a user-owned credential for direct service calls stay valid.

### Trusted callers for internal assertions

Every `/api/v1/mcp/internal/mcp-*` assertion is RS256, signed by the calling service with its own private key (`shellui_django` 0.4.0+). HS256 and `alg: none` are refused. Identity keeps a registry of trusted callers (`apps/agents/internal_callers.py`) and verifies each assertion with the public key of the caller whose issuer matches `iss`:

| Caller | Issuer setting | Public key |
|--------|----------------|------------|
| ai-service | `AI_SERVICE_ISSUER` | `AI_SERVICE_JWKS` or `AI_SERVICE_JWKS_URL` |
| storage-service | `STORAGE_SERVICE_ISSUER` | `STORAGE_SERVICE_JWKS` or `STORAGE_SERVICE_JWKS_URL` |
| hosting-service | `HOSTING_SERVICE_ISSUER` | `HOSTING_SERVICE_JWKS` or `HOSTING_SERVICE_JWKS_URL` |
| email-service | `EMAIL_SERVICE_ISSUER` | `EMAIL_SERVICE_JWKS` or `EMAIL_SERVICE_JWKS_URL` |
| dashboard (saas-service) | `PROVISIONING_ISSUER` | `PROVISIONING_PUBLIC_KEY` |

A caller with no issuer set is not trusted. Unknown issuers and wrong keys get `401`. Each `jti` is accepted once. Storage, hosting, and email may only create or read approvals for their own `service`, otherwise `403`.

### Live delegated agent authority (canonical)

Use this route to verify a regional **delegated** agent row against the live SaaS binding before trusting a downstream MCP token or approval path. Do **not** substitute revocation polling alone; this check reads the current `Agent` row. **No aliases:** JSON body keys are exactly `agent_id`, `company_id`, `global_company_id`, `grant_version`, `company_binding_version` (no `regional_id`, `global_agentid`, or extras). **200** responses always return the **same fixed keys** below (plus `revoked_at`, which is `null` when not revoked); values come from the live row together with the binding triple from the request.

- **Endpoints (same handler):**
  - **Canonical:** `POST /api/v1/mcp/internal/mcp-agent-delegated-authority`
  - **Aliases:** `POST /api/v1/mcp/internal/mcp-delegated-authority` and `POST /api/v1/mcp/internal/mcp-delegated-agent-authority`
- **Authorization:** `Bearer` RS256 assertion (`shellui_django.mcp.internal` verification rules), same pattern as other internal routes
  - `aud`: **`shellui-mcp-agent-delegated-authority`**
  - `scope`: **`mcp.agent.delegated.authority.read`**
  - `target`: Identity issuer (`JWT_ISSUER`, same as other internal assertions)
  - `iss`: the regional service issuer (`STORAGE_SERVICE_ISSUER`, `HOSTING_SERVICE_ISSUER`, `EMAIL_SERVICE_ISSUER`, or `AI_SERVICE_ISSUER`)
  - `sub`: `service`, `iat`, `exp`, `jti` as usual
  - **Only** these claims are allowed on the JWT. Extra claims (for example copied subject tool fields) are rejected with **401**.
- **Callers allowed:** storage, hosting, email, and ai-service only (`403` for dashboard and other issuers).
- **JSON body (strict, only these keys):**
  - `agent_id`: uuid string (regional `Agent` primary key)
  - `company_id`: JSON **positive** integer (regional company)
  - `global_company_id`: uuid string (SaaS binding, non-empty)
  - `grant_version`: JSON non-negative integer (`0` valid)
  - `company_binding_version`: JSON non-negative integer (`0` valid)

**HTTP**

| Situation | Status |
| --- | --- |
| Malformed or unsigned assertion; unknown issuer; wrong audience, scope, target, signature, lifetime, or replayed `jti`; extra JWT claims | **401** |
| No `Authorization: Bearer` assertion (empty body path) | **404** |
| Unknown JSON fields; wrong scalar types | **400** |
| Caller not in the allowlist (for example dashboard) | **403** |
| Agent row missing; `global_agent_id` null (personal agent) | **404** |

**200** response. Identity loads the agent by **`agent_id` and `company_id`** (body must match the row).

- When **`global_company_id` / `grant_version` / `company_binding_version`** match the live delegated row: **`authorized`** is `true` only if the agent would issue tokens: not paused, not expired, not revoked, and not globally blocked for that `global_agent_id`. Otherwise **`authorized`** is `false`.
- When those three binding fields **do not** match the live row: **`200`** with **`authorized`:** `false`, **`active`:** `false` (fail closed). **`revoked`**, **`paused`**, **`revoked_at`**, **`access_mode`**, **`read_level`**, **`allow_destructive`**, **`allow_destructive_without_asking`**, **`services_allowed`**, and **`global_allowed_services`** still reflect the **live** row.
- **`allow_destructive`:** always `false` for delegated agents in this response (destructive tools still require a human approval per call).
- **`allow_destructive_without_asking`:** from the live agent row (expected `false` for delegated rows created under current rules; included so gateways see the same field as non-delegated authority checks).
- **`services_allowed`:** sorted list of service ids from the agent row (effective regional allow list after exchange narrowing).
- **`global_allowed_services`:** sorted list from the agent row (cap from the last verified global subject token scope; exchange cannot widen past this).
- **`global_agent_id`:** always from the live row (never from the request body).

**200 body (fixed keys):** `authorized`, `active`, `revoked`, `paused`, `agent_id`, `company_id`, `global_agent_id`, `global_company_id`, `grant_version`, `company_binding_version`, `access_mode`, `read_level`, `allow_destructive`, `allow_destructive_without_asking`, `services_allowed`, `global_allowed_services`, `revoked_at` (unix seconds or JSON `null`).

This route is **not** cached on Identity.

Company owners and the member who created the agent approve or deny in Settings or via human user tokens:

- `GET /api/v1/mcp/approvals` (returns `approvals` and `pending_count`, the number of rows in `approvals`; pending rows include `service`, `action`, `tool_name`, `target` (`service:action`), `is_destructive`, `short_action_summary` (same as `action`), and `arguments_redacted` (always `{}` for internal creates))
- `GET /api/v1/mcp/approvals/{id}`
- `POST /api/v1/mcp/approvals/{id}/decide` with `{ "decision": "approve" | "deny" }`
- `POST /api/v1/mcp/approvals/{id}/approve` and `POST /api/v1/mcp/approvals/{id}/reject` (same behavior as decide)

The MCP client card (ai-service) calls `POST /api/v1/mcp/internal/mcp-approval-decide` with `allow`, `deny`, or `allow_session` (non-destructive only). Session allow lasts **60 seconds** per MCP connection by default (`MCP_APPROVAL_SESSION_TTL_SECONDS`, clamped 30 to 60). During new-company setup only, when the decision assertion is signed by **ai-service** and carries `setup_flow` with `mcp_session_ttl_seconds` between **600** and **900** (and not longer than the assertion JWT lifetime), and the regional agent still has setup context from exchange (above), Identity stores that TTL for this connection. The effective grant is capped by the **minimum** of remaining time to `setup_context_expires_at`, remaining time to the assertion JWT `exp`, and the configured max (`MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS`, default 900). If the minimum ceiling is below `MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS` (default 600), Identity uses the default session TTL instead (typically **60** seconds). Destructive actions never use session allow. `POST /api/v1/mcp/internal/mcp-approval-session-check` requires the same live authority claims as other internal approval routes (`grant_version` as JSON integer; when the agent is company-bound, `global_company_id` as uuid string and `company_binding_version` as JSON integer). The active session grant must still match the current agent: same `grant_version`, same SaaS binding pair when bound, and the grant's service set must stay within the agent's `services_allowed`. Setup echo fields come from the grant row snapshot at Allow time. Revoke on disconnect with `POST /api/v1/mcp/internal/mcp-approval-session-revoke`. Request bodies cannot set the TTL; only signed gateway claims count.

Fallback browser page: `GET /oauth/mcp/approval/{id}?token=…` (signed token from `fallback_path` on create). Approve and Deny only.

Audit event `identity.mcp.approval_decision` uses status `approved`, `denied`, `expired`, `client_allowed`, `client_denied`, or `client_session_allowed` with `{actor_email} {status} {tool_name} for {agent_name}`.

## Revocation

Pause or revoke agents with:

- `POST /api/v1/mcp/agents/{id}/pause`
- `POST /api/v1/mcp/agents/{id}/revoke`

Services poll `GET /api/v1/mcp/internal/mcp-revocations` with a signed assertion (audience `shellui-mcp-revocation`, scope `mcp.revocation.read`, cache **30 seconds** on the consumer) so revocation is effective almost immediately. Optional `?company_id=` filters the list to one tenant. The JSON body includes:

- `revoked_agent_ids`, `agents` (snapshots for **blocked** agents: `agent_id`, `company_id`, `is_active`, `paused`, `grant_version`), `cache_seconds`
- **`revocation_policy_version`**: integer fingerprint that changes when the blocked set changes, when any blocked agent snapshot changes, or when company-scoped **permission invalidation** bumps `Agent.grant_version` on an active agent (session Allow revoked, membership disabled, grant revoked, or agent `access_mode` / `read_level` / `allow_destructive_without_asking` / `services_allowed` updated)
- `revocation_assertion`: RS256 JWT (scope `mcp.revocation.list`, short `exp`) whose payload repeats `revoked_agent_ids`, `agents`, `cache_seconds`, and **`revocation_policy_version`**

Verify `revocation_assertion` with RS256 against Identity `/.well-known/jwks.json` (issuer `JWT_ISSUER`, audience `shellui-mcp-revocation`). Gateways that cache **positive** decisions (agent not in `revoked_agent_ids`) must treat the cache as stale when **`revocation_policy_version`** or the signed **`revocation_assertion`** JWT changes, or when the agent access token `jti` / `exp` / `grant_version` / `company_binding_version` no longer match.

**AI follow-up (field names):** rely on top-level **`revocation_policy_version`** and the same claim inside the verified **`revocation_assertion`**; pair with agent token **`grant_version`**, **`global_company_id`**, **`company_binding_version`**, **`setup_expires_at`** (when present), **`jti`**, and **`exp`**.

Identity tests use `apps.agents.trusted_revocation.parse_trusted_revocation_poll_response_identity` as a reference parser when shellui exposes a matching contract.

## Call logs

Services forward MCP call audit rows to `POST /api/v1/mcp/internal/mcp-call-logs` (assertion audience `shellui-mcp-call-log`). Identity stores them and emits `identity.mcp.call` security events. The body must include `outcome` as one of `allowed`, `failed`, `denied`, `waiting_approval`, or `session_used` (legacy `success`, `error`, `rate_limited`, `timeout`, and **`pending_approval`** are accepted on ingest and normalized to the five canonical values). Omitting `outcome` or sending an unknown string returns `400`. Identity does not infer an outcome from HTTP status alone. `company_id` must be a JSON integer in the body (same rule as the assertion). **Authority (required):** `grant_version` as a JSON integer must match the regional `Agent.grant_version`. For **delegated** agents (`global_agent_id` on the row), also send `global_company_id` (uuid string) and `company_binding_version` (JSON integer); they must match the agent row exactly. A mismatch returns **409** so a gateway cannot attach global ids from one SaaS binding to another regional agent. Personal agents must not send `global_company_id` / `company_binding_version`. **Global control-plane activity (no regional `Agent` row yet):** when `global_agent_id` (uuid string) is present, omit `agent_id`. The assertion must be **dashboard**-signed (`PROVISIONING_ISSUER` / `PROVISIONING_PUBLIC_KEY`), not a regional service key (**403** otherwise). Send `company_id` as a **positive** regional integer that matches the `ProvisionedCompany` row for `global_company_id`; send `grant_version` and `company_binding_version` as JSON integers and both must equal `ProvisionedCompany.limits_version` for that binding (**409** on mismatch). The row is stored with `agent` null and `company` set to that tenant; **destructive** `access_kind` is rejected for this path. Optional `approval_id` must reference a **global** pending row (null `agent_id` / `company_id` on the approval) with the same `global_agent_id`, `global_company_id`, `company_binding_version`, service, and tool as the body. **Destructive audit:** `access_kind` **`destructive`** is accepted only when the agent row allows destructive tools (`global_max_destructive`), `outcome` is **`allowed`** or **`session_used`**, and `approval_id` is present, refers to an **approved** row with `is_destructive` true, and matches the same agent, company, service, tool, and authority snapshot as internal approvals. **Approval link:** when `approval_id` is present it must match the row (same agent, company, service, tool, and authority snapshot); wrong tool or row returns **400**. `arguments`, `arguments_redacted`, and client-supplied `operation_title` / `resource_label` are rejected; Identity derives labels from `tool`, `method`, `path`, and `service`. Query strings are stripped from `path` before validation. New rows store `arguments_redacted` as `{}`.

Activity and admin list APIs map legacy stored values to the five labels. Use `error_code` (allowlisted) for timeout or rate limit detail; outcome stays `failed` for those cases.

Owners read logs with `GET /api/v1/mcp/call-logs`.

## Downstream access tokens (ai-service)

When ai-service forwards `tools/call` to storage, hosting, email, SaaS, or Identity, it asks Identity to mint a regional agent access token for that downstream `/mcp` URL.

- **Endpoint:** `POST /api/v1/mcp/internal/mcp-downstream-access-token` (answers **404** unless `AI_SERVICE_URL`, `AI_SERVICE_ISSUER`, and pinned `AI_SERVICE_JWKS` or `AI_SERVICE_JWKS_URL` are set).
- **Authorization:** `Bearer` RS256 delegation JWT signed by ai-service (`shellui_django.mcp.delegation.sign_downstream_token_request` on the caller). Identity verifies with `verify_downstream_token_request` against ai-service JWKS and expected issuer `AI_SERVICE_ISSUER`. Audience `shellui-mcp-downstream-token`, scope `mcp.downstream_token.mint`. Claims include `agent_id`, `company_id`, `resource`, and single-use `jti` (cached on Identity).
- **JSON body:** `{ "agent_id": "<uuid>", "company_id": <int>, "resource": "<canonical /mcp URL>" }` must match the JWT claims.
- **Response:** `{ "access_token": "<Identity RS256 agent JWT>" }` with the same agent claims as OAuth, `aud` narrowed to `resource`.
- **Checks:** agent exists, active, not revoked, belongs to `company_id`; `resource` is exactly one configured service `/mcp` URL and allowed in the agent's `services_allowed`. Per-agent and global rate limits apply. Identity never logs minted tokens.

## list_services

On Identity `/mcp`, the `list_services` tool returns MCP URLs discovered from existing settings:

- Identity: `JWT_ISSUER` + `/mcp`
- Storage: `STORAGE_SERVICE_URL` + `/mcp`
- Hosting: `HOSTING_SERVICE_URL` + `/mcp`
- Email: `EMAIL_SERVICE_URL` + `/mcp` when `EMAIL_SERVICE_API_KEY` is set
- SaaS: `SAAS_SERVICE_URL` + `/mcp` (use the configured public **https** origin from env; do not paste git remote URLs or other non-HTTP values into this setting)
- AI gateway (company clients): `{AI_SERVICE_URL}/c/<company_id>/mcp` (same host and path pattern as OAuth `resource`; not the plain `{AI_SERVICE_URL}/mcp` root)

Downstream minting uses only these configured origins (never a URL from the client).

## Agent JWT claims

Access tokens include:

| Claim | Meaning |
| --- | --- |
| `aud` | RFC 8707 resource URL (per-company AI gateway `{AI_SERVICE_URL}/c/<company_id>/mcp` or a plain service `{origin}/mcp`) |
| `sub` | `agent:{uuid}` |
| `agent_id` | Agent uuid |
| `company_id` | Company id |
| `scope` | Space-separated service ids |
| `grant_version` | Bumps when company-scoped MCP permissions invalidate session Allow grants |
| `global_company_id` | SaaS global company uuid when the regional agent is bound |
| `company_binding_version` | SaaS binding generation for that global company |
| `setup_context_company_id` / `setup_expires_at` / `setup_flow` / `mcp_new_company_grant` / `mcp_session_ttl_seconds` | New-company setup window on the regional token (from global exchange when valid) |
| `mcp_access` | `read_only`, `ask`, or `full` |
| `mcp_read` | `safe` or `sensitive` |
| `mcp_destructive` | Boolean on the JWT; `true` only for non-delegated agents that still have legacy `allow_destructive_without_asking`. Always `false` when `mcp_authority` is **`delegated`**. |

Refresh tokens use `grant_type=refresh_token` at `POST /oauth/token` (or `POST /oauth/mcp/token`) with the same `resource` parameter. Each refresh token is bound to one resource.

Regional Identity deployments scope agents to the company only (no `project_scope` in consent or JWT). Project binding for SaaS is enforced in saas-service.

Agent bearer tokens cannot pause, revoke, approve, list call logs, or change agent settings. Those admin routes require a human company owner token (`allow_agent_token=false`) and are not exported as MCP tools. Identity `/mcp` exposes only non-admin tools such as `list_services`.

Staff accounts cannot call `/api/v1/mcp/*` company admin APIs (same refusal as MCP OAuth).

## shellui-django MCP (other services)

Add the PyPI package `shellui-django[mcp]` (source: [django-commons](https://github.com/shellui/django-commons)) to storage, hosting, email, saas, and ai-service. Wire:

- `POST /mcp` using `shellui_django.mcp.server.McpServer`
- ai-service: aggregated gateway in `shellui_django.mcp.gateway` plus downstream token delegation (`shellui_django.mcp.delegation`)
- OpenAPI tools from operations tagged `mcp-tools` only (`@mcp_expose_tool`)
- Protected resource metadata pointing at Identity
- Revocation checks against Identity
- Per-agent rate limits and call log forwarding

See module docstrings in `shellui_django.mcp.internal` for assertion audiences and scopes.
