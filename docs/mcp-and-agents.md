---
description: Connect MCP clients to Shellui with OAuth, agent access levels, approvals, revocation, and call logs.
---

# MCP and agents

MCP is in Beta. Tool names and behavior may still change.

Shellui Identity is the OAuth authorization server for MCP clients. Each connected client receives a company-scoped **agent** with explicit access rules. Storage, hosting, email, SaaS, AI, and other services reuse the same MCP layer from the [shellui-django](https://github.com/shellui/django-commons) package (`shellui_django.mcp`) for their `/mcp` endpoint.

Identity exposes its **own** MCP tools at `POST /mcp` on the identity origin (for example `identity_list_services`). Multi-service MCP clients connect through **ai-service**, which holds one OAuth session per agent and requests short-lived downstream access tokens from Identity when calling another service's `/mcp`. Identity never holds an ai-service secret; ai-service never holds Identity's signing key.

## Connect a client (one URL per company)

Each company has its own MCP URL on ai-service: `{AI_SERVICE_URL}/c/your_company_id_here/mcp` (for example `https://ai.example.com/c/42/mcp`). The company comes from the URL, so the user never picks one and there is no default company. Plain `{AI_SERVICE_URL}/mcp` answers with an error that points to the per-company URL.

Company AI clients connect through the ai-service gateway `/c/<company_id>/mcp`. By default, `tools/list` on that URL returns a discovery list: `ai_list_services`, `ai_search_tools`, `ai_describe_tool`, `ai_call_tool`, and common reads such as `identity_list_users`. `?tools=all` returns every tool. Direct calls to every tool still work, with the same approvals.

`GET /api/v1/mcp/personal/status` (company member Bearer token) returns `mcp_enabled` and optional regional `mcp_url` as today, plus optional `global_mcp_url`. When `DASHBOARD_PUBLIC_URL` is set to the trusted Shellui dashboard origin (https, no path), `global_mcp_url` is `{DASHBOARD_PUBLIC_URL}/mcp`. It does not depend on whether the regional gateway URL is configured.

The authorization server metadata lists `token_endpoint` as `POST /oauth/token` on the Identity host. `POST /oauth/mcp/token` is the same MCP handler for clients that still use the old path.

1. Add the per-company URL as a connector in ChatGPT, Claude, Grok, MCP Inspector, or another MCP client.
2. The client reads protected resource metadata from ai-service (`/.well-known/oauth-protected-resource/c/<company_id>/mcp`), then authorization server metadata on identity (`/.well-known/oauth-authorization-server`).
3. The client registers with **dynamic client registration** (`POST /oauth/mcp/register`) unless an operator disabled it (`MCP_DYNAMIC_CLIENT_REGISTRATION=false` or `Company.mcp_allow_dynamic_registration=false`). Registration is limited to `AUTH_RATE_LIMIT_MCP_REGISTER` per hour per IP.
4. The browser opens `GET /oauth/mcp/authorize` with PKCE S256 and RFC 8707 `resource={AI_SERVICE_URL}/c/your_company_id_here/mcp`. A signed-out user lands on identity's own sign-in page (`/oauth/mcp/signin`) and asks for an email sign-in link. That page never shows the company name or its sign-in methods, and it looks the same for every company id, known or not, so nobody can map ids to companies. The link is sent only when the company exists and turned the email link on. Staff accounts can't use the email link and can't authorize MCP clients, including when they already have an identity session. The page is limited to `AUTH_RATE_LIMIT_MCP_SIGNIN` requests per 5 minutes per IP.
5. When the browser already has an identity session for a member of that company, `/oauth/mcp/authorize`, `/oauth/mcp/device`, `/oauth/mcp/signin`, and `/oauth/mcp/approval/<id>` show **Continue as** that email and **Use another account**. Continue as opens the existing consent or approval step. It does not approve the client. Use another account clears the identity session and shows the sign-in form. A session that cannot access the company is treated as signed out. After sign-in, identity checks membership, then shows the consent page with the company name. An unknown company answers 404 only at this point. The user picks services, access level, and read level, then clicks **Approve**. Identity never approves on its own.
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

## Device login for headless agents

Headless agents (a CLI, or an assistant such as Hermes) use the [OAuth 2.0 device authorization grant](https://www.rfc-editor.org/rfc/rfc8628) so a token is never pasted into chat. The agent learns it is connected by polling the token endpoint. Identity does not push a callback.

The curl walkthrough is in [MCP device login](mcp-device-flow.md). Summary:

| Step | Where |
| --- | --- |
| Start | `POST /oauth/mcp/device/code` with `client_id` and `resource` (the company MCP URL) |
| Browser | `verification_uri` (`/oauth/mcp/device`). `verification_uri_complete` adds `user_code` |
| Poll | `POST /oauth/token` or `POST /oauth/mcp/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` |
| Discovery | `device_authorization_endpoint` and that grant type on `GET /.well-known/oauth-authorization-server` |

`user_code` is eight characters from an unambiguous alphabet, shown as `XXXX-XXXX`. `device_code` and `user_code` are stored as SHA-256 hashes and are not written to logs. Access logs keep the path only, with no query string. The device code expires in about 10 minutes (`expires_in`, default 600 seconds) and is single-use. Poll at `interval` (default 5 seconds). Faster polls return `slow_down`; the client adds 5 seconds before the next request. `authorization_pending` means the person has not finished. `access_denied` means they denied it. `expired_token` means the code expired. After approval the token response matches the authorization-code grant: a short-lived access token and a refresh token. `aud` is the company MCP URL.

The browser page uses the same sign-in and consent screens as `/oauth/mcp/authorize` for that company (email link and the company's SSO home realm, then services, access level, and read level). Staff accounts cannot approve. A person who is not a member of that company cannot approve. Code entry is limited to `AUTH_RATE_LIMIT_MCP_DEVICE_VERIFY` attempts per 5 minutes per IP (default 8).

Approval creates a normal agent row (`created_by` is the member, `oauth_client` is the registered client). It shows up in `GET /api/v1/mcp/personal/agents` as `kind: oauth` and is revoked with `POST /api/v1/mcp/personal/agents/{id}/revoke`. `expires_at` is capped by `MCP_PERSONAL_AGENT_MAX_LIFETIME_DAYS` (default 90). Access tokens stay short-lived (`MCP_ACCESS_TOKEN_LIFETIME`). Refresh uses `grant_type=refresh_token` and the same `resource`. Each approval writes `oauth.device.approved` to the agent call log, with no code or token.

Token claims are the same as other OAuth agent access tokens: `agent_id`, `company_id`, `aud` (the company MCP URL), `mcp_access`, `mcp_read`, `mcp_destructive`, `scope`, `grant_version`, `sub` (`agent:{uuid}`).

### What ai-service must advertise

Identity does not serve the company MCP resource. ai-service does. Clients discover the device grant by following protected-resource metadata to identity, then reading authorization-server metadata. ai-service should keep returning, for each company:

`GET /.well-known/oauth-protected-resource/c/<company_id>/mcp`

```json
{
  "resource": "https://ai.example.com/c/42/mcp",
  "authorization_servers": ["https://identity.example.com"],
  "scopes_supported": ["mcp"],
  "bearer_methods_supported": ["header"]
}
```

`authorization_servers` must be identity's issuer, the same string as `issuer` on identity's `GET /.well-known/oauth-authorization-server`. A 401 from `POST {AI_SERVICE_URL}/c/<company_id>/mcp` should send:

```http
WWW-Authenticate: Bearer realm="mcp", resource_metadata="https://ai.example.com/.well-known/oauth-protected-resource/c/42/mcp", scope="mcp"
```

Do not put `device_authorization_endpoint` on the protected-resource document. That field is on the authorization server metadata identity already serves. If `authorization_servers` already points at identity, ai-service does not need a new metadata field for device login. It does need the `resource_metadata` challenge so the client can find that document.

### Settings and Admin prompts

Shellui Settings and Admin list and revoke these connections with the personal-agent APIs. Each prompt includes only the company MCP URL and tells the agent to use [OAuth device authorization (RFC 8628)](https://www.rfc-editor.org/rfc/rfc8628). It has no access token, refresh token, device code, or user code. The agent registers if it needs a `client_id`, calls the device authorization endpoint, shows the user code, and polls until the token response arrives.

## Global agent token exchange (region role)

A region trusts two global issuers. Each exchange checks `iss`, `aud`, and `kid` against one of them:

- **User tokens** are issued by the global identity server (`identity-global`, role `global`). User token exchange at `POST /oauth/token` verifies `GLOBAL_ISSUER_URL`, `GLOBAL_JWKS`, and `GLOBAL_ACCESS_TOKEN_AUDIENCE`.
- **Agent tokens** are issued by saas-service, the OAuth authorization server for the global MCP. saas-service puts its public URL in `iss` (that deployment's `GLOBAL_ISSUER_URL`) and advertises it on `/.well-known/oauth-authorization-server`. Pin that URL as `GLOBAL_AGENT_ISSUER_URL` and the matching keys as `GLOBAL_AGENT_JWKS`.

Leave `GLOBAL_AGENT_ISSUER_URL` and `GLOBAL_AGENT_JWKS` empty to verify agent tokens with `GLOBAL_ISSUER_URL` and `GLOBAL_JWKS`. Set only one of them and that value is used, with the other falling back. A token from the user issuer is rejected at agent exchange, and a token from the agent issuer is rejected at user exchange. A `kid` that exists only in the other JWKS is rejected. Identity does not fetch a JWKS URL for either issuer.

Global MCP OAuth bound the account to a SaaS company (company binding on the global agent token). There is no second regional browser consent for exchanging that token: the subject proves they already completed global MCP consent. The regional server still checks enabled membership for `company_id`.

The flow uses OAuth 2.0 Token Exchange (RFC 8693) at `POST /oauth/token` on the regional identity server (`POST /oauth/mcp/token` is the same handler for an agent-shaped subject token). Agent exchange answers **404** unless the role is `region`, `GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE` is set, and the effective agent issuer and pinned JWKS are non-empty.

Export `SUBJECT_TOKEN` to the global MCP agent access JWT, then run:

```bash
curl -sS -X POST "https://identity.example.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=${SUBJECT_TOKEN}" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "company_id=42" \
  --data-urlencode "resource=https://ai.example.com/c/42/mcp" \
  --data-urlencode "access_mode=read_only" \
  --data-urlencode "read_level=safe" \
  --data-urlencode "allow_destructive=false" \
  --data-urlencode "services=identity" \
  --data-urlencode "services=storage"
```

Optional `access_mode`, `read_level`, `allow_destructive`, and repeated `services` keys may only **narrow** the global agent (never broaden). Each `services` value is one MCP tool service id (for example `identity`, `storage`). You do **not** need to repeat `ai` in that list: capability to use the AI gateway comes from the global subject token `scope` (OAuth-style space-separated service ids), not from the exchange body. When `services` is omitted on a later exchange, Identity intersects the new global scope with the regional agent's current `services_allowed` (it does not default back to the full global list). `allow_destructive` must be JSON `true` or `false` when present (string numerics are rejected); regional access tokens never set `mcp_destructive` true for delegated agents. The `resource` must be exactly this region's configured AI gateway for that company (`{AI_SERVICE_URL}/c/your_company_id_here/mcp`, host and path must match `AI_SERVICE_URL`). Identity, storage, hosting, email, dashboard, or another region's host are rejected. The global user must already own or belong to `company_id` in this region (enabled membership). Global staff are refused, same as user token exchange.

`company_id` must be a **JSON integer** in a JSON body, or **digits only** in form bodies (no floats or signed strings).

The global subject token `scope` must include **`ai`** when exchanging for that AI gateway resource. Without `ai` in `scope`, exchange is denied even if the body lists other services.

Identity verifies the subject token offline against the agent issuer's pinned JWKS (`iss`, `aud`, `kid`, `exp`, `jti` replay cache). When both agent settings are set, that check does not use `GLOBAL_ISSUER_URL` or `GLOBAL_JWKS`. It creates or reuses one regional `Agent` row per `(company_id, global_agent_id)` and issues the usual MCP access and refresh tokens for the requested `resource`. The regional account link stays `GLOBAL_ISSUER_URL` and `sub` (the global user id). Agent exchange does not store `GLOBAL_AGENT_ISSUER_URL` as an upstream account issuer. Paused or revoked regional agents cannot exchange again until an operator unpauses them.

When a global agent is revoked on saas-service, saas must call `POST /api/v1/provisioning/global-agents/revoke` on each region with `{ "global_agent_id": "<uuid>" }` and the usual provisioning assertion. That records the global id as revoked, revokes every linked regional agent and its refresh sessions, and refuses further exchange for that id even when no regional row existed yet. Short-lived global agent JWTs limit exposure if the webhook is delayed.

### Global agent access token claims (saas-service)

Global agent tokens are RS256 JWTs from saas-service. Mint them after global MCP OAuth consent. Required claims:

| Claim | Meaning |
| --- | --- |
| `iss` | Agent issuer (`GLOBAL_AGENT_ISSUER_URL` when set, otherwise `GLOBAL_ISSUER_URL`) |
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

- `POST /api/v1/mcp/internal/mcp-approval-requests` with a short-lived assertion (audience `shellui-mcp-approval`, scope `mcp.approval.create`), same pattern as [company deletion](company-deletion.md). The JSON body may include `is_destructive` (JSON boolean; omitted means false) and `arguments_summary` (optional string, at most 500 characters). `arguments_summary` is a redacted plain-text summary of the arguments. Identity stores it on `short_action_summary` and shows it on the approval page. Send it only when the text is safe to show to the person who decides. Identity rejects **any** `arguments` key (including `{}`) and rejects `arguments_redacted`, `target`, and `short_action_summary`: `target` is set to `{service}:{action}` and `arguments_redacted` stays `{}`. A still-pending row keeps the first summary. A summary sent later fills an empty one. Renewing an expired pending row replaces the summary.
  - **Regional row** (normal MCP agent): `company_id` is a JSON **positive** integer (regional tenant). `agent_id` is the regional `Agent` uuid string. Live authority: `grant_version` (JSON integer). If that agent is company-bound (`global_company_id` on the row), the assertion must also carry `global_company_id` (uuid string) and `company_binding_version` (JSON integer, `0` valid) and they must match the live `Agent`. If the agent is not company-bound, omit both binding claims.
  - **Global account row** (SaaS dashboard before a regional `Agent` exists): only **dashboard** (`PROVISIONING_ISSUER` / `PROVISIONING_PUBLIC_KEY`) may create. Use `company_id` **`0`** (JSON integer) and `agent_id` set to the **same** uuid string as `global_agent_id` (the assertion `sub` may be `agent:<global_agent_id>`). Required claims: `global_agent_id` (uuid string), `global_company_id` (uuid string), `global_user_sub` (non-empty string, global IdP `sub` for the acting user), `company_binding_version` (JSON integer), `grant_version` (JSON integer). Identity does **not** trust a forwarded owner flag; it checks ownership by resolving `UpstreamAccount` for `(issuer=GLOBAL_ISSUER_URL, sub=global_user_sub)` and requiring that user in `Company.owners` for the region `ProvisionedCompany` with that `global_company_id`. **Grant authority:** `grant_version` and `company_binding_version` must both equal the region **`ProvisionedCompany.limits_version`** for that `global_company_id`. `GlobalAgentRevocation` for `global_agent_id` blocks create. Optional `setup_expires_at` (JSON non-negative unix seconds, strictly in the future) must match the global subject token when that token carries setup expiry; if present and invalid, create fails. Global rows store `agent_id` and `company_id` as null on the approval row; lookups use the global ids and `global_user_sub`, not a regional agent id. **`allow_session` / session check / session revoke** internal routes return **400** for global bindings (session grants require a regional `Agent`).
  Only **ai-service** may use a longer assertion JWT lifetime (see `MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS`); storage, hosting, and email stay near 60 seconds. ai-service may add `setup_flow` and `mcp_session_ttl_seconds` (600 to 900) on signed assertions during new-company **regional** setup. Identity extends session Allow **only** when the regional `Agent` still has server-stored setup context from global token exchange (`setup_company_id`, `setup_context_expires_at`) and the gateway assertion passes the usual checks (`mcp_session_ttl_seconds` in band, `<= exp - iat`, and grant ends by `setup_context_expires_at`). Other callers and HTTP bodies cannot rely on those claims for a longer grant.
- `POST /api/v1/mcp/internal/mcp-approval-state` with the same approval assertion (no GET). This is the read ai-service uses to poll one pending approval. Identity looks up the latest row matching all assertion fields. `404` when no row exists. **200** always returns the same keys: `id` (approval uuid), `status` (`pending`, `approved`, `denied`, or `expired`), `expires_at` (ISO-8601), `is_destructive` (JSON boolean), and `approval_url` (absolute). Use `status` to decide. `id` is present for every status, including `pending`. Consume still requires `status` `approved`.
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
- When those three binding fields **do not** match the live row: **`200`** with **`authorized`:** `false`, **`active`:** `false` (fail closed). **`revoked`**, **`paused`**, **`revoked_at`**, **`access_mode`**, **`read_level`**, **`allow_destructive`**, and **`services_allowed`** still reflect the **live** row.
- **`allow_destructive`:** always `false` for delegated agents in this response (destructive tools still require a human approval per call).
- **`services_allowed`:** sorted list of service ids from the agent row.
- **`global_agent_id`:** always from the live row (never from the request body).

**200 body (fixed keys):** `authorized`, `active`, `revoked`, `paused`, `agent_id`, `company_id`, `global_agent_id`, `global_company_id`, `grant_version`, `company_binding_version`, `access_mode`, `read_level`, `allow_destructive`, `services_allowed`, `revoked_at` (unix seconds or JSON `null`).

This route is **not** cached on Identity.

Company owners and the member who created the agent approve or deny in Settings or via human user tokens:

- `GET /api/v1/mcp/approvals` (returns `approvals` and `pending_count`, the number of rows in `approvals`; pending rows include `service`, `action`, `tool_name`, `target` (`service:action`), `is_destructive`, `short_action_summary` (the optional `arguments_summary`, or empty), `arguments_redacted` (always `{}` for internal creates), and `approval_url` (absolute link to the same browser page))
- `GET /api/v1/mcp/approvals/{id}`
- `POST /api/v1/mcp/approvals/{id}/decide` with `{ "decision": "approve" | "deny" }`
- `POST /api/v1/mcp/approvals/{id}/approve` and `POST /api/v1/mcp/approvals/{id}/reject` (same behavior as decide)

The MCP client card (ai-service) calls `POST /api/v1/mcp/internal/mcp-approval-decide` with `allow`, `deny`, or `allow_session` (non-destructive only). Session allow lasts **60 seconds** per MCP connection by default (`MCP_APPROVAL_SESSION_TTL_SECONDS`, clamped 30 to 60). During new-company setup only, when the decision assertion is signed by **ai-service** and carries `setup_flow` with `mcp_session_ttl_seconds` between **600** and **900** (and not longer than the assertion JWT lifetime), and the regional agent still has setup context from exchange (above), Identity stores that TTL for this connection. The effective grant is capped by the **minimum** of remaining time to `setup_context_expires_at`, remaining time to the assertion JWT `exp`, and the configured max (`MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS`, default 900). If the minimum ceiling is below `MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS` (default 600), Identity uses the default session TTL instead (typically **60** seconds). Destructive actions never use session allow. `POST /api/v1/mcp/internal/mcp-approval-session-check` requires the same live authority claims as other internal approval routes (`grant_version` as JSON integer; when the agent is company-bound, `global_company_id` as uuid string and `company_binding_version` as JSON integer). The active session grant must still match the current agent: same `grant_version`, same SaaS binding pair when bound, and the grant's service set must stay within the agent's `services_allowed`. Setup echo fields come from the grant row snapshot at Allow time. Revoke on disconnect with `POST /api/v1/mcp/internal/mcp-approval-session-revoke`. Request bodies cannot set the TTL; only signed gateway claims count.

**Create response (200).** Identity keeps the previous fields and adds `approval_url`:

```json
{
  "id": "<uuid>",
  "status": "pending",
  "expires_at": "<iso-8601>",
  "is_destructive": false,
  "fallback_path": "/oauth/mcp/approval/<uuid>?token=<signed>",
  "approval_url": "https://<identity-host>/oauth/mcp/approval/<uuid>?token=<signed>"
}
```

`status` is the row status (`pending` on create). `expires_at` is when the request stops being decidable (10 minutes from create, or from the last renewal of an expired pending row). `approval_url` is absolute on this region's public identity origin (`JWT_ISSUER`). `fallback_path` is the same path and token, relative. The signed token lets the browser open that one request. It does not replace the identity session, and it is not a bearer token for the API.

**State response (200).** `POST /api/v1/mcp/internal/mcp-approval-state`:

```json
{
  "id": "<uuid>",
  "status": "pending",
  "expires_at": "<iso-8601>",
  "is_destructive": false,
  "approval_url": "https://<identity-host>/oauth/mcp/approval/<uuid>?token=<signed>"
}
```

`status` is `pending`, `approved`, `denied`, or `expired`. Each call mints a new signed token on `approval_url`. Older tokens for that row stay valid until the signature max age (the approval window plus two minutes).

Browser page: `GET /oauth/mcp/approval/{id}?token=…` (the path inside `approval_url`). It shows the company, the agent name, the OAuth client name when the agent has one, the service, the tool, the argument summary, whether the tool is destructive, and the expiry time in UTC. Approve and Deny are CSRF-protected POSTs. One decision only: a later POST does not change an approved or denied row, and repeating the same decision shows that result again. A signed-out visitor signs in with that company's magic link and OAuth methods on `/oauth/mcp/signin`, then returns to this page. The identity session offers **Continue as** and **Use another account**. Only a company owner, or the member who created the agent, can decide. Staff accounts are refused, the same rule as other MCP pages. An expired, already decided, or unknown link shows that state and no buttons. A global approval row (no regional company or agent) explains that it cannot be decided on this page. The page is English or French from `Accept-Language`.

Audit event `identity.mcp.approval_decision` uses status `approved`, `denied`, `expired`, `client_allowed`, `client_denied`, or `client_session_allowed` with `{actor_email} {status} {tool_name} for {agent_name}`. When the decide call stored them, the event data and `GET /api/v1/mcp/approvals/{id}` also include `consent` (`in_chat` or `link`) and `client_name`. The company event log (`GET /api/v1/events?event_type=identity.mcp.approval_decision`) is the approvals history. Empty values are omitted.

**Decide body.** `POST /api/v1/mcp/internal/mcp-approval-decide` keeps `approval_id`, `decision` (`allow`, `deny`, or `allow_session`), optional `actor_email`, and optional `connection_id` for session allow. It also accepts:

- `consent`: optional JSON string, exactly `in_chat` or `link`. Any other type or value is **400**. `consent` `in_chat` on a destructive row is **409** with `{"error": "In-chat consent is not allowed for a destructive tool."}` and the row stays pending. `link` is allowed for destructive and non-destructive rows.
- `client_name`: optional JSON string. Control characters become spaces, then whitespace is collapsed. The result must be at most 80 characters. A non-string is **400**. A longer string is **400**. A blank string is stored as omitted.

**200 decide response** keeps `approval_id`, `status` (the row status, `approved` or `rejected`), and `audit_status` (`client_allowed`, `client_denied`, or `client_session_allowed`). `consent` and `client_name` are included only when they were stored:

```json
{
  "approval_id": "<uuid>",
  "status": "approved",
  "audit_status": "client_allowed",
  "consent": "in_chat",
  "client_name": "Claude"
}
```

A call that omits both fields returns only `approval_id`, `status`, and `audit_status`.

## Revocation

Pause or revoke agents with:

- `POST /api/v1/mcp/agents/{id}/pause`
- `POST /api/v1/mcp/agents/{id}/revoke`

Services poll `GET /api/v1/mcp/internal/mcp-revocations` with a signed assertion (audience `shellui-mcp-revocation`, scope `mcp.revocation.read`, cache **30 seconds** on the consumer) so revocation is effective almost immediately. Optional `?company_id=` filters the list to one tenant. The JSON body includes:

- `revoked_agent_ids`: blocked regional agent ids only (revoked, paused, or expired). Unchanged. Not every agent.
- `agents`: every regional `Agent` in the same `company_id` filter (omit the filter to list the region). Each object is `agent_id` (regional primary key), `company_id`, `is_active`, `paused`, `grant_version`. `global_company_id` and `company_binding_version` are present only when that row has them. No other keys. `agent_id` is never a global agent uuid.
- `cache_seconds`: `30`
- `max_active_grant_version`: integer, the largest `grant_version` among agents with `revoked_at` null, or `0` when there is none. The JSON value and the signed claim are the same integer.
- **`revocation_policy_version`**: integer fingerprint of `revoked_agent_ids`, every agent snapshot, `cache_seconds`, and `max_active_grant_version`. It changes when a blocked id set changes, when any snapshot changes (`is_active`, `paused`, `grant_version`, or SaaS binding), or when the active grant cap changes.
- `revocation_assertion`: RS256 JWT (scope `mcp.revocation.list`, short `exp`) whose payload repeats `revoked_agent_ids`, `agents`, `cache_seconds`, `revocation_policy_version`, and `max_active_grant_version`. A body that omits or disagrees with any of those claims fails closed (`Revocation list body mismatch`). There is no feature flag.

Verify `revocation_assertion` with RS256 against Identity `/.well-known/jwks.json` (issuer `JWT_ISSUER`, audience `shellui-mcp-revocation`). Gateways that cache **positive** decisions (agent not in `revoked_agent_ids`) must treat the cache as stale when **`revocation_policy_version`** or the signed **`revocation_assertion`** JWT changes, or when the agent access token `jti` / `exp` / `grant_version` / `company_binding_version` no longer match.

**AI follow-up (field names):** rely on top-level **`revocation_policy_version`** and the same claim inside the verified **`revocation_assertion`**; pair with agent token **`grant_version`**, **`global_company_id`**, **`company_binding_version`**, **`setup_expires_at`** (when present), **`jti`**, and **`exp`**.

Identity tests use `apps.agents.trusted_revocation.parse_trusted_revocation_poll_response_identity` as a reference parser when shellui exposes a matching contract.

## Call logs

Services forward MCP call audit rows to `POST /api/v1/mcp/internal/mcp-call-logs` (assertion audience `shellui-mcp-call-log`). Identity stores them and emits `identity.mcp.call` security events. The body must include `outcome` as one of `allowed`, `failed`, `denied`, `waiting_approval`, or `session_used` (legacy `success`, `error`, `rate_limited`, `timeout`, and **`pending_approval`** are accepted on ingest and normalized to the five canonical values). Omitting `outcome` or sending an unknown string returns `400`. Identity does not infer an outcome from HTTP status alone. `company_id` must be a JSON integer in the body (same rule as the assertion). **Authority (required):** `grant_version` as a JSON integer must match the regional `Agent.grant_version`. For **delegated** agents (`global_agent_id` on the row), also send `global_company_id` (uuid string) and `company_binding_version` (JSON integer); they must match the agent row exactly. A mismatch returns **409** so a gateway cannot attach global ids from one SaaS binding to another regional agent. Personal agents must not send `global_company_id` / `company_binding_version`. **Destructive audit:** `access_kind` **`destructive`** stays `destructive` (it is not stored as `write`). The agent row must allow destructive tools (`global_max_destructive`). `session_used` is rejected. `allowed` and `failed` require `approval_id` for a destructive row whose status is `approved` or `executed` (consume leaves the row `executed`; Identity does not move it back to `approved`). `denied` and `waiting_approval` are not execution: `approval_id` is optional, and when present it must be a destructive row in `pending` or `rejected` with the same agent, company, service, tool, and authority snapshot. A fingerprint that does not match that call returns **400**. **Approval link:** when `approval_id` is present it must match the row (same agent, company, service, tool, and authority snapshot); wrong tool or row returns **400**. `arguments`, `arguments_redacted`, and client-supplied `operation_title` / `resource_label` are rejected; Identity derives labels from `tool`, `method`, `path`, and `service`. Query strings are stripped from `path` before validation. New rows store `arguments_redacted` as `{}`.

Activity and admin list APIs map legacy stored values to the five labels. Use `error_code` (allowlisted) for timeout or rate limit detail; outcome stays `failed` for those cases.

Owners read logs with `GET /api/v1/mcp/call-logs`.

### Global dashboard activity

`shellui-django` 0.4.0 `build_mcp_call_log_assertion` signs the normal call-log JWT (`aud` `shellui-mcp-call-log`, `scope` `mcp.call_log.create`, `sub` `service`) and does not add company claims. The SaaS dashboard, and only that caller (`PROVISIONING_ISSUER` / `PROVISIONING_PUBLIC_KEY`), adds these claims on that same JWT when the activity is for a provisioned global company:

| Claim | JSON type |
| --- | --- |
| `agent_audit_scope` | string `global_company` |
| `global_agent_id` | uuid string |
| `global_company_id` | uuid string |
| `global_user_sub` | non-empty string, global IdP `sub` of the company owner |
| `grant_version` | non-negative integer |
| `company_binding_version` | non-negative integer |

`grant_version` and `company_binding_version` must both equal `ProvisionedCompany.limits_version` for that `global_company_id`. Identity checks the owner with `UpstreamAccount` (`issuer` `GLOBAL_ISSUER_URL`, `sub` `global_user_sub`) and `Company.owners` on the provisioned regional company. It does not trust an owner flag. A revoked global agent is rejected. Any other caller that sends `agent_audit_scope` receives **403**. A partial claim set receives **400**. No `ProvisionedCompany` receives **404**.

The log is stored on that regional company. Identity does not create a company with id `0` and does not copy `global_agent_id` into `Agent.id`. One active regional `Agent` with that `global_agent_id`, regional company, `global_company_id`, and both versions is linked. No such row leaves `agent` null. More than one active match returns **409**.

The JSON body must not include `arguments`, `arguments_redacted`, `query`, `body`, `email`, `client_ip`, or `result`, and the URL must not include a query string. Optional `company_id` must be the provisioned company's numeric id. Optional `agent_id` must equal the signed `global_agent_id` and is not used as a regional primary key. `GET /api/v1/mcp/call-logs` adds `agent_audit_scope`, `global_agent_id`, and `global_company_id` only on these rows. Regional rows keep the previous keys. Personal activity is unchanged. The delegated-authority **200** body stays 15 keys.

`approval_id` is accepted only when that one regional agent matches the approval fingerprint (`agent`, company, service, tool, grant, SaaS binding). Identity does not invent an approval. Destructive outcomes follow the regional rules above, including `executed` after consume.

### Unbound first company

Identity does not accept a `create_first_company` approval or activity row before a `ProvisionedCompany` exists. Settings approvals (`GET /api/v1/mcp/approvals`) and the approval fallback page load a regional `Company` and `Agent`. A null company row is not listed there, and `user_may_manage_approval` reads `row.agent`. Writing that row would not be owner-visible, so Identity does not write it and does not invent a regional company or agent to force it onto the list. After SaaS creates the company and the provisioned row exists, use the global dashboard activity assertion above. Existing global approval create (claim `company_id` `0` as a placeholder, real `ProvisionedCompany` required) is unchanged and is not a first-company bootstrap.

## Downstream access tokens (ai-service)

When ai-service forwards `tools/call` to storage, hosting, email, SaaS, or Identity, it asks Identity to mint a regional agent access token for that downstream `/mcp` URL.

- **Endpoint:** `POST /api/v1/mcp/internal/mcp-downstream-access-token` (answers **404** unless `AI_SERVICE_URL`, `AI_SERVICE_ISSUER`, and pinned `AI_SERVICE_JWKS` or `AI_SERVICE_JWKS_URL` are set).
- **Authorization:** `Bearer` RS256 delegation JWT signed by ai-service (`shellui_django.mcp.delegation.sign_downstream_token_request` on the caller). Identity verifies with `verify_downstream_token_request` against ai-service JWKS and expected issuer `AI_SERVICE_ISSUER`. Audience `shellui-mcp-downstream-token`, scope `mcp.downstream_token.mint`. Claims include `agent_id`, `company_id`, `resource`, and single-use `jti` (cached on Identity).
- **JSON body:** `{ "agent_id": "<uuid>", "company_id": <int>, "resource": "<canonical /mcp URL>" }` must match the JWT claims.
- **Response:** `{ "access_token": "<Identity RS256 agent JWT>" }` with the same agent claims as OAuth, `aud` narrowed to `resource`.
- **Checks:** agent exists, active, not revoked, belongs to `company_id`; `resource` is exactly one configured service `/mcp` URL and allowed in the agent's `services_allowed`. Per-agent and global rate limits apply. Identity never logs minted tokens.

## identity_list_services

On Identity `/mcp`, the `identity_list_services` tool returns MCP URLs discovered from existing settings:

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

Agent bearer tokens cannot pause, revoke, approve, list call logs, or change agent settings. Those admin routes require a human company owner token (`allow_agent_token=false`) and are not exported as MCP tools. Identity `/mcp` exposes the company admin operations on the MCP allowlist. Service discovery is `identity_list_services`.

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
