---
description: Connect MCP clients to Shellui with OAuth, agent access levels, approvals, revocation, and call logs.
---

# MCP and agents

Shellui Identity is the OAuth authorization server for MCP clients. Each connected client receives a company-scoped **agent** with explicit access rules. Storage, hosting, email, SaaS, AI, and other services reuse the same MCP layer from the [shellui-django](https://github.com/shellui/django-commons) package (`shellui_django.mcp`) for their `/mcp` endpoint.

Identity exposes its **own** MCP tools at `POST /mcp` on the identity origin (for example `list_services`). Multi-service MCP clients connect through **ai-service**, which holds one OAuth session per agent and requests short-lived downstream access tokens from Identity when calling another service's `/mcp`. Identity never holds an ai-service secret; ai-service never holds Identity's signing key.

## Connect a client (one URL per company)

Each company has its own MCP URL on ai-service: `{AI_SERVICE_URL}/c/<company_id>/mcp` (for example `https://ai.example.com/c/42/mcp`). The company comes from the URL, so the user never picks one and there is no default company. Plain `{AI_SERVICE_URL}/mcp` answers with an error that points to the per-company URL.

1. Add the per-company URL as a connector in ChatGPT, Claude, Grok, MCP Inspector, or another MCP client.
2. The client reads protected resource metadata from ai-service (`/.well-known/oauth-protected-resource/c/<company_id>/mcp`), then authorization server metadata on identity (`/.well-known/oauth-authorization-server`).
3. The client registers with **dynamic client registration** (`POST /oauth/mcp/register`) unless an operator disabled it (`MCP_DYNAMIC_CLIENT_REGISTRATION=false` or `Company.mcp_allow_dynamic_registration=false`). Registration is limited to `AUTH_RATE_LIMIT_MCP_REGISTER` per hour per IP.
4. The browser opens `GET /oauth/mcp/authorize` with PKCE S256 and RFC 8707 `resource={AI_SERVICE_URL}/c/<company_id>/mcp`. A signed-out user lands on identity's own sign-in page (`/oauth/mcp/signin`) and asks for an email sign-in link. That page never shows the company name or its sign-in methods, and it looks the same for every company id, known or not, so nobody can map ids to companies. The link is sent only when the company exists and turned the email link on. Staff accounts can't use the email link and can't authorize MCP clients. The page is limited to `AUTH_RATE_LIMIT_MCP_SIGNIN` requests per 5 minutes per IP.
5. After sign-in, identity checks that the user is a member of the company, then shows the consent page with the company name. An unknown company answers 404 only at this point. The user picks services, access level, and read level, then clicks **Approve**. Identity never approves on its own.
6. The client exchanges the code at `POST /oauth/mcp/token` with the same `resource`. The access token's `aud` is the per-company URL and its `company_id` is that company. Refresh tokens stay bound to the same resource.

### What the sign-in and consent pages show

Both pages exist to stop phishing, so they show before anything else:

- why the user is here: "`<client>` wants to access your company through the Shellui MCP connector" before sign-in, and with the company name on consent;
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

A user who authorized an MCP agent on the global console can exchange that **global agent access token** for a **regional agent access token** bound to one company in this region, without a second browser consent on the region. The flow uses OAuth 2.0 Token Exchange (RFC 8693) at `POST /oauth/mcp/token` on the regional identity server. The endpoint answers **404** unless the role is `region` and `GLOBAL_ISSUER_URL`, `GLOBAL_JWKS`, and `GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE` are set.

```
POST /oauth/mcp/token
Content-Type: application/json

{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<global agent JWT>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "company_id": "<regional company id>",
  "resource": "https://<regional-host>/mcp",
  "access_mode": "read_only",
  "read_level": "safe",
  "allow_destructive": false,
  "services": ["identity", "storage"]
}
```

Optional `access_mode`, `read_level`, `allow_destructive`, and `services` may only **narrow** the global agent (never broaden). The `resource` must match a service still allowed after narrowing. The global user must already own or belong to `company_id` in this region (enabled membership). Global staff are refused, same as user token exchange.

Identity verifies the subject token offline against `GLOBAL_JWKS` (`iss`, `aud`, `exp`, `jti` replay cache). It creates or reuses one regional `Agent` row per `(company_id, global_agent_id)` and issues the usual MCP access and refresh tokens for the requested `resource`. Paused or revoked regional agents cannot exchange again until an operator unpauses them.

When a global agent is revoked on saas-service, saas must call `POST /api/v1/provisioning/global-agents/revoke` on each region with `{ "global_agent_id": "<uuid>" }` and the usual provisioning assertion. That records the global id as revoked, revokes every linked regional agent and its refresh sessions, and refuses further exchange for that id even when no regional row existed yet. Short-lived global agent JWTs limit exposure if the webhook is delayed.

### Global agent access token claims (saas-service)

Global agent tokens are RS256 JWTs from the global identity issuer. saas-service should mint them after global MCP OAuth consent (not implemented in saas yet). Required claims:

| Claim | Meaning |
| --- | --- |
| `iss` | Global issuer (`GLOBAL_ISSUER_URL` on regions) |
| `aud` | `GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE` on regions (separate from user `GLOBAL_ACCESS_TOKEN_AUDIENCE`) |
| `sub` | Global user id (agent owner) |
| `agent_id` | Global agent uuid |
| `token_type` | `agent_access` (not `access`; no `sid` or `pat_id`) |
| `email`, `email_verified` | Owner email; `email_verified` must be boolean `true` |
| `user_metadata.is_staff` | Boolean `false` for non-staff; staff exchange is refused |
| `scope` | Space-separated service ids (`identity`, `storage`, …) |
| `mcp_access`, `mcp_read`, `mcp_destructive` | Same semantics as regional agent JWTs |
| `jti`, `iat`, `exp` | Short lifetime (match global MCP access TTL) |

Optional: `agent_name` for the regional agent display name.

## Access levels

| Mode | Value | Behavior |
| --- | --- | --- |
| Read only | `read_only` | Safe HTTP methods and tools tagged `x-mcp.read_only` |
| Ask before changes | `ask` (default) | Writes create a pending approval |
| Full access | `full` | Writes run immediately unless the tool is marked destructive |

**Destructive without asking:** separate flag (`allow_destructive_without_asking`, default off). When off, destructive tools still require approval even in full access mode.

## Read levels

| Level | Value | Behavior |
| --- | --- | --- |
| Safe | `safe` (default) | Masks personal data in tool results |
| Sensitive | `sensitive` | Returns more fields; still never returns stored secrets |

## Approvals

When a write needs human confirmation, the service creates an approval through Identity:

- `POST /api/v1/mcp/internal/mcp-approval-requests` with a short-lived assertion (audience `shellui-mcp-approval`, scope `mcp.approval.create`), same pattern as [company deletion](company-deletion.md). The assertion JWT carries `agent_id`, `company_id`, `service`, `action`, and `arguments_hash`. ai-service may add `setup_flow` and `mcp_session_ttl_seconds` (600 to 900) on signed assertions during new-company setup so Identity can grant a longer client session Allow; other callers cannot rely on those claims for a longer grant. The JSON body carries tool `arguments` (Identity stores `arguments_redacted` with the same `shellui_django.mcp` masking) and optional `target`, or `method` plus `path` to derive `target`.
- `POST /api/v1/mcp/internal/mcp-approval-state` with the same approval assertion (no GET). Identity looks up the latest row matching all assertion fields and returns `pending`, `approved`, `denied`, or `expired`. `404` when no row exists. Approved responses include `id` (approval uuid) for consume.
- `POST /api/v1/mcp/internal/mcp-approval-consume` with the same approval assertion. JSON body: `{ "approval_id": "<uuid>" }`. Identity loads the row with `id`, `company_id`, `agent_id`, `service`, and `arguments_hash` from the assertion; any mismatch returns `404`. Consumption is atomic (`select_for_update`) and single use; `{ "consumed": true }` only while the row is approved and younger than 10 minutes.
- One pending row per agent and arguments hash, **expires after 10 minutes**, runs once, never standing.

Storage, hosting, and email must use this contract exactly (assertion fields on state and consume, `approval_id` in the consume body).

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

Company owners and the member who created the agent approve or deny in Settings or via human user tokens:

- `GET /api/v1/mcp/approvals` (returns `approvals` and `pending_count`, the number of rows in `approvals`; pending rows include `service`, `action`, `tool_name`, `target`, `is_destructive`, `short_action_summary`, and `arguments_redacted`; secrets stay masked)
- `GET /api/v1/mcp/approvals/{id}`
- `POST /api/v1/mcp/approvals/{id}/decide` with `{ "decision": "approve" | "deny" }`
- `POST /api/v1/mcp/approvals/{id}/approve` and `POST /api/v1/mcp/approvals/{id}/reject` (same behavior as decide)

The MCP client card (ai-service) calls `POST /api/v1/mcp/internal/mcp-approval-decide` with `allow`, `deny`, or `allow_session` (non-destructive only). Session allow lasts **60 seconds** per MCP connection by default (`MCP_APPROVAL_SESSION_TTL_SECONDS`, clamped 30 to 60). During new-company setup only, when the decision assertion is signed by **ai-service** and carries `setup_flow` with `mcp_session_ttl_seconds` between **600** and **900** (and not longer than the assertion JWT lifetime), Identity stores that TTL for this connection. Destructive actions never use session allow. Check with `POST /api/v1/mcp/internal/mcp-approval-session-check`; revoke on disconnect with `POST /api/v1/mcp/internal/mcp-approval-session-revoke`. Request bodies cannot set the TTL; only signed gateway claims count.

Fallback browser page: `GET /oauth/mcp/approval/{id}?token=…` (signed token from `fallback_path` on create). Approve and Deny only.

Audit event `identity.mcp.approval_decision` uses status `approved`, `denied`, `expired`, `client_allowed`, `client_denied`, or `client_session_allowed` with `{actor_email} {status} {tool_name} for {agent_name}`.

## Revocation

Pause or revoke agents with:

- `POST /api/v1/mcp/agents/{id}/pause`
- `POST /api/v1/mcp/agents/{id}/revoke`

Services poll `GET /api/v1/mcp/internal/mcp-revocations` with a signed assertion (audience `shellui-mcp-revocation`, scope `mcp.revocation.read`, cache **30 seconds** on the consumer) so revocation is effective almost immediately. Optional `?company_id=` filters the list to one tenant. Identity signs each response (`revocation_assertion`, scope `mcp.revocation.list`, short `exp`) including `revoked_agent_ids`, `agents` (`agent_id`, `company_id`, `is_active`, `paused`), and `cache_seconds`. Services must verify with `shellui_django.mcp.internal.parse_trusted_revocation_poll_response` (RS256 against Identity `/.well-known/jwks.json`, no SimpleJWT settings) and cross-check `company_id` against the agent token before treating an agent as blocked. `McpServer` passes `(agent_id, company_id)` to `identity_revocation_check`.

## Call logs

Services forward redacted MCP call rows to `POST /api/v1/mcp/internal/mcp-call-logs` (assertion audience `shellui-mcp-call-log`). Identity stores them and emits `identity.mcp.call` security events. Arguments are redacted; tokens and secrets are never stored.

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
- SaaS: `SAAS_SERVICE_URL` + `/mcp`
- AI: `AI_SERVICE_URL` + `/mcp`

Downstream minting uses only these configured origins (never a URL from the client).

## Agent JWT claims

Access tokens include:

| Claim | Meaning |
| --- | --- |
| `aud` | RFC 8707 resource URL for one service (`{origin}/mcp`) |
| `sub` | `agent:{uuid}` |
| `agent_id` | Agent uuid |
| `company_id` | Company id |
| `scope` | Space-separated service ids |
| `mcp_access` | `read_only`, `ask`, or `full` |
| `mcp_read` | `safe` or `sensitive` |
| `mcp_destructive` | Allow destructive without asking |

Refresh tokens use `grant_type=refresh_token` at `/oauth/mcp/token` with the same `resource` parameter. Each refresh token is bound to one resource.

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
