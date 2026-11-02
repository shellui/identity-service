---
description: Connect MCP clients to Shellui with OAuth, agent access levels, approvals, revocation, and call logs.
---

# MCP and agents

Shellui Identity is the OAuth authorization server for MCP clients. Each connected client receives a company-scoped **agent** with explicit access rules. Storage, hosting, email, and other services reuse the same MCP layer from the [shellui-django](https://github.com/shellui/django-commons) package (`shellui_django.mcp`) for their `/mcp` endpoint.

## Connect a client (one URL and sign-in)

1. Point the MCP client at your identity origin (for example `https://auth.example.com`).
2. The client loads OAuth authorization server metadata at `/.well-known/oauth-authorization-server` and protected resource metadata at `/.well-known/oauth-protected-resource` (resource `/mcp`).
3. The client registers with **dynamic client registration** (`POST /oauth/mcp/register`) unless an operator disabled it (`MCP_DYNAMIC_CLIENT_REGISTRATION=false` or `Company.mcp_allow_dynamic_registration=false`).
4. The user signs in and approves company, services, access level, and read level on the consent screen (`GET/POST /oauth/mcp/authorize` with PKCE S256 and RFC 8707 `resource=<service>/mcp`).
5. The client exchanges the authorization code at `POST /oauth/mcp/token` with the same `resource`, then calls `POST /mcp` on that service with `Authorization: Bearer <access_token>`. Repeat for each service using a separate token per resource.

Staff accounts (`is_staff`, `is_superuser`, and global staff) cannot authorize MCP agents.

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

- `POST /api/v1/mcp/internal/mcp-approval-requests` with a short-lived assertion (audience `shellui-mcp-approval`, scope `mcp.approval.create`), same pattern as [company deletion](company-deletion.md). The assertion JWT carries `agent_id`, `company_id`, `service`, `action`, and `arguments_hash`. The JSON body carries tool `arguments` (Identity stores `arguments_redacted` with the same `shellui_django.mcp` masking) and optional `target`, or `method` plus `path` to derive `target`.
- `POST /api/v1/mcp/internal/mcp-approval-state` with the same approval assertion (no GET). Identity looks up the latest row matching all assertion fields and returns `pending`, `approved`, `denied`, or `expired`. `404` when no row exists. Approved responses include `id` (approval uuid) for consume.
- `POST /api/v1/mcp/internal/mcp-approval-consume` with the same approval assertion. JSON body: `{ "approval_id": "<uuid>" }`. Identity loads the row with `id`, `company_id`, `agent_id`, `service`, and `arguments_hash` from the assertion; any mismatch returns `404`. Consumption is atomic (`select_for_update`) and single use; `{ "consumed": true }` only while the row is approved and younger than 10 minutes.
- One pending row per agent and arguments hash, **expires after 10 minutes**, runs once, never standing.

Storage, hosting, and email must use this contract exactly (assertion fields on state and consume, `approval_id` in the consume body).

Company owners approve or reject in Shellui admin or via human user tokens only:

- `GET /api/v1/mcp/approvals` (pending rows include `service`, `action`, `target`, and `arguments_redacted`; secrets stay masked)
- `GET /api/v1/mcp/approvals/{id}`
- `POST /api/v1/mcp/approvals/{id}/approve`
- `POST /api/v1/mcp/approvals/{id}/reject`

## Revocation

Pause or revoke agents with:

- `POST /api/v1/mcp/agents/{id}/pause`
- `POST /api/v1/mcp/agents/{id}/revoke`

Services poll `GET /api/v1/mcp/internal/mcp-revocations` with a signed assertion (audience `shellui-mcp-revocation`, scope `mcp.revocation.read`, cache **30 seconds** on the consumer) so revocation is effective almost immediately. Optional `?company_id=` filters the list to one tenant. Identity signs each response (`revocation_assertion`, scope `mcp.revocation.list`, short `exp`) including `revoked_agent_ids`, `agents` (`agent_id`, `company_id`, `is_active`, `paused`), and `cache_seconds`. Services must verify with `shellui_django.mcp.internal.parse_trusted_revocation_poll_response` (RS256 against Identity `/.well-known/jwks.json`, no SimpleJWT settings) and cross-check `company_id` against the agent token before treating an agent as blocked. `McpServer` passes `(agent_id, company_id)` to `identity_revocation_check`.

## Call logs

Services forward redacted MCP call rows to `POST /api/v1/mcp/internal/mcp-call-logs` (assertion audience `shellui-mcp-call-log`). Identity stores them and emits `identity.mcp.call` security events. Arguments are redacted; tokens and secrets are never stored.

Owners read logs with `GET /api/v1/mcp/call-logs`.

## list_services

On Identity `/mcp`, the `list_services` tool returns MCP URLs discovered from existing settings:

- Identity: `JWT_ISSUER` + `/mcp`
- Storage: `STORAGE_SERVICE_URL` + `/mcp`
- Hosting: `HOSTING_SERVICE_URL` + `/mcp`
- Email: `EMAIL_SERVICE_URL` + `/mcp` when `EMAIL_SERVICE_API_KEY` is set

No new required environment variables.

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

Add the PyPI package `shellui-django[mcp]` (source: [django-commons](https://github.com/shellui/django-commons)) to storage, hosting, email, and saas. Wire:

- `POST /mcp` using `shellui_django.mcp.server.McpServer`
- OpenAPI tools from operations tagged `mcp-tools` only (`@mcp_expose_tool`)
- Protected resource metadata pointing at Identity
- Revocation checks against Identity
- Per-agent rate limits and call log forwarding

See module docstrings in `shellui_django.mcp.internal` for assertion audiences and scopes.
