---
description: Connect a headless MCP agent with the OAuth 2.0 device authorization grant, without pasting a token.
---

# MCP device login

Use this when the agent has no browser of its own (a CLI, or an assistant running in a terminal). The person approves in their own browser. The agent polls until Identity returns tokens. Nothing here pushes a notification, and no token is pasted into the chat.

The grant is [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628). Company rules, consent, claims, and revocation are the same as the browser flow in [MCP and agents](mcp-and-agents.md).

## Discover

1. The agent calls the company MCP URL, for example `https://ai.example.com/c/42/mcp`.
2. ai-service answers 401 with `WWW-Authenticate` and a `resource_metadata` URL.
3. That protected-resource document lists `authorization_servers` set to the identity issuer.
4. The agent reads `GET https://identity.example.com/.well-known/oauth-authorization-server` and uses:
   - `registration_endpoint` (`POST /oauth/mcp/register`)
   - `device_authorization_endpoint` (`POST /oauth/mcp/device/code`)
   - `token_endpoint` (`POST /oauth/token`)
   - `grant_types_supported`, which includes `urn:ietf:params:oauth:grant-type:device_code`

`POST /oauth/mcp/token` is the same token handler for clients that still use the old path.

## Walkthrough

Set the identity origin and the company MCP URL. `42` is the company id.

```bash
export IDENTITY=https://identity.example.com
export MCP_URL=https://ai.example.com/c/42/mcp
```

Register a public client once. A loopback redirect URI satisfies registration. Device login does not redirect there.

```bash
curl -sS -X POST "$IDENTITY/oauth/mcp/register" \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"Hermes","redirect_uris":["http://127.0.0.1/callback"]}'
```

Keep `client_id` from the response.

```bash
export CLIENT_ID=paste-the-client-id
```

Ask for a device code. Send form data. JSON is also accepted. `resource` must be the company MCP URL.

```bash
curl -sS -X POST "$IDENTITY/oauth/mcp/device/code" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "resource=${MCP_URL}"
```

A 200 response looks like this:

```json
{
  "device_code": "opaque-secret-for-the-agent",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://identity.example.com/oauth/mcp/device",
  "verification_uri_complete": "https://identity.example.com/oauth/mcp/device?user_code=WDJB-MJHT",
  "expires_in": 600,
  "interval": 5
}
```

Show `user_code` to the person and open `verification_uri_complete` (or send them to `verification_uri` and let them type the code). `user_code` is eight characters, `XXXX-XXXX`, from an alphabet without `0`, `O`, `1`, or `I`.

They sign in with that company's methods, see the client name, the company, and the access being requested, then choose **Allow** or **Deny**. Staff accounts are refused.

Poll the token endpoint every `interval` seconds. Send the same `resource`.

```bash
curl -sS -X POST "$IDENTITY/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "device_code=${DEVICE_CODE}" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "resource=${MCP_URL}"
```

| HTTP | `error` | What the agent does |
| --- | --- | --- |
| 400 | `authorization_pending` | Wait `interval` seconds and poll again |
| 400 | `slow_down` | Add 5 seconds to the wait, then poll again |
| 400 | `access_denied` | Stop. The person denied the request |
| 400 | `expired_token` | Stop. Start again from the device authorization request |
| 400 | `invalid_grant` | Stop. The code is unknown, belongs to another client, or was already used |
| 400 | `invalid_target` | Stop. `resource` is missing or is not the company URL from the device request |
| 200 | | Store `access_token` and `refresh_token`. Do not poll this device code again |

A successful body matches the authorization-code grant:

```json
{
  "access_token": "<access-token>",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<refresh-token>"
}
```

Refresh later with `grant_type=refresh_token`, the refresh token, and the same `resource`. The access token `aud` is `MCP_URL`. Claims include `agent_id`, `company_id`, `mcp_access`, `mcp_read`, `mcp_destructive`, `scope`, and `grant_version`.

The device code is single-use. A second poll after 200 returns `invalid_grant`.

## What is stored

Identity stores SHA-256 hashes of `device_code` and `user_code`, not the raw values. Logs record `company_id` and `client_id` only. The approval row in the agent call log (`oauth.device.approved`) has the client, resource, and chosen access. It has no code and no token. Query strings are not written to access logs, so `user_code` on `verification_uri_complete` stays out of those lines.

The agent row uses the same list and revoke APIs as other OAuth connections: `GET /api/v1/mcp/personal/agents` and `POST /api/v1/mcp/personal/agents/{id}/revoke`. `expires_at` is at most `MCP_PERSONAL_AGENT_MAX_LIFETIME_DAYS` (default 90). Access tokens stay on `MCP_ACCESS_TOKEN_LIFETIME` (default 15 minutes).

## OpenAPI

`POST /oauth/mcp/device/code` is operation `oauth_mcp_device_authorization` on `/api/schema/` and `/api/docs/`. The verification page is HTML, not a JSON operation. The token poll is the existing `POST /oauth/token` handler. Its device grant is described on the device operation and in the authorization server metadata.
