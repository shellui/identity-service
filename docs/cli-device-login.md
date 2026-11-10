---
description: Sign in the Shellui CLI with the OAuth 2.0 device authorization grant and receive a normal app session.
---

# CLI device login

Use this when `shellui login` runs in a terminal. The CLI shows a link and a user code. The person approves in a browser. The CLI polls until Identity returns an app session. The tokens are the same kind `POST /api/v1/oauth/session` returns, so existing CLI commands keep working. Refresh them at `POST /api/v1/token?grant_type=refresh_token`.

The grant is [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628). It is a separate client from [MCP device login](mcp-device-flow.md). A CLI device code never becomes an MCP token, and an MCP device code never becomes a CLI session. Authorization server metadata keeps `device_authorization_endpoint` on the MCP path. This page is the CLI advertisement.

The public identity origin below is `JWT_ISSUER`.

## Walkthrough

```bash
export IDENTITY=https://identity.example.com
export COMPANY_ID=42
```

Ask for a device code. Send form data. JSON is also accepted. `client_id` must be `shellui-cli`. `company_id` is required.

```bash
curl -sS -X POST "$IDENTITY/oauth/cli/device/code" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'client_id=shellui-cli' \
  --data-urlencode "company_id=${COMPANY_ID}"
```

A 200 response looks like this:

```json
{
  "device_code": "opaque-secret-for-the-cli",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://identity.example.com/oauth/cli/device",
  "verification_uri_complete": "https://identity.example.com/oauth/cli/device?user_code=WDJB-MJHT",
  "expires_in": 600,
  "interval": 5
}
```

`user_code` is eight characters, `XXXX-XXXX`, from an alphabet without `0`, `O`, `1`, or `I`. `expires_in` is 600 seconds. `interval` is 5 seconds.

Show `user_code` and open `verification_uri_complete` (or send the person to `verification_uri` and let them type the code). The page is for that company and offers only that company's sign-in methods: magic link when the company has it on, and the company's SSO home realm, plus a password form. Staff accounts (`is_staff` or `is_superuser`) can approve. They use a password or SSO. An email link is not sent to a staff account. MCP device login still refuses staff.

The approval page is titled "Sign in the Shellui CLI on another device". It shows the company name, the request time, the IP and user agent captured when the CLI asked for the code, and the code to check. The person chooses Allow or Deny. Code entry and password attempts are limited to `AUTH_RATE_LIMIT_CLI_DEVICE_VERIFY` per 5 minutes per IP (default 8). Device code requests are limited to `AUTH_RATE_LIMIT_CLI_DEVICE_CODE` per 5 minutes per IP (default 30).

Poll `POST /oauth/token` every `interval` seconds. Do not send an MCP `resource`.

```bash
curl -sS -X POST "$IDENTITY/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  --data-urlencode "device_code=${DEVICE_CODE}" \
  --data-urlencode 'client_id=shellui-cli'
```

| HTTP | `error` | What the CLI does |
| --- | --- | --- |
| 400 | `authorization_pending` | Wait `interval` seconds and poll again |
| 400 | `slow_down` | Add 5 seconds to the wait, then poll again |
| 400 | `access_denied` | Stop. The person denied the request |
| 400 | `expired_token` | Stop. Start again from the device authorization request |
| 400 | `invalid_grant` | Stop. The code is unknown, belongs to another client, was already used, or is an MCP device code |
| 401 | `invalid_client` | Stop. `client_id` is not `shellui-cli` |
| 200 | | Store `access_token` and `refresh_token`. Do not poll this device code again |

Error bodies include `error` and `error_description`. Branch on `error`.

A successful body matches `POST /api/v1/oauth/session`:

```json
{
  "access_token": "<access-token>",
  "refresh_token": "<refresh-token>",
  "token_type": "bearer",
  "expires_in": 300,
  "expires_at": 1730000000
}
```

`token_type` is lowercase `bearer`. `expires_in` is the access-token lifetime (`JWT_ACCESS_TOKEN_LIFETIME`, default 5 minutes). `aud` is `JWT_AUDIENCE`. Claims include `company_id`, `email`, `user_metadata`, `app_metadata`, `auth_time`, and `sid`. There is no `agent_id`. Refresh with `POST /api/v1/token?grant_type=refresh_token` and the refresh token. Non-staff refresh tokens use `JWT_REFRESH_TOKEN_LIFETIME` (default 7 days). Staff refresh tokens are capped by `CLI_STAFF_SESSION_MAX_AGE` (default `12h`). A later refresh keeps that same absolute cap. It does not start another 12 hours.

The device code is single-use. A second poll after 200 returns `invalid_grant`.

## What is stored

Identity stores SHA-256 hashes of `device_code` and `user_code`, not the raw values. The approval page can show the requesting IP and user agent until the grant is finished. The login audit event `identity.auth.login.succeeded` for that approval has `provider` `cli`, `device_kind` `cli`, `user_agent`, and `ip_hash` (a salted hash of the CLI IP, never the raw address). See [Event log](event-log.md).

The issued refresh token is an ordinary app session. `GET /api/v1/sessions` lists it for that user and company:

```json
{
  "sessions": [
    {
      "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "kind": "cli",
      "user_agent": "ShelluiCLI/1.0",
      "created_at": "2026-11-09T21:08:00+00:00",
      "expires_at": "2026-11-16T21:08:00+00:00",
      "current": true
    }
  ]
}
```

`kind` is `cli` for this grant and empty for other app sessions. `POST /api/v1/sessions/{id}/revoke` revokes that refresh session. A later refresh then fails. Personal access tokens and MCP agents are not in this list. MCP agents stay on `GET /api/v1/mcp/personal/agents`.

## OpenAPI

`POST /oauth/cli/device/code` is operation `oauth_cli_device_authorization` on `/api/schema/` and `/api/docs/`. The verification page is HTML, not a JSON operation. The token poll is `POST /oauth/token`. Session list and revoke are `api_v1_sessions_list` and `api_v1_sessions_revoke`.
