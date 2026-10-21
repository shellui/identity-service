---
description: How identity-service runs OAuth sign-in for a Shellui shell, from the authorize request to the token exchange, and how to configure the redirect allowlist.
---

# OAuth login

identity-service owns the whole OAuth flow. Provider apps call back to one fixed URL on identity-service, which exchanges the code server-side, applies the company rules, and returns tokens to the shell. This page covers that flow, the confirmation page, token delivery, and the redirect allowlist. For passwordless email sign-in, see [Magic link](magic-link.md). A company can enable both. A desktop app returns through a custom-scheme link instead of an http(s) shell. See [Desktop apps](desktop-apps.md). Web and desktop session codes both use S256 PKCE.

## How the flow works

The shell (or `shellui login` in the CLI) only talks to identity-service. The shell destination, `redirect_to`, travels in a signed OAuth `state` value, never in the provider callback URL:

1. The shell opens `GET /api/v1/authorize` with `company_id`, `redirect_to`, `code_challenge`, `code_challenge_method=S256`, and optionally `provider`.
2. Without `provider`, identity-service shows a sign-in method picker, even when the company has a single method.
3. identity-service redirects to the provider with `redirect_uri` set to its own `/api/v1/oauth/callback` and a signed `state`.
4. The provider returns to `/api/v1/oauth/callback`. identity-service exchanges the code server-side.
5. identity-service shows an account confirmation page. The user can continue, switch provider, or switch account. Some providers skip this step, see [Skip the confirmation page](#skip-the-confirmation-page).
6. identity-service redirects to `redirect_to?shellui_auth_code=…`. The shell `/login/callback` route posts the code to `POST /api/v1/oauth/session` with the same `redirect_to` and the S256 `code_verifier`. An http(s) callback must send an `Origin` header that matches that redirect.

Company join rules (`public`, `domain`, `invite`) apply after the provider sign-in succeeds. See [Company access](company-access.md).

## Register the callback URL

Register one callback URL on each provider app, pointing at identity-service, with no query string:

| Environment | Callback URL |
| --- | --- |
| Local | `http://localhost:8000/api/v1/oauth/callback` |
| Production | `https://auth.example.com/api/v1/oauth/callback` |

The provider homepage or application URL can still be your shell, for example `https://app.example.com`. Do not register the shell `/login/callback` URL at the provider: only identity-service redirects there. Supported providers and their settings are listed in [OAuth providers](oauth-providers.md).

## Skip the confirmation page

After the callback, identity-service shows a confirmation page so the user can check which account they used. Google skips it by default, because Google already shows its own consent screen and account picker. `OAUTH_SKIP_CONFIRM_PROVIDERS` controls the list:

| Value | Behavior |
| --- | --- |
| Unset | `google` skips the confirmation page |
| `google,microsoft` | Each listed provider skips it. Use catalog IDs from [OAuth providers](oauth-providers.md) |
| Empty (`OAUTH_SKIP_CONFIRM_PROVIDERS=`) | Every provider shows it |

An unknown ID in the list is ignored. When the profile is not good enough to finish on its own, identity-service shows the confirmation page anyway. That happens when the email is missing, is a `{id}@{provider}.local` placeholder, or comes with `email_verified: false`.

## Token delivery

By default, identity-service sends the shell a one-time code, not the tokens. The code is valid for `OAUTH_SESSION_CODE_TTL_SECONDS` (120 seconds by default) and works once:

| Mode | How the shell receives tokens | Status |
| --- | --- | --- |
| `code` (default) | `redirect_to?shellui_auth_code=…`, then `POST /api/v1/oauth/session` | Recommended |
| `fragment` | `redirect_to#access_token=…&refresh_token=…` | Deprecated, will be removed |

Choose the mode per request with `token_delivery=fragment` on `/api/v1/authorize`, or for the whole deployment with `OAUTH_TOKEN_DELIVERY`. `POST /api/v1/oauth/exchange` still serves older shells that receive the provider `?code=` themselves.

A custom-scheme redirect always uses the one-time code, even when fragment delivery is selected. See [Desktop apps](desktop-apps.md).

## PKCE for every session code

S256 PKCE is required for web redirects and for custom-scheme redirects. identity-service stores the challenge on the one-time code. It does not store the verifier. A copied `shellui_auth_code` cannot be redeemed without the verifier the shell kept.

Send the challenge when sign-in starts:

| Start | Parameters |
| --- | --- |
| `GET /api/v1/authorize` | query `code_challenge`, `code_challenge_method=S256` |
| `POST /api/v1/magic-link/request` | the same two fields in the JSON body |
| `GET /api/v1/saml/<organization_slug>/login/` | the same query parameters |

The method picker and the SAML handoff keep those parameters on the next URL. `plain` is refused. The challenge is 43 to 128 base64url characters (RFC 7636). The verifier is 43 to 128 unreserved characters. `code_challenge` is `BASE64URL(SHA256(verifier))` with the `=` padding removed.

Exchange:

```json
{
  "auth_code": "<shellui_auth_code>",
  "redirect_to": "<the callback URL with shellui_auth_code removed>",
  "code_verifier": "<verifier>"
}
```

`redirect_to` is the same URL sent at the start, including other query parameters, without `shellui_auth_code`. For an http(s) redirect the browser `Origin` header is required and must equal the origin of `redirect_to` (scheme, host, and port, no path). A missing `Origin` is `400` with `{"error":"Origin is required for this redirect."}`. A different origin is `400` with `{"error":"Origin does not match redirect_to."}`. Those two responses have no `error_code`. PKCE failures are `400` with `error` and `error_code` (`pkce_required`, `invalid_code_challenge`, `invalid_code_challenge_method`, `invalid_code_verifier`, `pkce_verification_failed`). A failed check does not use up the code.

A custom-scheme redirect still skips the Origin check, and only after the verifier matches. See [Desktop apps](desktop-apps.md#origin-check).

`token_delivery=fragment` still puts the tokens in the URL fragment and does not use this code. That mode is deprecated.

`POST /api/v1/oauth/exchange` and `POST /api/v1/providers/<provider>/login/` are the older JSON endpoints. They require S256 PKCE only for a custom-scheme `redirect_uri`. New shells use `/api/v1/authorize` and `/api/v1/oauth/session`.

### What @shellui/core sends today

On `develop` of [shellui/shellui](https://github.com/shellui/shellui), web sign-in does not send PKCE yet. Desktop sign-in does.

- `startOAuth` in `packages/core/src/features/auth/backends/shellui.ts` opens `GET /api/v1/authorize` with `provider`, `redirect_to`, `company_id`, and the optional client id, timezone, and device id. It does not set `code_challenge`.
- `redirect_to` is `window.location.origin` plus the callback path, with query `provider` and, when set, `company_oauth_client_id`.
- `OAuthCallbackView` calls `exchangeOAuthSessionCode` with `auth_code` and `redirect_to` only. `redirect_to` comes from `buildOAuthSessionRedirectTo`, which drops `shellui_auth_code` and keeps the other query.
- `exchangeOAuthSessionCode` posts JSON to `/api/v1/oauth/session` and adds `code_verifier` only when the caller passes one. The web callback does not.
- `sendMagicLink` adds `code_challenge` and `code_challenge_method` only when `options.codeChallenge` is set, which is the desktop path.
- The `fetch` is a cross-origin POST with `Accept` and `Content-Type` set to JSON. It does not set `credentials`. The browser adds `Origin` from the page. The client does not set `Origin` itself.

The shell and admin change that matches this service:

1. Create a verifier and its S256 challenge before navigation. Keep the verifier in `sessionStorage` for the tab. Do not put it on the authorize URL, in the email, or in the callback query.
2. `startOAuth` sets `code_challenge` and `code_challenge_method=S256`.
3. `sendMagicLink` sends those two fields for an http(s) `redirect_to` as well as a custom scheme.
4. The callback reads the verifier and posts `{auth_code, redirect_to, code_verifier}` from that page, so `Origin` is the page origin.
5. `shellui login` in `packages/cli/src/auth/login-flow.js` posts `{auth_code, redirect_to}` from the loopback page and does not send a verifier. The CLI must add the challenge to the authorize URL and `code_verifier` to that fetch. The waiting page must not print the verifier. The loopback `Origin` (`http://127.0.0.1:<port>`) already matches `redirect_to`.

Admin uses the same contract when it starts sign-in itself. When it goes through `@shellui/core`, the core change covers it. Desktop and Tauri already send the challenge and the verifier. A custom scheme still does not need a matching `Origin`.

## Redirect allowlist

identity-service only sends codes or tokens to origins the company approved. This stops a crafted `redirect_to` from sending a session to another site:

| Target | Rule |
| --- | --- |
| Loopback (`127.0.0.1`, `localhost`, `::1`) | Allowed when `DEBUG=true` or `OAUTH_ALLOW_LOOPBACK_REDIRECTS=true`, for the CLI and local shells |
| Other http(s) origins | Must match an active `CompanyOAuthRedirect` row for the company |
| Desktop app URI | Scheme must be in the company `desktop_redirect_schemes` list. An empty list turns desktop sign-in off. With `DEBUG=true`, or with `allow_desktop_dev_scheme`, a listed scheme also allows its `-dev` variant. See [Desktop apps](desktop-apps.md) |
| Hosting previews (`{slug}.{HOSTING_APP_DOMAIN}`) | Added and removed by hosting-service (`source=hosting`) when a site is created or deleted |
| Empty allowlist | Every non-loopback http(s) `redirect_to` is denied. A custom-scheme `redirect_to` is denied unless that scheme is in `desktop_redirect_schemes` |

Store web origins as scheme, host, and optional port, for example `http://localhost:4000` or `https://app.example.com`. A path or query on a web allowlist entry is ignored. A desktop redirect is not an allowlist row: add the scheme to the company, then send `shellui-playground://callback`.

### Manage the allowlist

Staff and company owners can edit the allowlist in three places:

- **Shellui admin**: **OAuth setup**, with manual origins and a separate list of hosting previews
- **Django admin**: **Company OAuth redirects**
- **REST API**: `GET`, `POST`, `PATCH`, and `DELETE` on `/api/v1/oauth-redirects?company_id=…`

This request adds a production shell origin for company `1`:

```bash
curl -s -X POST "https://auth.example.com/api/v1/oauth-redirects?company_id=1" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"base_url":"https://app.example.com","label":"Production shell"}'
```

hosting-service keeps preview origins in sync with `PUT` and `DELETE` on `/api/v1/hosting-oauth-redirects`, using the deployer's identity JWT (staff or company owner). The company comes from the token.

### CORS is a separate control

CORS decides which browser origins may call the API. The redirect allowlist decides where sessions go after sign-in. Only the allowlist needs to be strict:

| Concern | Mechanism | Strict |
| --- | --- | --- |
| Token delivery after OAuth | `CompanyOAuthRedirect` allowlist and one-time code exchange | Yes. Keep the list short and prefer `code` delivery |
| Browser API calls with a Bearer JWT | `CORS_ALLOW_ALL_ORIGINS=true` by default, with `CORS_ALLOW_CREDENTIALS=false` | No. JWT verification and company scoping protect the API |

Do not add hosting preview origins to `CORS_ALLOWED_ORIGINS`. Set `CORS_ALLOW_ALL_ORIGINS=false` only on installs that restrict API origins on purpose, see [Security hardening](security-hardening.md#cors-browser-api-calls).

## Account linking and login CSRF

identity-service first matches a sign-in to an existing user by provider account ID. When there is no match, it links by email only when the provider proves the user owns that email, for example a verified primary email on GitHub or `email_verified` in a Google ID token. Otherwise it returns an error rather than attach the sign-in to another user's account. The rule for each provider is in [How email linking works](oauth-providers.md#how-email-linking-works).

To block login CSRF, `/api/v1/authorize` stores a random nonce in the `shellui_oauth_state_nonce` cookie (HttpOnly, SameSite=Lax). The callback checks that nonce against the signed `state`, and rejects a `state` that was already used.

## Endpoints

| Endpoint | Role |
| --- | --- |
| `GET /api/v1/authorize` | Start sign-in, with an optional method picker |
| `GET /api/v1/oauth/callback` | Provider callback and confirmation page |
| `POST /api/v1/oauth/confirm` | Finish sign-in after confirmation |
| `GET /api/v1/oauth/confirm?action=switch&confirm_token=…` | Restart OAuth with the account picker (Google, Microsoft) |
| `POST /api/v1/oauth/session` | Exchange `shellui_auth_code` for tokens |
| `POST /api/v1/oauth/exchange` | Deprecated code exchange for older shells |
| `GET`, `POST`, `PATCH`, `DELETE` `/api/v1/oauth-redirects` | Manage the redirect allowlist |
| `PUT`, `DELETE` `/api/v1/hosting-oauth-redirects` | hosting-service sync (`source=hosting`) |
| `GET /api/v1/oauth-provider-catalog` | Provider catalog for Shellui admin |
| `GET`, `POST` `/api/v1/oauth-social-apps` | Company provider apps (client ID, secret, settings) |

## Related

- [Desktop apps](desktop-apps.md): custom-scheme return and PKCE
- [OAuth providers](oauth-providers.md): supported providers and their settings
- [Account deletion](account-deletion.md): `DELETE /api/v1/user`
- [Upgrade notes](upgrading.md): moving from fragment delivery or shell-hosted callbacks
- [Security hardening](security-hardening.md): rate limits and HTTPS defaults
