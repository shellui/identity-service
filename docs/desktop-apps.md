---
description: Sign a desktop app in through the system browser and return with a custom-scheme deep link and PKCE.
---

# Desktop apps

A desktop app signs people in through the system browser, then returns to the app with a custom-scheme deep link such as `shellui-playground://callback?shellui_auth_code=…`. The Shellui playground is the first app that uses this. Web shells keep the http(s) flow in [OAuth login](oauth-login.md). That flow is unchanged: an http(s) `redirect_to` is still an origin on the allowlist, and PKCE stays optional there.

## Allow the deep link

Add one exact URI to the company redirect allowlist with `kind` set to `desktop`. The match is exact. A different path, host, or query is refused. There is no prefix match.

The scheme must look like an app id: a hyphenated name such as `shellui-playground`, or a reverse-DNS name such as `com.shellui.app`. These schemes are refused: `http`, `https`, `javascript`, `data`, `file`, `vbscript`, `about`, `blob`, `ftp`, and other browser or network schemes. The URI cannot contain userinfo (`user:pass@host`) or a fragment (`#…`).

Staff and company owners add the row in the same places as a web origin:

- **Shellui admin**: OAuth setup, once that screen sends `kind`
- **Django admin**: Company OAuth redirects, kind **Desktop app**
- **REST API**: `POST /api/v1/oauth-redirects?company_id=…`

```bash
curl -s -X POST "https://auth.example.com/api/v1/oauth-redirects?company_id=1" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"base_url":"shellui-playground://callback","kind":"desktop","label":"Playground"}'
```

A `kind=web` row is still an http(s) origin prefix, for example `https://app.example.com`. Hosting preview sync only writes web rows.

## PKCE

Every custom-scheme redirect requires [PKCE](https://www.rfc-editor.org/rfc/rfc7636) with `code_challenge_method=S256`. `plain` is refused. The app keeps the verifier. identity-service stores the challenge only, on the one-time session code or the magic-link token. The verifier is not stored, logged, or sent on a webhook.

Send the challenge when sign-in starts:

| Start | Parameters |
| --- | --- |
| `GET /api/v1/authorize` | `code_challenge`, `code_challenge_method=S256` |
| `POST /api/v1/magic-link/request` | same fields in the JSON body |
| `GET /api/v1/saml/<organization_slug>/login/` | same query parameters |
| `GET /api/v1/providers/<provider>/authorize/` | same query parameters |

The method picker and the SAML handoff from `/api/v1/authorize` keep those parameters on the next URL.

Exchange the one-time code with the verifier:

```json
{
  "auth_code": "…",
  "redirect_to": "shellui-playground://callback",
  "code_verifier": "…"
}
```

`POST /api/v1/oauth/session` returns **400** with `error` and `error_code` when PKCE fails. A failed check does not use up the code, so the app can retry with the verifier. A wrong verifier is not a guessable secret: the verifier is 43 to 128 characters.

| `error_code` | When |
| --- | --- |
| `pkce_required` | Custom-scheme redirect with no S256 challenge at the start, or no verifier at the exchange |
| `invalid_code_challenge_method` | Method is missing or is not exactly `S256` |
| `invalid_code_challenge` | Challenge is not 43 to 128 base64url characters |
| `invalid_code_verifier` | Verifier is not 43 to 128 unreserved characters |
| `pkce_verification_failed` | Verifier does not match the stored challenge |

An http(s) redirect does not require PKCE. If the client sent a challenge, the exchange must send a matching verifier. Older session errors stay `{ "error": "…" }` with no `error_code`.

Custom-scheme redirects always use the one-time code. `token_delivery=fragment` and `OAUTH_TOKEN_DELIVERY=fragment` do not put tokens in the deep link. If a custom-scheme redirect reaches the end of sign-in without a challenge, the deep link carries `shellui_oauth_error` and `shellui_oauth_error_code=pkce_required` instead of a code.

`POST /api/v1/oauth/exchange` and `POST /api/v1/providers/<provider>/login/` are the older JSON token endpoints. For a custom-scheme `redirect_uri` they require `code_challenge`, `code_challenge_method=S256`, and `code_verifier` on that same request. Desktop apps should use `/api/v1/authorize` and `/api/v1/oauth/session`, which bind the verifier to the challenge stored at the start.

## Origin check

`POST /api/v1/oauth/session` compares the `Origin` header to the redirect origin when the redirect is http(s) and the header is present. A desktop app has no matching browser origin. Tauri may send `Origin: tauri://localhost`, or no `Origin` at all.

identity-service skips that check only after PKCE has succeeded for a custom-scheme redirect. A missing or wrong verifier is rejected first, and the code stays unused. An http(s) redirect keeps the Origin check, including when the client also sent PKCE.

## Sign-in flow

1. The app opens the system browser to `GET /api/v1/authorize` with `company_id`, `redirect_to` (the exact allowlisted URI), `code_challenge`, `code_challenge_method=S256`, and optionally `provider`.
2. The person signs in with an OAuth provider, SAML, or a magic link.
3. The browser shows **Return to the app** (English or French, from `Accept-Language`) and a button. The page also sets `window.location` to the deep link, because some browsers block an automatic custom-scheme navigation.
4. The deep link is `shellui-playground://callback?shellui_auth_code=…`.
5. The app posts `auth_code`, the same `redirect_to`, and `code_verifier` to `POST /api/v1/oauth/session`.

The code lasts `OAUTH_SESSION_CODE_TTL_SECONDS` (120 seconds by default) and works once, as for a web shell.

## Magic link

`POST /api/v1/magic-link/request` takes the desktop `redirect_to` and the PKCE fields. The email still opens an https link on identity-service. After the person uses it, the return page sends them back to the app with `shellui_auth_code`.

The same rules as [Magic link](magic-link.md) still hold:

- the raw token is not logged, stored in plain text, or put on a webhook
- staff and superuser accounts get a notice, not a link
- the sign-in email goes only to the address that asked for it

A custom-scheme `redirect_to` has no https page to offer, so the staff notice has no **Go to sign-in** button.

`POST /api/v1/magic-link/verify` with JSON, for a custom-scheme link, also requires `code_verifier`. identity-service checks it before the token is used. The browser form that the email opens does not send the verifier. The app sends it at `POST /api/v1/oauth/session`.

## SAML and invitations

SAML uses the same PKCE query parameters on `/api/v1/saml/<organization_slug>/login/`. `GET /api/v1/authorize?provider=saml` forwards the challenge onto that URL. The challenge is stored with the AuthnRequest. The verifier is not.

`POST /api/v1/invitations` accepts an exact desktop URI as `app_url` when that URI is on the allowlist. PKCE is not required when the invitation is created: the inviter does not have the invitee's verifier. The person who accepts the invitation sends PKCE on the later sign-in. The email (English and French) says to copy the link when the button does not open the app. An http(s) invitation email keeps the sentence about copying the URL into a browser.

## What to change in the client and in admin

**@shellui/core and the desktop app**

- Register the custom scheme with the operating system, and add that exact URI as `kind=desktop` for the company.
- Generate a PKCE verifier, send the S256 challenge on authorize, magic link, and SAML, and keep the verifier in the app.
- Open the system browser for sign-in. Handle the deep link, read `shellui_auth_code`, and exchange it with `code_verifier`.
- Do not send the verifier to the browser, and do not expect `Origin` to match the custom scheme.
- Treat `shellui_oauth_error` and `shellui_oauth_error_code` on the deep link as a failed sign-in.

**Shellui admin**

- Offer `kind` on the OAuth redirect screen: `web` (origin prefix) or `desktop` (exact URI).
- Show desktop rows separately from hosting previews. Hosting sync does not create them.
- Do not require PKCE when an owner sends an invitation to a desktop URI.

Migrations `companies.0026_desktop_custom_scheme_redirect` and `authapi.0018_desktop_custom_scheme_redirect` add `kind` and the stored challenge. Existing rows stay `kind=web`. Web shells need no client change.

## Related

- [OAuth login](oauth-login.md): the web flow and the allowlist
- [Magic link](magic-link.md): email sign-in
- [SAML single sign-on](saml.md): company IdPs
- [Company access](company-access.md): invitations
- [Security hardening](security-hardening.md): Origin and redirects
