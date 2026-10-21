---
description: Sign a desktop app in through the system browser and return with a custom-scheme deep link and PKCE.
---

# Desktop apps

A desktop app signs people in through the system browser, then returns to the app with a custom-scheme deep link such as `shellui-playground://callback?shellui_auth_code=…`. You register the app's schemes once on the company. Desktop sign-in stays off until that list has a scheme. Social sign-in, magic link, and SAML all use the same list. Web shells keep the http(s) flow in [OAuth login](oauth-login.md). An http(s) `redirect_to` is still an origin on the allowlist, and PKCE stays optional there.

## Pick a scheme

You choose the scheme when you register the desktop app with the operating system. Use a lowercase name that belongs to your app, such as `shellui-playground` or `com.example.desktop`. The value must be an [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.1) scheme: a letter, then letters, digits, `+`, `-`, or `.`.

These schemes are refused: `http`, `https`, `javascript`, `data`, `file`, `vbscript`, `about`, `blob`, and other browser or network schemes such as `ftp`, `mailto`, and `ws`. Uppercase is refused. Send `shellui-playground`, not `Shellui-Playground`.

The deep link the app opens looks like this:

```text
shellui-playground://callback
```

`callback` is the path your app handles. identity-service accepts any path on the registered scheme, for example `shellui-playground://auth/done`. A different scheme is refused.

## Register the scheme

Set `desktop_redirect_schemes` on the company. Identity has no separate desktop-app record: a sign-in is for one company, named by `company_id` (or, for SAML, by the organization slug that belongs to that company). The scheme belongs to that company, not to Google, GitHub, or any other provider.

The field is a list. An empty list keeps desktop sign-in off, so a custom-scheme `redirect_to` returns `unregistered_scheme`. A scheme in the list is accepted for every sign-in method of that company. Any other scheme is refused.

When `DEBUG=true`, a registered scheme also accepts its `-dev` variant: `shellui-playground` allows `shellui-playground-dev`. `shellui start --app` signs in with that variant so a dev build never takes an installed app's links. With `DEBUG=false`, that variant is refused unless the company sets `allow_desktop_dev_scheme`.

The flag only adds `-dev` to schemes already on the list. It does not accept another scheme, a second `-dev` (`shellui-playground-dev-dev`), or a lookalike such as `shellui-playground-devx`. You can still list `shellui-playground-dev` itself with the flag off.

Staff and company owners set the list and the flag on the company. Members can read both fields. Only an owner, or staff (`is_staff` or `is_superuser`), can change them.

- **Django admin**: open the company and edit **Desktop redirect schemes** and **Allow desktop dev scheme**
- **REST API**: `PATCH /api/v1/companies/<id>/` (company owner or staff)

```bash
curl -s -X PATCH "https://auth.example.com/api/v1/companies/1/" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"desktop_redirect_schemes":["shellui-playground"]}'
```

Send `{"allow_desktop_dev_scheme":true}` on the same path to accept `shellui-playground-dev` when `DEBUG=false`.

The company response includes the same fields:

```json
{
  "id": 1,
  "name": "Acme",
  "slug": "acme",
  "owners": [4],
  "access_mode": "public",
  "allowed_email_domains": [],
  "data_retention_days": 7,
  "desktop_redirect_schemes": ["shellui-playground"],
  "allow_desktop_dev_scheme": false
}
```

Send `{"desktop_redirect_schemes":[]}` to turn desktop sign-in off. The http(s) redirect allowlist is unchanged. Hosting preview sync still writes web origins only. OAuth client and social app requests no longer accept `desktop_redirect_scheme`.

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

An http(s) redirect requires the same S256 challenge and verifier. See [OAuth login](oauth-login.md#pkce-for-every-session-code). Older session errors that are not PKCE stay `{ "error": "…" }` with no `error_code`.

Custom-scheme redirects always use the one-time code. `token_delivery=fragment` and `OAUTH_TOKEN_DELIVERY=fragment` do not put tokens in the deep link. If a custom-scheme redirect reaches the end of sign-in without a challenge, the deep link carries `shellui_oauth_error` and `shellui_oauth_error_code=pkce_required` instead of a code.

`POST /api/v1/oauth/exchange` and `POST /api/v1/providers/<provider>/login/` are the older JSON token endpoints. For a custom-scheme `redirect_uri` they require `code_challenge`, `code_challenge_method=S256`, and `code_verifier` on that same request. Desktop apps should use `/api/v1/authorize` and `/api/v1/oauth/session`, which bind the verifier to the challenge stored at the start.

## Origin check

`POST /api/v1/oauth/session` requires the `Origin` header on an http(s) redirect, and that header must match the redirect origin. A missing header is rejected. A desktop app has no matching browser origin. Tauri may send `Origin: tauri://localhost`, or no `Origin` at all.

identity-service skips that check only after PKCE has succeeded for a custom-scheme redirect. A missing or wrong verifier is rejected first, and the code stays unused. An http(s) redirect keeps the Origin check after PKCE succeeds.

## Sign-in flow

1. The app opens the system browser to `GET /api/v1/authorize` with `company_id`, `redirect_to` (a URI on the registered scheme), `code_challenge`, `code_challenge_method=S256`, and optionally `provider`.
2. The person signs in with an OAuth provider, SAML, or a magic link.
3. The browser shows **Return to the app** (English or French, from `Accept-Language`) and a button. The page also sets `window.location` to the deep link, because some browsers block an automatic custom-scheme navigation.
4. The deep link is `shellui-playground://callback?shellui_auth_code=…`.
5. The app posts `auth_code`, the same `redirect_to`, and `code_verifier` to `POST /api/v1/oauth/session`.

The code lasts `OAUTH_SESSION_CODE_TTL_SECONDS` (120 seconds by default) and works once, as for a web shell.

## Browser error page

A sign-in error that a person hits in the browser renders an HTML page in English or French, from `Accept-Language`. The page states what failed and offers **Go back** (`Retour`). It does not include a token, an auth code, or the sign-in URL.

When the request already has a redirect on that application's registered scheme, the page also shows **Back to the app** (`Revenir à l'application`). That link opens the same path with only an `error` query parameter:

```text
shellui-playground://callback?error=pkce_required
```

The app reads `error` and shows its own message. The query never contains `shellui_auth_code`, a verifier, or a token. If the scheme is missing, or it is not in the company list, the page has no app button.

Clients that send `Accept: application/json`, and JSON API endpoints such as `POST /api/v1/oauth/session`, still receive JSON.

## Magic link

`POST /api/v1/magic-link/request` takes the desktop `redirect_to` and the PKCE fields. The email still opens an https link on identity-service. After the person uses it, the return page sends them back to the app with `shellui_auth_code`.

The same rules as [Magic link](magic-link.md) still hold:

- the raw token is not logged, stored in plain text, or put on a webhook
- staff and superuser accounts get a notice, not a link
- the sign-in email goes only to the address that asked for it

A custom-scheme `redirect_to` has no https page to offer, so the staff notice has no **Go to sign-in** button.

`POST /api/v1/magic-link/verify` with JSON, for a custom-scheme link, also requires `code_verifier`. identity-service checks it before the token is used. The browser form that the email opens does not send the verifier. The app sends it at `POST /api/v1/oauth/session`. An expired or invalid link shows the browser error page. When the stored redirect uses the registered scheme, **Back to the app** opens `shellui-playground://callback?error=magic_link_expired` (or `magic_link_invalid`).

## SAML and invitations

SAML uses the same PKCE query parameters on `/api/v1/saml/<organization_slug>/login/`. `GET /api/v1/authorize?provider=saml` forwards the challenge onto that URL. The challenge is stored with the AuthnRequest. The verifier is not.

`POST /api/v1/invitations` accepts a desktop URI as `app_url` when its scheme is in the company list. PKCE is not required when the invitation is created: the inviter does not have the invitee's verifier. The person who accepts the invitation sends PKCE on the later sign-in. The email (English and French) says to copy the link when the button does not open the app. An http(s) invitation email keeps the sentence about copying the URL into a browser.

## What to change in the client and in admin

**@shellui/core and the desktop app**

- Register the custom scheme with the operating system, and add that scheme to the company `desktop_redirect_schemes` list.
- Generate a PKCE verifier, send the S256 challenge on authorize, magic link, and SAML, and keep the verifier in the app.
- Open the system browser for sign-in. Handle the deep link, read `shellui_auth_code`, and exchange it with `code_verifier`.
- Handle `error` on the same deep link when sign-in fails in the browser. Do not expect a token on that URL.
- Do not send the verifier to the browser, and do not expect `Origin` to match the custom scheme.
- Treat `shellui_oauth_error` and `shellui_oauth_error_code` on the success-path deep link as a failed sign-in.

**Shellui admin**

- Edit `desktop_redirect_schemes` on the company. Leave the list empty until a desktop app has a scheme.
- Turn on `allow_desktop_dev_scheme` when a dev build must sign in to this company with the `-dev` scheme and `DEBUG` is off.
- Do not add a desktop row on the OAuth redirect allowlist. That list stays http(s) origins.
- Do not require PKCE when an owner sends an invitation to a desktop URI.

Migration `companies.0029_company_desktop_redirect_schemes` copies existing schemes onto the company and drops `CompanyOAuthClient.desktop_redirect_scheme`. Migration `companies.0030_company_allow_desktop_dev_scheme` adds `allow_desktop_dev_scheme`, off by default. Migration `authapi.0018_desktop_custom_scheme_redirect` stores the PKCE challenge. Web shells send the same S256 challenge and verifier. See [OAuth login](oauth-login.md#pkce-for-every-session-code).

## Related

- [OAuth login](oauth-login.md): the web flow and the allowlist
- [Magic link](magic-link.md): email sign-in
- [SAML single sign-on](saml.md): company IdPs
- [Company access](company-access.md): invitations
- [Security hardening](security-hardening.md): Origin and redirects
