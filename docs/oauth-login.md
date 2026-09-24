# Identity-hosted OAuth login

identity-service owns the OAuth authorize and callback endpoints. Provider apps register a **fixed** redirect URI on the identity host. The shell or CLI bounce target (`redirect_to`) travels in signed OAuth `state`, not in the provider callback URL.

## Flow

1. Shell (or `shellui login`) opens `GET /api/v1/authorize` with `company_id`, `redirect_to`, and optionally `provider`.
2. Without `provider`, identity shows a **sign-in method picker** (even when only one provider is enabled), then continues.
3. Identity redirects to the IdP using `redirect_uri={identity}/api/v1/oauth/callback` and a signed `state` that carries `redirect_to` and company context.
4. The provider returns to `/api/v1/oauth/callback`. Identity exchanges the code server-side.
5. The user sees an **account confirmation** page (confirm, switch provider, or switch account on the same provider).
6. On confirm, identity redirects to `redirect_to?shellui_auth_code=…` (default). The shell `/login/callback` route POSTs the code to `POST /api/v1/oauth/session` with the same `redirect_to` URL and stores the returned JSON tokens.

**Legacy fragment delivery:** set `token_delivery=fragment` on `/api/v1/authorize` (or `OAUTH_TOKEN_DELIVERY=fragment`) to receive `redirect_to#access_token=…&refresh_token=…` instead. Fragment mode is deprecated and will be removed in a future release.

`POST /api/v1/oauth/exchange` remains for older shells that still receive provider `?code=` on the frontend.

## Provider app registration

Register **one** Authorization callback URL per provider app — the identity callback, with **no query string**:

| Environment | Callback URL |
|-------------|--------------|
| Local | `http://localhost:8000/api/v1/oauth/callback` |
| Production | `https://<identity-host>/api/v1/oauth/callback` |

Homepage / application URL may still point at the shell (e.g. `http://localhost:4000` or `https://app.example.com`).

Do **not** register the shell `/login/callback` URL on the IdP. That path only receives tokens after identity redirects with a fragment.

## Social login providers

identity-service uses **[django-allauth](https://docs.allauth.org/en/latest/)** for `SocialApp` storage and provider modules. **Stock releases** wire the identity-hosted OAuth flow (`/api/v1/authorize` → `/api/v1/oauth/callback`) for **GitHub**, **Google**, and **Microsoft** only. Every other provider in the allauth catalog is **available in the library** once you enable its module, satisfy any extra dependencies from the provider page, create per-company `SocialApp` credentials, and extend OAuth wiring in your deploy — see the full checklist and catalog in **[Social login providers (django-allauth)](oauth-providers.md)**.

Quick reference:

| Tier | Examples | Stock Shellui OAuth wired? |
| ---- | -------- | -------------------------- |
| **Primary / common starters** | Google, Microsoft, GitHub, Apple, GitLab, Slack, Okta, Auth0, Keycloak (OIDC), OpenID Connect, SAML, Discord, Facebook, LinkedIn, Amazon Cognito | GitHub, Google, Microsoft only |
| **Also available** | Full django-allauth **65.14.1** module list (X/Twitter OAuth 1+2, Twitch, Steam, …) | Requires custom enablement |

Upstream source of truth: [django-allauth socialaccount providers](https://docs.allauth.org/en/latest/socialaccount/providers/index.html).

Configuring a provider does **not** mean Shellui pre-registers IdP clients — operators still create OAuth/SAML apps with each vendor. Listing a provider is not a security certification.

## Redirect allowlist

After OAuth, identity may bounce tokens only to approved targets for that company.

| Target | Rule |
|--------|------|
| Loopback (`127.0.0.1`, `localhost`, `::1`) | Allowed when `DEBUG=true` or `OAUTH_ALLOW_LOOPBACK_REDIRECTS=true` (CLI / local dev) |
| Other origins | Must match an active `CompanyOAuthRedirect` row for the company |
| Hosting previews (`{slug}.{HOSTING_APP_DOMAIN}`) | Synced automatically by hosting-service (`source=hosting`) when a site is created/deleted |
| Empty allowlist | Non-loopback `redirect_to` is **denied** |

Store **origins** only (scheme + host + optional port), for example:

- `http://localhost:4000`
- `https://app.example.com`

Path and query on the allowlist entry are ignored; matching is by origin (or origin prefix).

Configure via:

- **Django admin → Company OAuth redirects**
- Shellui admin **OAuth setup** (manual origins + separate hosting preview list)
- `GET` / `POST` / `PATCH` / `DELETE` `/api/v1/oauth-redirects?company_id=…` (staff or company owner)
- Hosting sync: `PUT` / `DELETE` `/api/v1/hosting-oauth-redirects` with the deployer's identity JWT (staff or company owner; forwarded by hosting-service; company from token)

Example:

```bash
curl -s -X POST "https://auth.example.com/api/v1/oauth-redirects?company_id=1" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"base_url":"https://app.example.com","label":"Production shell"}'
```

### CORS vs redirect allowlist

These are different controls:

| Concern | Mechanism | Strict? |
|---------|-----------|---------|
| **Token delivery** (`redirect_to` after OAuth) | `CompanyOAuthRedirect` allowlist + one-time code exchange | **Yes** — keep allowlist strict; prefer `code` delivery over URL fragments |
| **Browser API calls** (Bearer JWT to `/api/v1/*`) | Permissive CORS (`CORS_ALLOW_ALL_ORIGINS=true` by default; `CORS_ALLOW_CREDENTIALS=false`) | No — JWT verification and company scoping are the auth boundary (same model as Supabase) |

Do **not** add every hosting preview slug to `CORS_ALLOWED_ORIGINS`. Preview login still requires the redirect allowlist (auto-synced by hosting-service). Set `CORS_ALLOW_ALL_ORIGINS=false` only for lock-down installs that intentionally restrict API origins.

## Security hardening

Rate limits, HTTPS defaults, Postgres SSL, trusted-proxy IP handling, and PAT lifetime are documented in [security-hardening.md](security-hardening.md).

## Related endpoints

| Endpoint | Role |
|----------|------|
| `GET /api/v1/authorize` | Start login; optional method picker |
| `GET /api/v1/oauth/callback` | Provider callback + confirmation UI |
| `POST /api/v1/oauth/confirm` | Finish sign-in after confirmation |
| `POST /api/v1/oauth/session` | Exchange `shellui_auth_code` for JWT JSON (default delivery) |
| `GET /api/v1/oauth/confirm?action=switch&confirm_token=…` | Restart OAuth with account picker (Google / Microsoft) |
| `GET`/`POST`/`PATCH`/`DELETE` `/api/v1/oauth-redirects` | Manage allowlist |
| `PUT`/`DELETE` `/api/v1/hosting-oauth-redirects` | Hosting-service sync (`source=hosting`, owner/staff JWT) |

Company join rules (`public` / `domain` / `invite`) still apply after a successful provider login — see [company-access.md](company-access.md).

## JWT `user_metadata.groups`

Access and refresh tokens (and `GET /api/v1/user`) include `user_metadata.groups`: a sorted list of **effective** company group `display_name` values for the token’s `company_id`. That includes groups where the user is a **direct** member and every **ancestor** group linked via nested SCIM group members (`member_groups` / `parent_groups`), transitively and cycle-safe within the same company.

SCIM **User** resources still expose **direct** group membership only — see [scim.md](scim.md).

## Upgrading

### To session-code token delivery (H-03)

1. Deploy identity-service with migration `0010_refresh_rotation_oauth_session_code`.
2. Update shells to read `shellui_auth_code` from the login callback query string and call `POST /api/v1/oauth/session` with `{ "auth_code": "…", "redirect_to": "<same callback URL>" }`.
3. Until shells are updated, pass `token_delivery=fragment` on authorize or set `OAUTH_TOKEN_DELIVERY=fragment` on the identity host.

### Refresh rotation (H-02)

- Logout now revokes the refresh session; clients should discard both tokens locally.
- Token refresh returns a new refresh token; persist the new value and stop using the old one.
- All outstanding refresh tokens from before this release stop working after deploy — users must sign in again.

### From shell-hosted callbacks (pre-0.4.0)

If you previously registered `{shell}/login/callback` on GitHub, Google, or Microsoft:

1. Change each provider app’s callback to `{identity}/api/v1/oauth/callback`.
2. Add every production shell origin to the company redirect allowlist.
3. Deploy identity-service with migration `0013_companyoauthredirect` (runs automatically on container start).
4. Prefer a Shellui / admin build that shows the identity callback in OAuth setup.

### To 0.4.1 (hosting sync + permissive CORS)

1. Deploy identity-service so migration `0014_companyoauthredirect_source` runs (adds `source` on `CompanyOAuthRedirect`; existing rows default to `manual`).
2. Keep `CORS_ALLOW_ALL_ORIGINS=true` unless you intentionally lock down API origins; do **not** enumerate hosting preview slugs in `CORS_ALLOWED_ORIGINS`.
3. Ensure hosting-service can reach `PUT`/`DELETE /api/v1/hosting-oauth-redirects` with a staff or company-owner identity JWT so preview origins stay on the redirect allowlist.
