# Identity-hosted OAuth login

identity-service owns the OAuth authorize and callback endpoints. Provider apps register a **fixed** redirect URI on the identity host. The shell or CLI bounce target (`redirect_to`) travels in signed OAuth `state`, not in the provider callback URL.

## Flow

1. Shell (or `shellui login`) opens `GET /api/v1/authorize` with `company_id`, `redirect_to`, and optionally `provider`.
2. Without `provider`, identity shows a **sign-in method picker** (even when only one provider is enabled), then continues.
3. Identity redirects to the IdP using `redirect_uri={identity}/api/v1/oauth/callback` and a signed `state` that carries `redirect_to` and company context.
4. The provider returns to `/api/v1/oauth/callback`. Identity exchanges the code server-side.
5. The user sees an **account confirmation** page (confirm, switch provider, or switch account on the same provider).
6. On confirm, identity redirects to `redirect_to#access_token=…&refresh_token=…` (URL fragment). The shell `/login/callback` route reads the fragment and stores the session.

`POST /api/v1/oauth/exchange` remains for older shells that still receive `?code=` on the frontend. New shells should use the fragment bounce above.

## Provider app registration

Register **one** Authorization callback URL per provider app — the identity callback, with **no query string**:

| Environment | Callback URL |
|-------------|--------------|
| Local | `http://localhost:8000/api/v1/oauth/callback` |
| Production | `https://<identity-host>/api/v1/oauth/callback` |

Homepage / application URL may still point at the shell (e.g. `http://localhost:4000` or `https://app.example.com`).

Do **not** register the shell `/login/callback` URL on the IdP. That path only receives tokens after identity redirects with a fragment.

## Redirect allowlist

After OAuth, identity may bounce tokens only to approved targets for that company.

| Target | Rule |
|--------|------|
| Loopback (`127.0.0.1`, `localhost`, `::1`) | Always allowed (CLI / local listeners) |
| Other origins | Must match an active `CompanyOAuthRedirect` row for the company |
| Empty allowlist | Non-loopback `redirect_to` is **denied** |

Store **origins** only (scheme + host + optional port), for example:

- `http://localhost:4000`
- `https://app.example.com`

Path and query on the allowlist entry are ignored; matching is by origin (or origin prefix).

Configure via:

- **Django admin → Company OAuth redirects**
- Shellui admin **OAuth setup** (shows the identity callback URL and manage allowlist)
- `GET` / `POST` / `PATCH` / `DELETE` `/api/v1/oauth-redirects?company_id=…` (staff or company owner)

Example:

```bash
curl -s -X POST "https://auth.example.com/api/v1/oauth-redirects?company_id=1" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"base_url":"https://app.example.com","label":"Production shell"}'
```

## Related endpoints

| Endpoint | Role |
|----------|------|
| `GET /api/v1/authorize` | Start login; optional method picker |
| `GET /api/v1/oauth/callback` | Provider callback + confirmation UI |
| `POST /api/v1/oauth/confirm` | Finish sign-in after confirmation |
| `GET /api/v1/oauth/confirm?action=switch&confirm_token=…` | Restart OAuth with account picker (Google / Microsoft) |
| `GET`/`POST`/`PATCH`/`DELETE` `/api/v1/oauth-redirects` | Manage allowlist |

Company join rules (`public` / `domain` / `invite`) still apply after a successful provider login — see [company-access.md](company-access.md).

## Upgrading from shell-hosted callbacks

If you previously registered `{shell}/login/callback` on GitHub, Google, or Microsoft:

1. Change each provider app’s callback to `{identity}/api/v1/oauth/callback`.
2. Add every production shell origin to the company redirect allowlist.
3. Deploy identity-service with migration `0013_companyoauthredirect` (runs automatically on container start).
4. Prefer a Shellui / admin build that shows the identity callback in OAuth setup.
