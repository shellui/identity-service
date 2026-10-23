---
description: Run identity-service on its own, as an OpenID Provider, or as a relying party that trusts one upstream provider.
---

# Instance roles

`SHELLUI_INSTANCE_ROLE` selects how this process behaves. Leave it unset and identity-service is a standalone deployment: sign-in, tokens, SCIM, SAML, and webhooks stay as they are, and the endpoints on this page answer **404**.

| Value | Role |
| --- | --- |
| unset | Standalone. Nothing on this page is active |
| `global` | OpenID Provider. Other deployments can trust this issuer |
| `region` | Relying party. This deployment trusts one upstream identity provider |

Use a distinct `JWT_AUDIENCE` on each deployment, and do not copy `JWT_PRIVATE_KEY` or `SECRET_KEY` from one deployment to another. `SESSION_COOKIE_DOMAIN` and `CSRF_COOKIE_DOMAIN` stay unset, so session cookies are host-only.

## Provider (`global`)

The provider publishes an OpenID Connect discovery document and accepts silent sign-in only. `prompt` must be `none`. There is no login page on the authorize endpoint: a missing browser session redirects back with `error=login_required`.

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery |
| `GET /oauth/authorize` | Authorization code request. `prompt=none`, `response_type=code`, scope includes `openid` |
| `POST /oauth/token` | Code exchange. `client_secret_basic` or `client_secret_post` |
| `GET` or `POST /oauth/userinfo` | Profile for the opaque access token |
| `GET /.well-known/jwks.json` | Signing keys, the same document API tokens use |

`id_token` and userinfo carry `sub`, `email`, and `email_verified`. `email_verified` is the boolean `true` only after a completed sign-in that proved the address (a magic link, or a provider that reported the address as verified). The tokens do not carry `is_staff` or `is_superuser`. API access tokens issued in this role also carry `sub` (the same value as the `id_token`) and `email_verified`, which the dashboard reads before it lets an owner create a company.

A successful sign-in on the provider sets a host-only cookie, `shellui_op_session`, on the path `/oauth/`. It is not the Django session cookie. `POST /api/v1/logout` sends a [back-channel logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) token to each client's `backchannel_logout_uri`.

### Clients

`OIDC_CLIENTS` is a JSON list. Each object has `client_id`, `client_secret`, `redirect_uris`, and an optional `backchannel_logout_uri`. Redirect and logout URLs must be `https` (`http` is accepted when `DEBUG=true`). An empty list means authorize rejects every client.

```json
[
  {
    "client_id": "relying-party",
    "client_secret": "replace-me",
    "redirect_uris": ["https://auth.example.net/oauth/upstream-callback"],
    "backchannel_logout_uri": "https://auth.example.net/oauth/backchannel-logout"
  }
]
```

`OIDC_CORS_ALLOWED_ORIGINS` is a comma-separated list of origins. It applies to the OpenID and provisioning endpoints only. The Bearer API keeps `CORS_ALLOW_ALL_ORIGINS`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `OIDC_CLIENTS` | empty | Confidential clients |
| `OIDC_CORS_ALLOWED_ORIGINS` | empty | Browser origins for the OpenID endpoints |
| `OIDC_SESSION_TTL_SECONDS` | `43200` | Provider cookie lifetime |
| `OIDC_CODE_TTL_SECONDS` | `60` | Authorization code lifetime |
| `OIDC_ID_TOKEN_TTL_SECONDS` | `300` | `id_token` lifetime |
| `OIDC_BACKCHANNEL_TIMEOUT_SECONDS` | `3` | Logout POST timeout |

These webhook events are registered on every deployment and emitted only when the role is `global`. Other roles omit them from `GET /api/v1/events/types` and from webhook rules:

- `identity.federation.authorize.succeeded`
- `identity.federation.backchannel_logout.sent`

Payloads do not include tokens, authorization codes, or sign-in links.

## Relying party (`region`)

The relying party trusts one upstream provider from the environment. This is not a per-company OAuth application, and the company sign-in page does not grow a button for it.

| Variable | Purpose |
| --- | --- |
| `GLOBAL_ISSUER_URL` | Upstream issuer. Must match the upstream `iss` claim |
| `GLOBAL_JWKS` | Pinned JWKS JSON. Keys are not fetched from the network |
| `GLOBAL_CLIENT_ID` | Client id issued by the upstream provider |
| `GLOBAL_CLIENT_SECRET` | Matching client secret |
| `GLOBAL_REDIRECT_URI` | Optional. Defaults to `{JWT_ISSUER}/oauth/upstream-callback` |

`GET /oauth/silent-signin?company_id=&redirect_to=` starts the flow. `redirect_to` must pass the company allowlist. The browser is sent to the upstream authorize endpoint with `prompt=none` and S256 PKCE. `GET /oauth/upstream-callback` finishes it.

A local user is created or linked only when `email_verified` is the boolean `true`. The string `"true"` is rejected. The link is the upstream `iss` and `sub`. An existing local user is matched by that verified email. `is_staff` and `is_superuser` are never set here. Change those flags in Django admin only.

If the upstream redirect carries `error=login_required`, no account is created.

### Token exchange (region role)

A shell signed in to the global server gets a regional session without a browser redirect, using OAuth 2.0 Token Exchange (RFC 8693). It answers **404** unless the role is `region` and `GLOBAL_ISSUER_URL`, `GLOBAL_JWKS` and `GLOBAL_ACCESS_TOKEN_AUDIENCE` are set.

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<global access token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&company_id=<regional company id>
```

Success (200, `Cache-Control: no-store`):

```json
{
  "access_token": "<regional access token>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 300,
  "expires_at": 1793000000,
  "refresh_token": "<regional refresh token>"
}
```

The refresh token works with the usual `POST /api/v1/token?grant_type=refresh_token`.

Checks on the subject token, all offline:

- RS256 only, signed by a key in `GLOBAL_JWKS` (matched by `kid`)
- `iss` equals `GLOBAL_ISSUER_URL`, `aud` equals `GLOBAL_ACCESS_TOKEN_AUDIENCE`, `exp` not passed
- `token_type` is `access` and the token carries a session id (`sid`). Refresh tokens and personal access tokens are refused
- `email_verified` is the boolean `true`

The user is then linked exactly like the upstream silent sign-in (`iss` and `sub`, local staff accounts refused, new accounts never staff) and the company join rules apply as on any sign-in: an invite-only company refuses a user who has no membership.

Errors follow RFC 6749: `invalid_request`, `invalid_target` (unknown `company_id`), `invalid_grant` (token or user refused, with `error_description`). An `Origin` that is not in `OIDC_CORS_ALLOWED_ORIGINS` gets **403**, and only those origins get CORS headers, so list every shell origin there (for example `https://dashboard.shellui.com`, and `http://localhost:4000` for local testing). Tokens are never logged.

The global access token is not checked against global session revocation. It lives for `JWT_ACCESS_TOKEN_LIFETIME` (5 minutes by default) on the global server.

### Provisioning API

The dashboard (shellui/saas-service) creates and manages regional companies here. Nothing else calls this API. It answers **404** unless the role is `region` and `PROVISIONING_PUBLIC_KEY`, `PROVISIONING_ISSUER` and `GLOBAL_ISSUER_URL` are set.

| Variable | Purpose |
| --- | --- |
| `PROVISIONING_PUBLIC_KEY` | Dashboard provisioning public key, PEM (literal `
` accepted). `manage.py setup` on saas-service prints it |
| `PROVISIONING_KEY_ID` | Optional. When set, the assertion `kid` must match (saas-service `PROVISIONING_KEY_ID`, default `dashboard-1`) |
| `PROVISIONING_ISSUER` | Must equal saas-service `PROVISIONING_ASSERTION_ISSUER` |
| `PROVISIONING_AUDIENCE` | Optional. Defaults to the host of `JWT_ISSUER`, for example `id.eu.shellui.com` |
| `PROVISIONING_DEFAULT_REDIRECTS` | Comma-separated origins added to every new company's redirect allowlist, for example the regional admin |

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/provisioning/companies` | Create a company and its owner. **201** with the company, **409** with `id` when the `global_company_id` exists |
| `GET /api/v1/provisioning/companies?linked=shellui` | `{ "results": [...], "next": url or null }`, 200 per page, ordered by id |
| `GET /api/v1/provisioning/companies/{id}` | Company with `status`, `limits_version`, and owner subjects |
| `PATCH /api/v1/provisioning/companies/{id}` | `name` and/or `status` (`active` or `suspended`) |
| `PUT /api/v1/provisioning/companies/{id}/limits` | `{ "version", "limits" }`. An older version returns **409** `stale_version` |
| `DELETE /api/v1/provisioning/companies/{id}` | **202**, status `deleting`. Data is kept; nothing is removed by this call |

Every call sends `Authorization: Bearer <assertion>`, an RS256 JWT signed with the pinned key. Required claims: `iss`, `aud`, `sub`, `iat`, `exp` (at most 300 seconds after `iat`), `jti`, `scope` equal to `provisioning`, and a request binding: `htm` (method), `htu` (path with query) and `bh` (base64url SHA-256 of the exact body bytes). A reused `jti` returns **401** `assertion_replayed`. Writes need `Idempotency-Key`; the same key and request return the stored response, and the same key with a different request returns **409** `idempotency_conflict`. Errors are `{ "detail", "error_code" }`.

Create body:

```json
{
  "global_company_id": "uuid from the dashboard",
  "name": "Acme",
  "plan": "free",
  "access_mode": "public",
  "owner": {"subject": "global sub", "email": "ada@acme.com", "email_verified": true, "name": "Ada"}
}
```

The owner is linked by the global subject (`GLOBAL_ISSUER_URL` and `owner.subject`). Without a link, an existing user with the same email is linked, and otherwise a new user is created. `owner.email_verified` must be the boolean `true` (**403** `email_not_verified` otherwise). An existing `is_staff` or `is_superuser` account is refused (**409** `user_is_staff`). This API never sets those flags.

`GET /api/v1/companies/{id}/plan` returns `{ "company_id", "limits", "limits_version", "status" }` to a member of that company, for regional services. Suspension keeps hosted sites online; services read `status` to lock the admin and deploys.

### Back-channel logout

`POST /oauth/backchannel-logout` accepts `logout_token` (form or JSON). The token must use RS256, the pinned key, `aud` equal to `GLOBAL_CLIENT_ID`, and the back-channel logout event. A `nonce` is rejected. A repeated `jti` is rejected. A known `sub` has its refresh sessions revoked. The response is **200** when the token is valid, including when the subject is unknown here.

### Production startup

With `DEBUG=false` and `SHELLUI_INSTANCE_ROLE=region`, the process refuses to start when any of these still use a built-in host:

- `EMAIL_SERVICE_URL` host is `email.shellui.com`
- `CSRF_TRUSTED_ORIGINS` or `ALLOWED_HOSTS` contains `admin.shellui.com` or `email.shellui.com`

Set this deployment's own email service, allowed hosts, and trusted origins. `GLOBAL_ISSUER_URL`, `GLOBAL_JWKS`, `GLOBAL_CLIENT_ID`, `GLOBAL_CLIENT_SECRET`, and `JWT_ISSUER` are required in that same mode. `manage.py check --deploy` reports the same failures as `federation.E002`.
