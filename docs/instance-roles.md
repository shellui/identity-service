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
| `POST /api/v1/federation/provision` | Staff only. Create a company and its owner on a relying party |
| `POST /api/v1/federation/plan` | Staff only. Push plan limits to a relying party |

`id_token` and userinfo carry `sub`, `email`, and `email_verified`. `email_verified` is the boolean `true` only after a completed sign-in that proved the address (a magic link, or a provider that reported the address as verified). The tokens do not carry `is_staff` or `is_superuser`.

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

### Provisioning out

`POST /api/v1/federation/provision` is for a staff user. The body is JSON:

| Field | Purpose |
| --- | --- |
| `region_base_url` | Relying party origin, `https` |
| `audience` | That deployment's `JWT_ISSUER` |
| `company_name` | Company name to create |
| `company_slug` | Optional slug |
| `owner_email` | Must already be verified on this provider |
| `plan` | Optional limits object |
| `idempotency_key` | 8 to 200 characters, `[A-Za-z0-9._:-]` |
| `webhook_company_id` | Optional company that receives the webhook below |

The provider signs a short-lived assertion with its JWT key and posts it to the relying party. The owner email is sent only when `email_verified` is true. `POST /api/v1/federation/plan` takes `region_base_url`, `audience`, `company_slug`, `plan`, and `idempotency_key`.

These webhook events are registered on every deployment and emitted only when the role is `global`. Other roles omit them from `GET /api/v1/events/types` and from webhook rules:

- `identity.federation.authorize.succeeded`
- `identity.federation.provisioning.completed`
- `identity.federation.plan.pushed`
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

### Provisioning API

`POST /api/v1/provisioning/companies` and `POST /api/v1/provisioning/plans` accept a signed assertion.

```http
POST /api/v1/provisioning/companies
Authorization: Bearer <assertion>
Idempotency-Key: <same value as the assertion claim>
```

The assertion is RS256, signed by a key in `GLOBAL_JWKS`. Required claims are `iss` (equal to `GLOBAL_ISSUER_URL`), `aud` (equal to this deployment's `JWT_ISSUER`), `iat`, `exp` (at most 120 seconds after `iat`), `jti`, and `idempotency_key` (equal to the header). A company assertion also needs `email_verified: true`, `company.name`, and `owner.email`.

The same idempotency key and the same body return the stored response. The same key with a different body returns **409** `idempotency_conflict`. A reused `jti` on a different key returns **401** `assertion_replayed`. An unverified email returns **403** `email_not_verified` and writes nothing.

`POST /api/v1/provisioning/plans` updates limits for an existing company slug. `GET /api/v1/companies/{id}/plan` returns `{ "company_id", "limits" }` to a member of that company. Unknown companies and non-members get **404**.

### Back-channel logout

`POST /oauth/backchannel-logout` accepts `logout_token` (form or JSON). The token must use RS256, the pinned key, `aud` equal to `GLOBAL_CLIENT_ID`, and the back-channel logout event. A `nonce` is rejected. A repeated `jti` is rejected. A known `sub` has its refresh sessions revoked. The response is **200** when the token is valid, including when the subject is unknown here.

### Production startup

With `DEBUG=false` and `SHELLUI_INSTANCE_ROLE=region`, the process refuses to start when any of these still use a built-in host:

- `EMAIL_SERVICE_URL` host is `email.shellui.com`
- `CSRF_TRUSTED_ORIGINS` or `ALLOWED_HOSTS` contains `admin.shellui.com` or `email.shellui.com`

Set this deployment's own email service, allowed hosts, and trusted origins. `GLOBAL_ISSUER_URL`, `GLOBAL_JWKS`, `GLOBAL_CLIENT_ID`, `GLOBAL_CLIENT_SECRET`, and `JWT_ISSUER` are required in that same mode. `manage.py check --deploy` reports the same failures as `federation.E002`.
