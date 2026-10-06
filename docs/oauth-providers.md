---
description: The sign-in providers identity-service supports, the settings each one needs, and when each one links accounts by email.
---

# OAuth providers

identity-service supports 16 sign-in providers: 15 OAuth 2.0 and OpenID Connect providers, plus SAML 2.0. Each company creates its own app at the provider, then adds the credentials in Shellui admin under **OAuth setup**. Shellui admin offers exactly the providers on this page. For the sign-in flow itself, see [OAuth login](oauth-login.md).

## Register the callback URL

Every provider app uses the same callback URL, on identity-service. Register it with no query string:

| Environment | Callback URL |
| --- | --- |
| Local | `http://localhost:8000/api/v1/oauth/callback` |
| Production | `https://auth.example.com/api/v1/oauth/callback` |

Replace `auth.example.com` with your identity-service host. Do not register your shell's `/login/callback` URL at the provider: identity-service redirects there after sign-in. django-allauth docs mention `/accounts/<provider>/login/callback/`, a path identity-service does not serve.

## Social and developer accounts

People sign in with an account they already have at a public provider. Use these for products open to anyone.

| Provider | Catalog ID | Protocol | Company settings | Links by email |
| --- | --- | --- | --- | --- |
| <span role="img" aria-label="Apple" style={{display:'inline-block',width:18,height:18,verticalAlign:'middle',flexShrink:0,background:'currentColor',WebkitMask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/apple.svg) center / contain no-repeat',mask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/apple.svg) center / contain no-repeat'}} /> [Apple](#apple) | `apple` | OAuth2 | Client ID, secret, `key`, `certificate_key` | When the provider marks the email verified |
| <span role="img" aria-label="GitHub" style={{display:'inline-block',width:18,height:18,verticalAlign:'middle',flexShrink:0,background:'currentColor',WebkitMask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/github.svg) center / contain no-repeat',mask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/github.svg) center / contain no-repeat'}} /> [GitHub](#github) | `github` | OAuth2 | Client ID and secret | Verified primary email |
| <span role="img" aria-label="GitLab" style={{display:'inline-block',width:18,height:18,verticalAlign:'middle',flexShrink:0,background:'#FC6D26',WebkitMask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/gitlab.svg) center / contain no-repeat',mask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/gitlab.svg) center / contain no-repeat'}} /> [GitLab](#gitlab) | `gitlab` | OAuth2 | Client ID, secret, `gitlab_url` (optional) | When the provider marks the email verified |
| <span role="img" aria-label="Google" style={{display:'inline-block',width:18,height:18,verticalAlign:'middle',flexShrink:0,background:'#4285F4',WebkitMask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/google.svg) center / contain no-repeat',mask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/google.svg) center / contain no-repeat'}} /> [Google](#google) | `google` | OAuth2 | Client ID and secret | Verified email in the ID token |
| <span role="img" aria-label="Line" style={{display:'inline-block',width:18,height:18,verticalAlign:'middle',flexShrink:0,background:'#00C300',WebkitMask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/line.svg) center / contain no-repeat',mask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/line.svg) center / contain no-repeat'}} /> [Line](#line) | `line` | OAuth2 | Client ID and secret | When the provider marks the email verified |
| <span aria-hidden="true" style={{display:'inline-flex',alignItems:'center',justifyContent:'center',width:18,height:18,verticalAlign:'middle',flexShrink:0,borderRadius:'50%',background:'var(--ifm-color-emphasis-300)',fontSize:11,fontWeight:700}}>L</span> [LinkedIn](#linkedin) | `linkedin` | OpenID Connect | Client ID and secret | Verified email in the ID token |
| <span aria-hidden="true" style={{display:'inline-flex',alignItems:'center',justifyContent:'center',width:18,height:18,verticalAlign:'middle',flexShrink:0,borderRadius:'50%',background:'var(--ifm-color-emphasis-300)',fontSize:11,fontWeight:700}}>M</span> [Microsoft](#microsoft) | `microsoft` | OAuth2 | Client ID, secret, `tenant` (optional) | Tenant check |
| <span role="img" aria-label="Reddit" style={{display:'inline-block',width:18,height:18,verticalAlign:'middle',flexShrink:0,background:'#FF4500',WebkitMask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/reddit.svg) center / contain no-repeat',mask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/reddit.svg) center / contain no-repeat'}} /> [Reddit](#reddit) | `reddit` | OAuth2 | Client ID and secret | When the provider marks the email verified |
| <span role="img" aria-label="Shopify" style={{display:'inline-block',width:18,height:18,verticalAlign:'middle',flexShrink:0,background:'#7AB55C',WebkitMask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/shopify.svg) center / contain no-repeat',mask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/shopify.svg) center / contain no-repeat'}} /> [Shopify](#shopify) | `shopify` | OAuth2 | Client ID and secret | When the provider marks the email verified |
| <span aria-hidden="true" style={{display:'inline-flex',alignItems:'center',justifyContent:'center',width:18,height:18,verticalAlign:'middle',flexShrink:0,borderRadius:'50%',background:'var(--ifm-color-emphasis-300)',fontSize:11,fontWeight:700}}>S</span> [Slack](#slack) | `slack` | OAuth2 | Client ID and secret | When the provider marks the email verified |
| <span role="img" aria-label="Twitch" style={{display:'inline-block',width:18,height:18,verticalAlign:'middle',flexShrink:0,background:'#9146FF',WebkitMask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/twitch.svg) center / contain no-repeat',mask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/twitch.svg) center / contain no-repeat'}} /> [Twitch](#twitch) | `twitch` | OAuth2 | Client ID and secret | Email from Twitch |

## Company identity providers

These providers are run by the company itself, for example its Okta org or Keycloak realm. Use them for workforce single sign-on (SSO). identity-service never links these sign-ins to an existing user by email.

| Provider | Catalog ID | Protocol | Company settings | Links by email |
| --- | --- | --- | --- | --- |
| <span role="img" aria-label="Auth0" style={{display:'inline-block',width:18,height:18,verticalAlign:'middle',flexShrink:0,background:'#EB5424',WebkitMask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/auth0.svg) center / contain no-repeat',mask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/auth0.svg) center / contain no-repeat'}} /> [Auth0](#auth0) | `auth0` | OAuth2 | Client ID, secret, `AUTH0_URL` | Never |
| <span role="img" aria-label="Keycloak" style={{display:'inline-block',width:18,height:18,verticalAlign:'middle',flexShrink:0,background:'currentColor',WebkitMask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/keycloak.svg) center / contain no-repeat',mask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/keycloak.svg) center / contain no-repeat'}} /> [Keycloak](#keycloak) | `keycloak` | OpenID Connect | Client ID, secret, `provider_id`, `server_url` | Never |
| <span role="img" aria-label="Okta" style={{display:'inline-block',width:18,height:18,verticalAlign:'middle',flexShrink:0,background:'#007DC1',WebkitMask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/okta.svg) center / contain no-repeat',mask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/okta.svg) center / contain no-repeat'}} /> [Okta](#okta) | `okta` | OAuth2 | Client ID, secret, `OKTA_BASE_URL` | Never |
| <span role="img" aria-label="OpenID Connect" style={{display:'inline-block',width:18,height:18,verticalAlign:'middle',flexShrink:0,background:'#F78C40',WebkitMask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/openid.svg) center / contain no-repeat',mask:'url(https://cdn.jsdelivr.net/npm/simple-icons@16.33.0/icons/openid.svg) center / contain no-repeat'}} /> [OpenID Connect](#openid-connect) | `openid_connect` | OpenID Connect | Client ID, secret, `server_url` | Never |
| <span aria-hidden="true" style={{display:'inline-flex',alignItems:'center',justifyContent:'center',width:18,height:18,verticalAlign:'middle',flexShrink:0,borderRadius:'50%',background:'var(--ifm-color-emphasis-300)',fontSize:11,fontWeight:700}}>S</span> [SAML](#saml) | `saml` | SAML | `idp_entity_id`, see [SAML](saml.md) | Trusted domains only |

## How email linking works

The first time someone signs in with a provider, identity-service looks for an existing user with the same provider account. When there is none, it can attach the sign-in to an existing user with the same email, but only when the provider proves the email belongs to that person. The **Links by email** column shows the proof each provider needs. Without it, identity-service matches by provider account ID only and never takes over another user by email.

## Provider setup

Each section lists where to create the app, the extra settings Shellui admin asks for, and provider-specific behavior.

### Apple

Follow the django-allauth Apple setup: the client ID is your Services ID and the client secret is the Key ID of your Sign in with Apple key.

Paste the `.p8` file content in `certificate_key`. Shellui admin never shows it again.

Apple posts the callback as a form (`form_post`). identity-service handles that on the same callback URL.

- **Catalog ID**: `apple`
- **Create the app**:
  - App registration: `https://developer.apple.com/account/resources/identifiers/list`
  - App settings: `https://developer.apple.com/account/resources/authkeys/list`
- **Settings**: `key` (Apple Team ID, required), `certificate_key` (Sign in with Apple private key (.p8), required, secret)
- **Email linking**: Links by email when the profile has `email_verified: true`. Otherwise the account is matched by provider account ID only.
- **Apps per company**: one
- **Reference**: [django-allauth Apple docs](https://docs.allauth.org/en/latest/socialaccount/providers/apple.html)

### Auth0

Set `AUTH0_URL` to your tenant domain, for example `https://your_tenant.eu.auth0.com`.

- **Catalog ID**: `auth0`
- **Create the app**: `https://manage.auth0.com/#/clients`
- **Settings**: `AUTH0_URL` (Auth0 domain URL, required)
- **Email linking**: Never links by email. The company controls this identity provider, so its email claims are not proof of ownership. Accounts are matched by provider account ID, scoped to the issuer.
- **Apps per company**: one
- **Reference**: [django-allauth Auth0 docs](https://docs.allauth.org/en/latest/socialaccount/providers/auth0.html)

### GitHub

Create an OAuth app and paste the callback URL as the **Authorization callback URL**.

- **Catalog ID**: `github`
- **Create the app**: `https://github.com/settings/applications/new`
- **Email linking**: identity-service reads `/user/emails` and links by email only when the primary address is verified. Without a verified primary email, sign-in stops with an error.
- **Apps per company**: one
- **Reference**: [django-allauth GitHub docs](https://docs.allauth.org/en/latest/socialaccount/providers/github.html)

### GitLab

Leave `gitlab_url` empty for gitlab.com. For a self-hosted GitLab, set its base URL.

A self-hosted GitLab counts as a company identity provider: it never links by email, and account IDs are prefixed with the GitLab base URL.

- **Catalog ID**: `gitlab`
- **Settings**: `gitlab_url` (GitLab base URL, optional)
- **Email linking**: Links by email when the profile has `email_verified: true`. Otherwise the account is matched by provider account ID only.
- **Apps per company**: one
- **Reference**: [django-allauth GitLab docs](https://docs.allauth.org/en/latest/socialaccount/providers/gitlab.html)

### Google

Google skips the identity-service account confirmation page by default, because Google already shows its own account picker. Change this with `OAUTH_SKIP_CONFIRM_PROVIDERS`, see [OAuth login](oauth-login.md#skip-the-confirmation-page).

- **Catalog ID**: `google`
- **Create the app**: `https://console.developers.google.com/`
- **Email linking**: Links by email when the ID token has `email_verified: true` and the same email as the userinfo response.
- **Apps per company**: one
- **Reference**: [django-allauth Google docs](https://docs.allauth.org/en/latest/socialaccount/providers/google.html)

### Keycloak

Set `server_url` to the realm issuer, for example `https://keycloak.example.com/realms/acme`. identity-service loads the OpenID Connect discovery document from it.

- **Catalog ID**: `keycloak`
- **Settings**: `provider_id` (Provider ID, required), `server_url` (OpenID Connect issuer URL, required)
- **Email linking**: Never links by email. The company controls this identity provider, so its email claims are not proof of ownership. Accounts are matched by provider account ID, scoped to the issuer.
- **Apps per company**: several, one per identity provider
- **Reference**: [django-allauth Keycloak docs](https://docs.allauth.org/en/latest/socialaccount/providers/keycloak.html)

### Line

- **Catalog ID**: `line`
- **Create the app**: `https://developers.line.biz/console/`
- **Email linking**: Links by email when the profile has `email_verified: true`. Otherwise the account is matched by provider account ID only.
- **Apps per company**: one
- **Reference**: [django-allauth Line docs](https://docs.allauth.org/en/latest/socialaccount/providers/line.html)

### LinkedIn

Enable **Sign In with LinkedIn using OpenID Connect** on the app. The LinkedIn endpoints are fixed in identity-service, so there is nothing else to set.

- **Catalog ID**: `linkedin`
- **Create the app**: `https://www.linkedin.com/secure/developer`
- **Email linking**: Links by email when the verified ID token has `email_verified: true` and the same email as userinfo. Otherwise the account is matched by provider account ID only.
- **Apps per company**: several, one per identity provider
- **Reference**: [django-allauth LinkedIn docs](https://docs.allauth.org/en/latest/socialaccount/providers/linkedin.html)

### Microsoft

Register the app in Microsoft Entra ID. Set `tenant` to your directory (GUID or domain) to accept only your organization, or leave it empty for any Microsoft account.

- **Catalog ID**: `microsoft`
- **Create the app**: `https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade`
- **Settings**: `tenant` (Tenant ID, optional)
- **Email linking**: With a dedicated `tenant` (GUID or domain), the ID token `tid` must match it. With `common` or no tenant, the ID token must carry `xms_edov: true`. Otherwise sign-in stops with an error, so a personal account cannot claim a work email.
- **Apps per company**: one
- **Reference**: [django-allauth Microsoft docs](https://docs.allauth.org/en/latest/socialaccount/providers/microsoft.html)

### Okta

Set `OKTA_BASE_URL` to your Okta org URL, for example `https://acme.okta.com`.

- **Catalog ID**: `okta`
- **Settings**: `OKTA_BASE_URL` (Okta org URL, required)
- **Email linking**: Never links by email. The company controls this identity provider, so its email claims are not proof of ownership. Accounts are matched by provider account ID, scoped to the issuer.
- **Apps per company**: one
- **Reference**: [django-allauth Okta docs](https://docs.allauth.org/en/latest/socialaccount/providers/okta.html)

### OpenID Connect

Use this entry for any standards-compliant OpenID Connect provider. Set `server_url` to the issuer URL or to its `/.well-known/openid-configuration` URL.

identity-service checks that the discovery document `issuer` matches, and verifies ID tokens against the provider keys.

- **Catalog ID**: `openid_connect`
- **Settings**: `server_url` (OpenID Connect issuer URL, required)
- **Email linking**: Never links by email. The company controls this identity provider, so its email claims are not proof of ownership. Accounts are matched by provider account ID, scoped to the issuer.
- **Apps per company**: several, one per identity provider
- **Reference**: [django-allauth OpenID Connect docs](https://docs.allauth.org/en/latest/socialaccount/providers/openid_connect.html)

### Reddit

- **Catalog ID**: `reddit`
- **Create the app**: `https://www.reddit.com/prefs/apps/`
- **Email linking**: Links by email when the profile has `email_verified: true`. Otherwise the account is matched by provider account ID only.
- **Apps per company**: one
- **Reference**: [django-allauth Reddit docs](https://docs.allauth.org/en/latest/socialaccount/providers/reddit.html)

### SAML

SAML has its own setup and endpoints. Follow [SAML single sign-on](saml.md).

- **Catalog ID**: `saml`
- **Email linking**: Matched by SAML NameID only. Email linking needs `trusted_for_verified_domains` and a verified company domain, see [SAML email linking](saml.md#email-linking).
- **Apps per company**: several, one per identity provider
- **Reference**: [django-allauth SAML docs](https://docs.allauth.org/en/latest/socialaccount/providers/saml.html)

### Shopify

Sign-in needs the store domain. Add it to the authorize request: `GET /api/v1/authorize?provider=shopify&shop=your_store.myshopify.com&…`.

- **Catalog ID**: `shopify`
- **Email linking**: Links by email when the profile has `email_verified: true`. Otherwise the account is matched by provider account ID only.
- **Apps per company**: one
- **Reference**: [django-allauth Shopify docs](https://docs.allauth.org/en/latest/socialaccount/providers/shopify.html)

### Slack

Create the app at api.slack.com and add the callback URL under **OAuth & Permissions**.

- **Catalog ID**: `slack`
- **Create the app**: `https://api.slack.com/apps/new`
- **Email linking**: Links by email when the profile has `email_verified: true`. Otherwise the account is matched by provider account ID only.
- **Apps per company**: one
- **Reference**: [django-allauth Slack docs](https://docs.allauth.org/en/latest/socialaccount/providers/slack.html)

### Twitch

identity-service requests one scope, `user:read:email`. Authorize and token calls go to `id.twitch.tv` and the profile call to `https://api.twitch.tv/helix/users`. These hosts are fixed: a company URL or scope setting returns `oauth_setting_not_allowed`.

When the Helix user `id` is missing, or the profile request fails, sign-in stops with `token_exchange_failed`. No account is created.

Twitch runs without PKCE. Sign-in relies on the signed OAuth state and the client secret.

- **Catalog ID**: `twitch`
- **Create the app**: `https://dev.twitch.tv/console`
- **Email linking**: Twitch returns `email` only for verified addresses, so its presence is the check. When Twitch omits it, sign-in stops with `oauth_identity_failed`.
- **Apps per company**: one
- **Reference**: [django-allauth Twitch docs](https://docs.allauth.org/en/latest/socialaccount/providers/twitch.html)

## Providers that are not available

django-allauth ships 98 more provider modules. They stay in `GET /api/v1/oauth-provider-catalog` with `supported: false` and an `unsupported_reason`, but Shellui admin hides them and `POST /api/v1/oauth-social-apps` refuses them with **400**. A provider becomes available once identity-service has an adapter for it, covered by a hand-written sign-in test.

## Update this page

This page is generated from `apps/authapi/provider_catalog.json` (catalog version 2, django-allauth 65.19.5). After a catalog change, regenerate it:

```bash
uv run python tools/render_oauth_providers_doc.py
```

CI fails when this page does not match the catalog. Edit provider notes in `tools/render_oauth_providers_doc.py`, not here.
