# Social login providers (django-allauth)

identity-service stores OAuth client credentials in django-allauth **`SocialApp`** rows (linked to companies via **`CompanyOAuthClient`**). The service depends on **[django-allauth 65.14.1](https://docs.allauth.org/en/latest/)** (`pyproject.toml` / `uv.lock`).

**Source of truth for provider setup steps:** the upstream [django-allauth socialaccount provider index](https://docs.allauth.org/en/latest/socialaccount/providers/index.html). Each provider page documents IdP registration, optional Python/OS packages, and `SOCIALACCOUNT_PROVIDERS` settings.

This page mirrors that catalog for operators planning IdP coverage. It does **not** imply Shellui ships credentials for every IdP — you still register each client with the provider and attach it to a company.

---

## How this relates to Shellui OAuth

| Layer | What it does |
| ----- | ------------ |
| **django-allauth** | Provider modules, `SocialApp` model, optional vanilla `/accounts/…` routes (not mounted by default in identity-service) |
| **identity-service OAuth API** | Identity-hosted flow: `GET /api/v1/authorize` → IdP → `GET /api/v1/oauth/callback` → confirmation → `redirect_to?shellui_auth_code=…` — see [OAuth login](oauth-login.md) |
| **Per-company enablement** | Active `CompanyOAuthClient` rows; `GET /api/v1/settings?company_id=…` lists providers that have credentials for that company |

### IdP callback URL (Shellui flow)

Register **one** authorization callback on the IdP — the identity host, **no query string**:

| Environment | Callback URL |
| ----------- | ------------ |
| Local | `http://localhost:8000/api/v1/oauth/callback` |
| Production | `https://<identity-host>/api/v1/oauth/callback` |

django-allauth’s **default** callback pattern (when using stock allauth URLs) is `…/accounts/<provider>/login/callback/`. identity-service does **not** expose that path for the Shellui authorize flow; use the table above instead.

### Enabling a provider (operator checklist)

1. **Read the allauth provider page** linked from the [provider index](https://docs.allauth.org/en/latest/socialaccount/providers/index.html) (scopes, tenant IDs, SAML metadata, etc.).
2. **Install optional dependencies** called out on that page (for example SAML stacks, crypto, or provider-specific libraries). Add OS packages in your container image when allauth documents Debian requirements.
3. **Enable the provider module** in Django: add `allauth.socialaccount.providers.<provider_id>` to `INSTALLED_APPS` (see the provider page — identity-service ships with `github`, `google`, and `microsoft` only).
4. **Configure `SOCIALACCOUNT_PROVIDERS`** in settings when the provider page shows non-default scopes or endpoints (see `config/settings.py` for the stock three).
5. **Create credentials per company:** Django admin → Company → OAuth clients, or `POST /api/v1/admin/oauth-social-apps` + company mapping. Each IdP needs its own client id/secret (or SAML metadata) on a `SocialApp`.
6. **Allowlist shell origins** for token delivery (`CompanyOAuthRedirect`) — [OAuth login → Redirect allowlist](oauth-login.md#redirect-allowlist).

**Stock release wiring:** `GET /api/v1/authorize`, the method picker, and server-side code exchange are implemented for **`github`**, **`google`**, and **`microsoft`** only (`apps/authapi/oauth.py`). Additional allauth providers are **available in the library** but require extending that OAuth integration (and `SUPPORTED_OAUTH_PROVIDERS`) in a custom deploy or future release before they appear in the Shellui login UI. Lower-level APIs (`/api/v1/providers/<provider>/authorize/` and `/api/v1/providers/<provider>/login/`) follow the same provider allowlist today.

Listing a provider here is **not** a security or legal attestation for that IdP.

---

## Primary / recommended (common starters)

These are typical enterprise, consumer, and developer IdPs. Only **GitHub**, **Google**, and **Microsoft** are wired end-to-end in the stock image; the rest follow the same allauth + `SocialApp` pattern once your deploy enables the module and OAuth wiring.

| Provider | allauth id | Protocol | Notes |
| -------- | ---------- | -------- | ----- |
| Google | [`google`](https://docs.allauth.org/en/latest/socialaccount/providers/google.html) | OAuth 2 / OIDC | **Stock** — common consumer & Workspace |
| Microsoft | [`microsoft`](https://docs.allauth.org/en/latest/socialaccount/providers/microsoft.html) | OAuth 2 / OIDC | **Stock** — Entra ID (Azure AD) & personal accounts; set tenant on `SocialApp.settings` |
| GitHub | [`github`](https://docs.allauth.org/en/latest/socialaccount/providers/github.html) | OAuth 2 | **Stock** — developer teams |
| Apple | [`apple`](https://docs.allauth.org/en/latest/socialaccount/providers/apple.html) | OAuth 2 / OIDC | Sign in with Apple; extra Apple developer setup |
| GitLab | [`gitlab`](https://docs.allauth.org/en/latest/socialaccount/providers/gitlab.html) | OAuth 2 | Self-hosted or gitlab.com |
| Slack | [`slack`](https://docs.allauth.org/en/latest/socialaccount/providers/slack.html) | OAuth 2 | Workspace apps |
| Okta | [`okta`](https://docs.allauth.org/en/latest/socialaccount/providers/okta.html) | OAuth 2 / OIDC | Workforce IdP |
| Auth0 | [`auth0`](https://docs.allauth.org/en/latest/socialaccount/providers/auth0.html) | OAuth 2 / OIDC | Auth0 tenant |
| Keycloak | [`openid_connect`](https://docs.allauth.org/en/latest/socialaccount/providers/openid_connect.html) | OIDC | Configure Keycloak as an OpenID Connect provider (allauth Keycloak guide) |
| OpenID Connect | [`openid_connect`](https://docs.allauth.org/en/latest/socialaccount/providers/openid_connect.html) | OIDC | Generic OIDC IdPs |
| SAML | [`saml`](https://docs.allauth.org/en/latest/socialaccount/providers/saml.html) | SAML 2.0 | Enterprise SSO; often extra Python/XML dependencies |
| Discord | [`discord`](https://docs.allauth.org/en/latest/socialaccount/providers/discord.html) | OAuth 2 | Communities |
| Facebook | [`facebook`](https://docs.allauth.org/en/latest/socialaccount/providers/facebook.html) | OAuth 2 | Consumer login |
| LinkedIn | [`linkedin_oauth2`](https://docs.allauth.org/en/latest/socialaccount/providers/linkedin.html) | OAuth 2 / OIDC | Prefer OpenID Connect per [allauth LinkedIn](https://docs.allauth.org/en/latest/socialaccount/providers/linkedin.html); legacy module id `linkedin_oauth2` |
| Amazon Cognito | [`amazon_cognito`](https://docs.allauth.org/en/latest/socialaccount/providers/amazon_cognito.html) | OAuth 2 / OIDC | AWS user pools |

For **provisioning** (not social login), many teams pair OAuth with **[SCIM](scim.md)** for Okta, Entra ID, or similar directories.

---

## Also available (full django-allauth 65.14.1 catalog)

The tables below list provider modules shipped inside **django-allauth 65.14.1** (the version pinned in this repository). Primary starters above are omitted here to avoid duplication. Names follow the [official provider index](https://docs.allauth.org/en/latest/socialaccount/providers/index.html) where they differ from the Python package slug.

<details>
<summary><strong>Generic protocol adapters</strong></summary>

| Provider | allauth id | Protocol |
| -------- | ---------- | -------- |
| [OpenID](https://docs.allauth.org/en/latest/socialaccount/providers/openid.html) | `openid` | OpenID 2.0 |
| [OAuth 2 (generic)](https://docs.allauth.org/en/latest/socialaccount/providers/oauth2.html) | `oauth2` | OAuth 2 |

</details>

<details>
<summary><strong>Enterprise, education & workforce</strong></summary>

| Provider | allauth id | Protocol |
| -------- | ---------- | -------- |
| [Atlassian](https://docs.allauth.org/en/latest/socialaccount/providers/atlassian.html) | `atlassian` | OAuth 2 |
| [Authentiq](https://docs.allauth.org/en/latest/socialaccount/providers/authentiq.html) | `authentiq` | OAuth 2 |
| [Authelia](https://docs.allauth.org/en/latest/socialaccount/providers/authelia.html) | `authelia` | OAuth 2 |
| [Cilogon](https://docs.allauth.org/en/latest/socialaccount/providers/cilogon.html) | `cilogon` | OAuth 2 |
| [Clever](https://docs.allauth.org/en/latest/socialaccount/providers/clever.html) | `clever` | OAuth 2 |
| [Dataporten](https://docs.allauth.org/en/latest/socialaccount/providers/dataporten.html) | `dataporten` | OAuth 2 |
| [Edmodo](https://docs.allauth.org/en/latest/socialaccount/providers/edmodo.html) | `edmodo` | OAuth 2 |
| [Edx](https://docs.allauth.org/en/latest/socialaccount/providers/edx.html) | `edx` | OAuth 2 |
| [Globus](https://docs.allauth.org/en/latest/socialaccount/providers/globus.html) | `globus` | OAuth 2 |
| [JupyterHub](https://docs.allauth.org/en/latest/socialaccount/providers/jupyterhub.html) | `jupyterhub` | OAuth 2 |
| [LemonLDAP::NG](https://docs.allauth.org/en/latest/socialaccount/providers/lemonldap.html) | `lemonldap` | OAuth 2 |
| [Netiq](https://docs.allauth.org/en/latest/socialaccount/providers/netiq.html) | `netiq` | OAuth 2 |
| [Nextcloud](https://docs.allauth.org/en/latest/socialaccount/providers/nextcloud.html) | `nextcloud` | OAuth 2 |
| [ORCID](https://docs.allauth.org/en/latest/socialaccount/providers/orcid.html) | `orcid` | OAuth 2 |
| [Salesforce](https://docs.allauth.org/en/latest/socialaccount/providers/salesforce.html) | `salesforce` | OAuth 2 |
| [Sharefile](https://docs.allauth.org/en/latest/socialaccount/providers/sharefile.html) | `sharefile` | OAuth 2 |
| [Windows Live](https://docs.allauth.org/en/latest/socialaccount/providers/windowslive.html) | `windowslive` | OAuth 2 |
| [Zoho](https://docs.allauth.org/en/latest/socialaccount/providers/zoho.html) | `zoho` | OAuth 2 |
| [Cern](https://docs.allauth.org/en/latest/socialaccount/providers/cern.html) | `cern` | OAuth 2 |

</details>

<details>
<summary><strong>Developer tools & collaboration</strong></summary>

| Provider | allauth id | Protocol |
| -------- | ---------- | -------- |
| [Bitbucket](https://docs.allauth.org/en/latest/socialaccount/providers/bitbucket.html) | `bitbucket_oauth2` | OAuth 2 |
| [Box](https://docs.allauth.org/en/latest/socialaccount/providers/box.html) | `box` | OAuth 2 |
| [Dropbox](https://docs.allauth.org/en/latest/socialaccount/providers/dropbox.html) | `dropbox` | OAuth 2 |
| [Gitea](https://docs.allauth.org/en/latest/socialaccount/providers/gitea.html) | `gitea` | OAuth 2 |
| [Mediawiki](https://docs.allauth.org/en/latest/socialaccount/providers/mediawiki.html) | `mediawiki` | OAuth 2 |
| [Miro](https://docs.allauth.org/en/latest/socialaccount/providers/miro.html) | `miro` | OAuth 2 |
| [Notion](https://docs.allauth.org/en/latest/socialaccount/providers/notion.html) | `notion` | OAuth 2 |
| [Stackexchange](https://docs.allauth.org/en/latest/socialaccount/providers/stackexchange.html) | `stackexchange` | OAuth 2 |
| [Trello](https://docs.allauth.org/en/latest/socialaccount/providers/trello.html) | `trello` | OAuth 1 |
| [Zoom](https://docs.allauth.org/en/latest/socialaccount/providers/zoom.html) | `zoom` | OAuth 2 |

</details>

<details>
<summary><strong>Consumer, social & media</strong></summary>

| Provider | allauth id | Protocol |
| -------- | ---------- | -------- |
| [23andMe](https://docs.allauth.org/en/latest/socialaccount/providers/23andme.html) | `twentythreeandme` | OAuth 2 |
| [500px](https://docs.allauth.org/en/latest/socialaccount/providers/500px.html) | `fivehundredpx` | OAuth 2 |
| Angellist | `angellist` | OAuth 2 |
| Disqus | `disqus` | OAuth 2 |
| Douban | `douban` | OAuth 2 |
| [Flickr](https://docs.allauth.org/en/latest/socialaccount/providers/flickr.html) | `flickr` | OAuth 1 |
| Foursquare | `foursquare` | OAuth 2 |
| [Instagram](https://docs.allauth.org/en/latest/socialaccount/providers/instagram.html) | `instagram` | OAuth 2 |
| [Kakao](https://docs.allauth.org/en/latest/socialaccount/providers/kakao.html) | `kakao` | OAuth 2 |
| [Line](https://docs.allauth.org/en/latest/socialaccount/providers/line.html) | `line` | OAuth 2 |
| Meetup | `meetup` | OAuth 2 |
| [Odnoklassniki](https://docs.allauth.org/en/latest/socialaccount/providers/odnoklassniki.html) | `odnoklassniki` | OAuth 2 |
| [Pinterest](https://docs.allauth.org/en/latest/socialaccount/providers/pinterest.html) | `pinterest` | OAuth 2 |
| [Reddit](https://docs.allauth.org/en/latest/socialaccount/providers/reddit.html) | `reddit` | OAuth 2 |
| [Snapchat](https://docs.allauth.org/en/latest/socialaccount/providers/snapchat.html) | `snapchat` | OAuth 2 |
| [Soundcloud](https://docs.allauth.org/en/latest/socialaccount/providers/soundcloud.html) | `soundcloud` | OAuth 2 |
| Spotify | `spotify` | OAuth 2 |
| [Steam](https://docs.allauth.org/en/latest/socialaccount/providers/steam.html) | `steam` | OpenID |
| [Tiktok](https://docs.allauth.org/en/latest/socialaccount/providers/tiktok.html) | `tiktok` | OAuth 2 |
| Tumblr | `tumblr` | OAuth 2 |
| [Tumblr (OAuth 2)](https://docs.allauth.org/en/latest/socialaccount/providers/tumblr_oauth2.html) | `tumblr_oauth2` | OAuth 2 |
| [Twitch](https://docs.allauth.org/en/latest/socialaccount/providers/twitch.html) | `twitch` | OAuth 2 |
| [Untappd](https://docs.allauth.org/en/latest/socialaccount/providers/untappd.html) | `untappd` | OAuth 2 |
| [Vimeo](https://docs.allauth.org/en/latest/socialaccount/providers/vimeo.html) | `vimeo` | OAuth 1 |
| [Vimeo (OAuth 2)](https://docs.allauth.org/en/latest/socialaccount/providers/vimeo_oauth2.html) | `vimeo_oauth2` | OAuth 2 |
| [Vk](https://docs.allauth.org/en/latest/socialaccount/providers/vk.html) | `vk` | OAuth 2 |
| [Weibo](https://docs.allauth.org/en/latest/socialaccount/providers/weibo.html) | `weibo` | OAuth 2 |
| [Weixin (WeChat)](https://docs.allauth.org/en/latest/socialaccount/providers/weixin.html) | `weixin` | OAuth 2 |
| [X / Twitter (OAuth 1)](https://docs.allauth.org/en/latest/socialaccount/providers/twitter.html) | `twitter` | OAuth 1 |
| [X / Twitter (OAuth 2)](https://docs.allauth.org/en/latest/socialaccount/providers/twitter_oauth2.html) | `twitter_oauth2` | OAuth 2 |
| [Xing](https://docs.allauth.org/en/latest/socialaccount/providers/xing.html) | `xing` | OAuth 1 |
| [Yahoo](https://docs.allauth.org/en/latest/socialaccount/providers/yahoo.html) | `yahoo` | OAuth 2 |
| [Yandex](https://docs.allauth.org/en/latest/socialaccount/providers/yandex.html) | `yandex` | OAuth 2 |

</details>

<details>
<summary><strong>Commerce, finance & productivity</strong></summary>

| Provider | allauth id | Protocol |
| -------- | ---------- | -------- |
| [Amazon](https://docs.allauth.org/en/latest/socialaccount/providers/amazon.html) | `amazon` | OAuth 2 |
| Asana | `asana` | OAuth 2 |
| Coinbase | `coinbase` | OAuth 2 |
| [Dwolla](https://docs.allauth.org/en/latest/socialaccount/providers/dwolla.html) | `dwolla` | OAuth 2 |
| [Eventbrite](https://docs.allauth.org/en/latest/socialaccount/providers/eventbrite.html) | `eventbrite` | OAuth 2 |
| Feedly | `feedly` | OAuth 2 |
| [Feishu](https://docs.allauth.org/en/latest/socialaccount/providers/feishu.html) | `feishu` | OAuth 2 |
| [Figma](https://docs.allauth.org/en/latest/socialaccount/providers/figma.html) | `figma` | OAuth 2 |
| [Gumroad](https://docs.allauth.org/en/latest/socialaccount/providers/gumroad.html) | `gumroad` | OAuth 2 |
| [Hubspot](https://docs.allauth.org/en/latest/socialaccount/providers/hubspot.html) | `hubspot` | OAuth 2 |
| [Klaviyo](https://docs.allauth.org/en/latest/socialaccount/providers/klaviyo.html) | `klaviyo` | OAuth 2 |
| [Mailchimp](https://docs.allauth.org/en/latest/socialaccount/providers/mailchimp.html) | `mailchimp` | OAuth 2 |
| Mailru | `mailru` | OAuth 2 |
| [Patreon](https://docs.allauth.org/en/latest/socialaccount/providers/patreon.html) | `patreon` | OAuth 2 |
| [Paypal](https://docs.allauth.org/en/latest/socialaccount/providers/paypal.html) | `paypal` | OAuth 2 |
| [Pocket](https://docs.allauth.org/en/latest/socialaccount/providers/pocket.html) | `pocket` | OAuth 1 |
| [Questrade](https://docs.allauth.org/en/latest/socialaccount/providers/questrade.html) | `questrade` | OAuth 2 |
| [Quickbooks](https://docs.allauth.org/en/latest/socialaccount/providers/quickbooks.html) | `quickbooks` | OAuth 2 |
| Robinhood | `robinhood` | OAuth 2 |
| [Shopify](https://docs.allauth.org/en/latest/socialaccount/providers/shopify.html) | `shopify` | OAuth 2 |
| [Stocktwits](https://docs.allauth.org/en/latest/socialaccount/providers/stocktwits.html) | `stocktwits` | OAuth 2 |
| [Strava](https://docs.allauth.org/en/latest/socialaccount/providers/strava.html) | `strava` | OAuth 2 |
| [Stripe](https://docs.allauth.org/en/latest/socialaccount/providers/stripe.html) | `stripe` | OAuth 2 |
| [Trainingpeaks](https://docs.allauth.org/en/latest/socialaccount/providers/trainingpeaks.html) | `trainingpeaks` | OAuth 2 |
| [Ynab](https://docs.allauth.org/en/latest/socialaccount/providers/ynab.html) | `ynab` | OAuth 2 |

</details>

<details>
<summary><strong>Regional, specialty & other</strong></summary>

| Provider | allauth id | Protocol |
| -------- | ---------- | -------- |
| [Agave](https://docs.allauth.org/en/latest/socialaccount/providers/agave.html) | `agave` | OAuth 2 |
| [Baidu](https://docs.allauth.org/en/latest/socialaccount/providers/baidu.html) | `baidu` | OAuth 2 |
| [Basecamp](https://docs.allauth.org/en/latest/socialaccount/providers/basecamp.html) | `basecamp` | OAuth 2 |
| [Battlenet](https://docs.allauth.org/en/latest/socialaccount/providers/battlenet.html) | `battlenet` | OAuth 2 |
| Bitly | `bitly` | OAuth 2 |
| [Daum](https://docs.allauth.org/en/latest/socialaccount/providers/daum.html) | `daum` | OAuth 2 |
| [Digitalocean](https://docs.allauth.org/en/latest/socialaccount/providers/digitalocean.html) | `digitalocean` | OAuth 2 |
| [Dingtalk](https://docs.allauth.org/en/latest/socialaccount/providers/dingtalk.html) | `dingtalk` | OAuth 2 |
| [Discogs](https://docs.allauth.org/en/latest/socialaccount/providers/discogs.html) | `discogs` | OAuth 1 |
| [Doximity](https://docs.allauth.org/en/latest/socialaccount/providers/doximity.html) | `doximity` | OAuth 2 |
| [Draugiem](https://docs.allauth.org/en/latest/socialaccount/providers/draugiem.html) | `draugiem` | OAuth 2 |
| [Drip](https://docs.allauth.org/en/latest/socialaccount/providers/drip.html) | `drip` | OAuth 2 |
| [Eveonline](https://docs.allauth.org/en/latest/socialaccount/providers/eveonline.html) | `eveonline` | OAuth 2 |
| [Evernote](https://docs.allauth.org/en/latest/socialaccount/providers/evernote.html) | `evernote` | OAuth 1 |
| [Exist](https://docs.allauth.org/en/latest/socialaccount/providers/exist.html) | `exist` | OAuth 2 |
| [Firefox Accounts](https://docs.allauth.org/en/latest/socialaccount/providers/fxa.html) | `fxa` | OAuth 2 |
| [Frontier](https://docs.allauth.org/en/latest/socialaccount/providers/frontier.html) | `frontier` | OAuth 2 |
| Hubic | `hubic` | OAuth 2 |
| [Lichess](https://docs.allauth.org/en/latest/socialaccount/providers/lichess.html) | `lichess` | OAuth 2 |
| [Mailcow](https://docs.allauth.org/en/latest/socialaccount/providers/mailcow.html) | `mailcow` | OAuth 2 |
| [Naver](https://docs.allauth.org/en/latest/socialaccount/providers/naver.html) | `naver` | OAuth 2 |
| [Openstreetmap](https://docs.allauth.org/en/latest/socialaccount/providers/openstreetmap.html) | `openstreetmap` | OAuth 1 |
| [Telegram](https://docs.allauth.org/en/latest/socialaccount/providers/telegram.html) | `telegram` | Login widget |
| [Wahoo](https://docs.allauth.org/en/latest/socialaccount/providers/wahoo.html) | `wahoo` | OAuth 2 |

</details>
### Upstream index vs this pin

The [latest allauth provider index](https://docs.allauth.org/en/latest/socialaccount/providers/index.html) may document providers before they appear in a given release. This repository pins **django-allauth 65.14.1** — module lists above reflect that wheel. Upstream pages for **[Authelia](https://docs.allauth.org/en/latest/socialaccount/providers/authelia.html)**, **[CERN](https://docs.allauth.org/en/latest/socialaccount/providers/cern.html)**, and **[Klaviyo](https://docs.allauth.org/en/latest/socialaccount/providers/klaviyo.html)** are included in the enterprise/commerce tables for planning; upgrade django-allauth before enabling those modules.

Some package modules (for example `angellist`, `spotify`, `tumblr`) do not yet have dedicated upstream doc pages — use the [provider index](https://docs.allauth.org/en/latest/socialaccount/providers/index.html) and module source in the allauth package.

---

## See also

- [OAuth login](oauth-login.md) — Shellui authorize/callback flow, redirect allowlist, upgrades
- [Company access](company-access.md) — join modes after a successful login
- [Configuration](configuration.md) — environment variables and production checklist
