# identity-service documentation

Welcome to **Shellui identity-service** — a Django backend that provides Shellui-compatible authentication under `/api/v1/*`.

**Current docs target:** release **v0.7.0** (email-service delivery, event log, invitations, SAML SSO).

Live site: [https://docs.shellui.com/identity](https://docs.shellui.com/identity) · Project setup: [README.md](https://github.com/shellui/identity-service/blob/develop/README.md) on GitHub.

---

## v0.7.0 highlights

| Area | Summary |
| ---- | ------- |
| **[OAuth login](oauth-login.md)** | Identity-hosted authorize/callback, session-code vs legacy fragment delivery, redirect allowlist, company OAuth clients, hosting sync |
| **[Social login providers](oauth-providers.md)** | django-allauth catalog with 15 supported OAuth providers (Twitch, LinkedIn, Slack, OpenID Connect, Keycloak, Okta, Auth0, …), IdP callback URLs |
| **[SAML](saml.md)** | SAML 2.0 SSO with multiple IdPs per company, SP metadata, ACS, and optional SLO |
| **[SCIM](scim.md)** | Opt-in enterprise provisioning (Users + Groups + nested groups), per-company bearer tokens |
| **[Shellui webhooks](actions.md)** | Domain events → signed webhooks, DB outbox + `retry_webhooks` |
| **[Email](email-service.md)** | Magic links and invitations via email-service, SMTP fallback, event forwarding |
| **[Event log](event-log.md)** | Every event and sign-in in one table, per-company data retention, admin REST API |
| **[Scheduled jobs](scheduled-jobs.md)** | `purge_expired_data` (hourly) and `retry_webhooks` (every minute), with Coolify, Compose and Kubernetes examples |
| **[n8n integration](n8n.md)** | Webhook node setup, signature verification, retries |
| **[Configuration](configuration.md)** | JWT (`iss`/`aud`, RS256, HS256 legacy), CORS, `REDIS_URL`, Postgres timeouts, Gunicorn, `/health/live`, `SCIM_ENABLED`, `TRUSTED_PROXY_IPS`, token delivery |
| **[Company access](company-access.md)** | Public, domain, and invitation-only join modes after OAuth, plus email invitations |
| **[JWKS](jwks.md)** | RS256 signing and `/.well-known/jwks.json` |
| **[Security hardening](security-hardening.md)** | Rate limits, transport defaults, trusted proxies |
| **[Metrics](metrics.md)** | JWT and personal access token access to `/api/v1/metrics` |
| **[Releases](RELEASES.md)** | Docker Hub tags and publish checklist |

---

## Quick start (operators)

1. Copy [`.env.example`](https://github.com/shellui/identity-service/blob/develop/.env.example) and set `SECRET_KEY`, JWT keys, `JWT_ISSUER`, and `JWT_AUDIENCE` for production.
2. Point load balancers at **`GET /health/live`**.
3. Register IdP callbacks at `{identity-host}/api/v1/oauth/callback` and configure company redirect allowlists — [OAuth login](oauth-login.md).
4. For multi-worker production, set **`REDIS_URL`** — [Configuration](configuration.md).
5. For SCIM, run migrations and create a company SCIM token — [SCIM](scim.md).
6. Schedule `purge_expired_data` every hour and, if you use webhooks, `retry_webhooks` every minute: [Scheduled jobs](scheduled-jobs.md).

---

## Preview these docs locally

These pages are built and published by [shellui/shellui](https://github.com/shellui/shellui) as part of [docs.shellui.com](https://docs.shellui.com). The sidebar is `docs/sidebars.js` in this repository. To preview your edits with live reload, clone `shellui` next to this repository and run:

```bash
cd ../shellui
pnpm install
DOCS_SERVICES=identity pnpm docs:start
```

The site picks up `../identity-service/docs` and reloads as you edit. See [Build the docs site](https://github.com/shellui/shellui/blob/develop/docs/docs-site.md) for the other options.
