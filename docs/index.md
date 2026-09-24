# identity-service documentation

Welcome to **Shellui identity-service** — a Django backend that provides Shellui-compatible authentication under `/api/v1/*`.

**Current docs target:** release **v0.6.0** on **`develop`** (Redis shared cache, enterprise SCIM).

Live site: [https://identity.docs.shellui.com](https://identity.docs.shellui.com) · Project setup: [README.md](https://github.com/shellui/identity-service/blob/develop/README.md) on GitHub.

---

## v0.6.0 highlights

| Area | Summary |
| ---- | ------- |
| **[OAuth login](oauth-login.md)** | Identity-hosted authorize/callback, session-code vs legacy fragment delivery, redirect allowlist, company OAuth clients, hosting sync |
| **[SCIM](scim.md)** | Opt-in enterprise provisioning (Users + Groups + nested groups), per-company bearer tokens |
| **[Configuration](configuration.md)** | JWT (`iss`/`aud`, RS256, HS256 legacy), CORS, `REDIS_URL`, Postgres timeouts, Gunicorn, `/health/live`, `SCIM_ENABLED`, `TRUSTED_PROXY_IPS`, token delivery |
| **[Company access](company-access.md)** | Public, domain, and invitation-only join modes after OAuth |
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
5. For SCIM, set `SCIM_ENABLED=true` and run migrations — [SCIM](scim.md).

---

## Preview these docs locally

From the repository root:

```bash
cd tools/docusaurus
npm install
npm start
```

Open the URL printed by Docusaurus (default `http://localhost:3000`).
