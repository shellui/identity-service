---
title: identity-service
sidebar_label: Overview
description: identity-service is the Shellui authentication backend. It signs people in with OAuth, magic link, or SAML, issues JWTs, and manages companies, groups, SCIM provisioning, and webhooks.
---

import Link from '@docusaurus/Link';
import ProviderLogos from './_provider-logos.mdx';

# identity-service

<p style={{fontSize:'1.25rem',lineHeight:1.5,color:'var(--ifm-color-emphasis-700)',marginBottom:'1.5rem'}}>Sign-in, sessions, and company directories for your Shellui app, in one service you host.</p>

identity-service is the authentication backend for Shellui (`backend.type: "shellui"`). It signs people in with OAuth, a magic link, or SAML, issues the JSON Web Tokens (JWTs) your shell and APIs verify, and keeps each company's members, groups, and access rules. It is a Django app, published as the `shellui/identity-service` Docker image.

<div style={{display:'flex',flexWrap:'wrap',gap:'0.75rem',margin:'1.5rem 0 2rem'}}>
  <Link className="button button--primary button--lg" to="/identity/getting-started">Run identity-service</Link>
  <Link className="button button--secondary button--lg" to="/identity/oauth-login">See how sign-in works</Link>
</div>

## Sign-in providers

Each company picks its own sign-in methods and adds its own provider credentials in Shellui admin. Magic link sign-in works with no provider at all.

<ProviderLogos />

## What identity-service does

identity-service covers six areas. Each card opens the guide for that area.

<div className="row" style={{rowGap:'1rem',marginBottom:'1rem'}}>
  <div className="col col--6">
    <Link className="card padding--lg" to="/identity/oauth-login" style={{height:'100%',color:'inherit',textDecoration:'none'}}>
      <strong style={{fontSize:'1.05rem'}}>Sign people in</strong>
      <span style={{marginTop:'0.5rem',color:'var(--ifm-color-emphasis-700)'}}>OAuth and OpenID Connect providers, passwordless magic links, and SAML 2.0 single sign-on, behind one authorize endpoint.</span>
    </Link>
  </div>
  <div className="col col--6">
    <Link className="card padding--lg" to="/identity/jwks" style={{height:'100%',color:'inherit',textDecoration:'none'}}>
      <strong style={{fontSize:'1.05rem'}}>Issue tokens your APIs trust</strong>
      <span style={{marginTop:'0.5rem',color:'var(--ifm-color-emphasis-700)'}}>RS256 access tokens, rotating refresh tokens, and personal access tokens, verified against a public JWKS endpoint.</span>
    </Link>
  </div>
  <div className="col col--6">
    <Link className="card padding--lg" to="/identity/company-access" style={{height:'100%',color:'inherit',textDecoration:'none'}}>
      <strong style={{fontSize:'1.05rem'}}>Control who joins a company</strong>
      <span style={{marginTop:'0.5rem',color:'var(--ifm-color-emphasis-700)'}}>Public, email domain, or invitation-only access, with owners, groups, and email invitations.</span>
    </Link>
  </div>
  <div className="col col--6">
    <Link className="card padding--lg" to="/identity/scim" style={{height:'100%',color:'inherit',textDecoration:'none'}}>
      <strong style={{fontSize:'1.05rem'}}>Provision from a directory</strong>
      <span style={{marginTop:'0.5rem',color:'var(--ifm-color-emphasis-700)'}}>SCIM 2.0 users and nested groups from Okta, Microsoft Entra ID, and other identity providers, one token per company.</span>
    </Link>
  </div>
  <div className="col col--6">
    <Link className="card padding--lg" to="/identity/actions" style={{height:'100%',color:'inherit',textDecoration:'none'}}>
      <strong style={{fontSize:'1.05rem'}}>React to identity events</strong>
      <span style={{marginTop:'0.5rem',color:'var(--ifm-color-emphasis-700)'}}>Signed webhooks for user, group, and SCIM events, an event log with retention, and email through email-service.</span>
    </Link>
  </div>
  <div className="col col--6">
    <Link className="card padding--lg" to="/identity/scheduled-jobs" style={{height:'100%',color:'inherit',textDecoration:'none'}}>
      <strong style={{fontSize:'1.05rem'}}>Run it in production</strong>
      <span style={{marginTop:'0.5rem',color:'var(--ifm-color-emphasis-700)'}}>One Docker image with built-in scheduled jobs, rate limits, a liveness probe, and Prometheus metrics.</span>
    </Link>
  </div>
</div>

## How sign-in works

A Shellui shell never talks to a provider directly. identity-service runs the whole flow and returns tokens to the shell:

1. The shell sends the browser to `GET /api/v1/authorize` with `company_id` and `redirect_to`.
2. identity-service redirects to the provider named in `provider`, or shows the company's providers to pick from when it is not set.
3. The provider returns to `/api/v1/oauth/callback`. identity-service exchanges the code server-side and applies the company access rules.
4. identity-service redirects to `redirect_to?shellui_auth_code=…`, an origin on the company allowlist.
5. The shell exchanges that one-time code at `POST /api/v1/oauth/session` for an access token and a refresh token.

Your own APIs verify the access token with the public keys at `/.well-known/jwks.json`, without sharing any secret with identity-service. Details are in [OAuth login](oauth-login.md) and [JWT and JWKS](jwks.md).

## Find your guide

Pick the row that matches what you are doing today:

| You want to | Start with |
| --- | --- |
| Deploy identity-service with Docker and Redis | [Run identity-service](getting-started.md), then [Configuration](configuration.md) |
| Add Google, GitHub, Microsoft, or another provider | [OAuth providers](oauth-providers.md) |
| Let people sign in without a provider | [Magic link](magic-link.md) |
| Connect a company's Okta or Entra ID | [SAML single sign-on](saml.md) and [SCIM provisioning](scim.md) |
| Restrict who can join a company | [Company access](company-access.md) |
| Verify Shellui tokens in another service | [JWT and JWKS](jwks.md) |
| Run automation when users join or leave | [Webhooks](actions.md) and [n8n](n8n.md) |
| Audit sign-ins and changes | [Event log](event-log.md) |
| Harden a production install | [Security hardening](security-hardening.md) |
| Upgrade from an older release | [Upgrade notes](upgrading.md) |

## Endpoints at a glance

These are the endpoints you meet first. The full, interactive reference is served by each install at `/api/docs/` (OpenAPI).

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/settings?company_id=…` | Sign-in methods and providers enabled for a company |
| `GET /api/v1/authorize` | Start a sign-in |
| `POST /api/v1/oauth/session` | Exchange the one-time `shellui_auth_code` for tokens |
| `POST /api/v1/token?grant_type=refresh_token` | Refresh a session |
| `GET /api/v1/user` | Current user profile and `user_metadata` |
| `GET /.well-known/jwks.json` | Public keys for token verification |
| `GET /health/live` | Liveness probe for load balancers |

## Release and source

These docs describe identity-service **0.7.0**. Source, issues, and the changelog are on [GitHub](https://github.com/shellui/identity-service). Release tags and the Docker publish steps are in [Releases](RELEASES.md).

These pages are built from the `docs/` folder of the repository by [shellui/shellui](https://github.com/shellui/shellui) and published on [docs.shellui.com](https://docs.shellui.com). To preview an edit with live reload, clone `shellui` next to `identity-service` and run:

```bash
cd ../shellui
pnpm install
DOCS_SERVICES=identity pnpm docs:start
```
