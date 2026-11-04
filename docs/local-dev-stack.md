---
description: Run identity-service in the Shellui sibling-repo dev stack (shellui/dev).
---

# Local dev stack

The shared compose file lives in **shellui/shellui** at `dev/docker-compose.yml`. Clone identity-service next to that repo (see the dev stack contract). The compose file builds this service with `target: dev`, bind-mounts the repo at `/app`, and maps host port **8001** to container port **8000**.

Start the full stack from shellui:

```bash
cd shellui/dev
cp .env.local.example .env.local   # once
docker compose --env-file .env.local up
```

Start only identity (Postgres and Redis must already be running on the compose network):

```bash
cd shellui/dev
docker compose --env-file .env.local up identity
```

The **dev** image target installs Python dependencies under `/opt/venv` (outside `/app`), runs migrations, then `python manage.py runserver 0.0.0.0:8000` with autoreload. Set `DEBUG=true`. The production Dockerfile stage is unchanged and remains the default for publish and CI.

## Public vs internal URLs

Browser-facing URLs and JWT issuers use **localhost** and the published host ports. Outbound HTTP from this container uses compose **service names** on port **8000**.

| Purpose | Example value |
| --- | --- |
| `JWT_ISSUER` (public `iss`, OAuth, magic links) | `http://localhost:8001` |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,identity` |
| `CSRF_TRUSTED_ORIGINS` | `http://localhost:8001,http://localhost:5173,http://localhost:5174,http://localhost:5175` |
| `EMAIL_SERVICE_URL` (MCP `list_services`, docs) | `http://localhost:8004` |
| `EMAIL_SERVICE_INTERNAL_URL` (send API, company deletion) | `http://email:8000` |
| `STORAGE_SERVICE_URL` / `STORAGE_SERVICE_INTERNAL_URL` | `http://localhost:8002` / `http://storage:8000` |
| `HOSTING_SERVICE_URL` / `HOSTING_SERVICE_INTERNAL_URL` | `http://localhost:8003` / `http://hosting:8000` |
| `SAAS_SERVICE_URL` | `http://localhost:8005` |
| `AI_SERVICE_URL` / `AI_SERVICE_JWKS_URL` | `http://localhost:8006` / `http://ai:8000/.well-known/jwks.json` |

When an `*_INTERNAL_URL` variable is unset, the matching public URL is used (production behaviour).

Other services fetch this server's JWKS over the internal network, for example `http://identity:8000/.well-known/jwks.json`, while `JWT_ISSUER` stays `http://localhost:8001`.

## Variables in shellui `dev/.env.local`

Compose prefixes clash-prone secrets in `.env.local.example` (for example `IDENTITY_SECRET_KEY`). Map them to the names this app reads (`SECRET_KEY`, and so on). Typical identity entries:

| `.env.local` name | Container env | Example |
| --- | --- | --- |
| `IDENTITY_SECRET_KEY` | `SECRET_KEY` | generated |
| `IDENTITY_DEBUG` | `DEBUG` | `true` |
| `IDENTITY_JWT_ISSUER` | `JWT_ISSUER` | `http://localhost:8001` |
| `IDENTITY_JWT_AUDIENCE` | `JWT_AUDIENCE` | `shellui` |
| `IDENTITY_JWT_PRIVATE_KEY` | `JWT_PRIVATE_KEY` | empty with `DEBUG=true` (HS256) or RS256 PEM |
| `IDENTITY_POSTGRES_DATABASE_URL` | `POSTGRES_DATABASE_URL` | `postgres://postgres:postgres@postgres:5432/identity` |
| `IDENTITY_REDIS_URL` | `REDIS_URL` | `redis://redis:6379/0` |
| `IDENTITY_EMAIL_SERVICE_URL` | `EMAIL_SERVICE_URL` | `http://localhost:8004` |
| `IDENTITY_EMAIL_SERVICE_INTERNAL_URL` | `EMAIL_SERVICE_INTERNAL_URL` | `http://email:8000` |
| `IDENTITY_EMAIL_SERVICE_API_KEY` | `EMAIL_SERVICE_API_KEY` | optional for Mailpit-only flows |
| `IDENTITY_ALLOWED_HOSTS` | `ALLOWED_HOSTS` | `localhost,127.0.0.1,identity` |
| `IDENTITY_CSRF_TRUSTED_ORIGINS` | `CSRF_TRUSTED_ORIGINS` | see table above |

Optional service URLs for MCP and company deletion follow the public/internal split in the table. Region or global instance roles need the same extra settings as production; see [Instance roles](instance-roles.md).

With `DEBUG=true`, `REDIS_URL` is recommended (rate limits and OAuth state) but not required; the dev entrypoint does not start Gunicorn or the Celery scheduler. For scheduled jobs locally, set `REDIS_URL` and run the production image in `web` mode, or use the repo's `docker-compose.yml`.

## Standalone compose in this repo

`docker-compose.yml` at the repo root builds the **production** image and is aimed at a single-service try-out. Prefer the shellui dev stack when working across services. See [Configuration](configuration.md) for every variable.
