---
description: Run identity-service locally with Docker Compose, connect a Shellui app to it, and prepare a production deployment.
---

# Run identity-service

This page takes you from an empty folder to a working sign-in. You start identity-service locally with Docker Compose, create a company, connect a Shellui app, then go through the settings a production deployment needs.

## Start it locally

Docker Compose starts identity-service with `DEBUG=true`, SQLite, and a Redis container. You need Docker and Git:

```bash
git clone https://github.com/shellui/identity-service.git
cd identity-service
cp .env.example .env
```

Open `.env` and set `SECRET_KEY` to a long random value. Django uses it to sign sessions and CSRF tokens, and in local development it also signs the JWTs. To generate one:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(50))"
```

Then build and start the stack:

```bash
docker compose up --build
```

The container runs the database migrations, then serves on [http://localhost:8000](http://localhost:8000). Three pages are useful right away:

- **`/`**: on an empty database, a one-time form creates the first superuser (only while `DEBUG=true`)
- **`/admin/`**: Django admin, where operators manage companies, users, and provider apps
- **`/api/docs/`**: the interactive OpenAPI reference for every endpoint

To create the superuser from the command line instead:

```bash
docker compose exec -u appuser identity-service python manage.py createsuperuser
```

### Run without Docker

To work on the code, run identity-service with [uv](https://docs.astral.sh/uv/). With `DEBUG=true` and no `REDIS_URL`, it uses an in-process cache and skips the scheduled jobs:

```bash
uv sync
cp .env.example .env
uv run python manage.py migrate
uv run python manage.py runserver
```

## Create a company

Every sign-in belongs to a company (a tenant). In Django admin, open **Companies** and add one. Note its ID: the shell sends it as `company_id` on every sign-in.

New companies have magic link sign-in turned on. In local development, emails go to the console backend, so the sign-in link shows up in the container logs:

```bash
docker compose logs -f identity-service
```

Staff accounts, including the superuser you created, cannot sign in with a magic link: they get a notice instead of a link (see [Staff accounts](magic-link.md#staff-accounts)). Test magic links with a regular address, or sign in with OAuth.

To add OAuth, create an app at the provider with the callback URL `http://localhost:8000/api/v1/oauth/callback`, then add its client ID and secret in Shellui admin under **OAuth setup** (or with `POST /api/v1/oauth-social-apps`). [OAuth providers](oauth-providers.md) lists every supported provider and its settings.

## Connect your Shellui app

Point the shell at identity-service in `shellui.config.json`. `companyId` is the company you created, and `login` lists the methods the login page may offer:

```json
{
  "backend": {
    "type": "shellui",
    "url": "http://localhost:8000",
    "companyId": 1,
    "login": {
      "methods": ["magic_link", "oauth"],
      "oauthProviders": ["github"]
    }
  }
}
```

The shell intersects that list with what the company has enabled, read from `GET /api/v1/settings`. While `DEBUG=true`, identity-service accepts any loopback `redirect_to`, so a shell on `http://localhost:4000` works without more setup. Every other shell origin must be on the company redirect allowlist, see [OAuth login](oauth-login.md#redirect-allowlist). The shell side of this setup is described in [Connect a backend](https://docs.shellui.com/backend).

## Deploy to production

The Docker image defaults to `DEBUG=false` and refuses to start until the production settings are in place. Use the `shellui/identity-service` image with a pinned tag, for example `shellui/identity-service:0.7.0`.

:::warning Redis is required
With `DEBUG=false`, the container exits at startup when `REDIS_URL` is unset. Redis backs rate limits, the logout denylist, OAuth and SAML state, and the scheduled jobs.
:::

Set these variables before the first start:

| Variable | Value |
| --- | --- |
| `SECRET_KEY` | A long random value, kept secret |
| `JWT_PRIVATE_KEY` | RS256 private key, see below |
| `JWT_ISSUER` | Public HTTPS URL of identity-service, for example `https://auth.example.com` |
| `JWT_AUDIENCE` | `shellui`, or the audience your APIs expect |
| `ALLOWED_HOSTS` | Hostname of identity-service, for example `auth.example.com` |
| `CSRF_TRUSTED_ORIGINS` | `https://auth.example.com`, for Django admin and the sign-in pages |
| `REDIS_URL` | For example `redis://redis:6379/0` |
| `POSTGRES_DATABASE_URL` | Recommended. Without it, SQLite is stored in the `/app/data` volume |

Generate the signing key with the image itself. The command prints `JWT_PRIVATE_KEY` and `JWT_KEY_ID`:

```bash
docker run --rm -e SECRET_KEY=temporary \
  shellui/identity-service:0.7.0 python manage.py generate_jwt_keys
```

In a secret manager or the Coolify UI, paste only the PEM value, without the surrounding quotes. [JWT and JWKS](jwks.md) explains key formats and rotation.

Then finish the deployment:

1. Point the load balancer health check at `GET /health/live`. It does not touch the database.
2. Behind a reverse proxy, list the proxy addresses in `TRUSTED_PROXY_IPS` so rate limits see the real client IP.
3. Create the first superuser with `python manage.py createsuperuser` in the container.
4. Add each production shell origin to the company redirect allowlist.
5. Run `./tools/prod-config-check.sh https://auth.example.com` from a checkout to check the live configuration.

Every variable is described in [Configuration](configuration.md). The production defaults for HTTPS, cookies, and rate limits are in [Security hardening](security-hardening.md).

## Next steps

Once sign-in works, continue with the guide that matches your product:

- [Company access](company-access.md): restrict who can join, and send invitations
- [Webhooks](actions.md): call your automation when users join or leave
- [Scheduled jobs](scheduled-jobs.md): check the built-in jobs, or move them to their own container
