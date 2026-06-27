# identity-service

`identity-service` is a Django backend that provides authentication endpoints compatible with ShellUI (`backend.type = "shellui"`).

It supports OAuth login (GitHub/Google/Microsoft), issues JWT tokens, exposes Supabase-like auth routes under `/api/v1/*`, and returns user metadata that ShellUI can use (including avatar URL).

## Features

- ShellUI-compatible auth API at `/api/v1/*`
- OAuth login flow for GitHub, Google, Microsoft
- JWT access + refresh token issuance (RS256 with JWKS when `JWT_PRIVATE_KEY` is set)
- Token refresh endpoint (`grant_type=refresh_token`)
- User metadata endpoint (`/api/v1/user`)
- CORS for local ShellUI (`http://localhost:4000`), admin dev server (`http://localhost:5174`), hosted admin (`https://admin.shellui.com`), and optional extra origins via env `CORS_ALLOWED_ORIGINS` (comma-separated)
- OpenAPI docs with drf-spectacular

## Project Structure

- `src/config/` Django project settings and URL routing
- `src/apps/authapi/` authentication API and OAuth flow
- `src/apps/companies/` example business domain app

## Main Auth Endpoints

- `GET /.well-known/jwks.json` public JWKS for RS256 JWT verification (see [docs/jwks.md](docs/jwks.md))
- `GET /api/v1/settings` list enabled login methods/providers
- `GET /api/v1/authorize?provider=github&redirect_to=...` start OAuth redirect
- `GET /api/v1/oauth/callback` OAuth callback from provider
- `POST /api/v1/token?grant_type=refresh_token` refresh session using refresh token
- `POST /api/v1/logout` logout endpoint
- `GET /api/v1/user` return authenticated user profile + metadata
- `PUT /api/v1/user` update user metadata

## Staff admin endpoints

These routes require a valid JWT whose user has `is_staff=true` (`user_metadata.is_staff` is set from Django when tokens are issued).

- `GET /api/v1/users?q=&page=&page_size=` — paginated user list (`page_size` capped at 100)
- `GET /api/v1/users/<id>` — single user (Django fields + `user_metadata` cache)
- `PUT /api/v1/users/<id>` — JSON body may include `first_name`, `last_name`, `is_staff`, `is_active`, and optional `data` object to merge into cached metadata (same idea as `PUT /api/v1/user`). You cannot remove your own staff flag or deactivate yourself via this API.

## Quick Start

1. Create and activate a Python virtual environment.
2. Install dependencies:

```bash
cd src
pip install -r requirements.txt
```

3. Configure OAuth credentials per company (Django admin → Company → OAuth clients, or `POST /api/v1/admin/oauth-social-apps`):

```bash
# After starting the service, create a company and add GitHub/Google/Microsoft client id + secret
# for that company via the admin API or Django admin UI.
```

4. Run migrations and start server:

```bash
python manage.py migrate
python manage.py runserver
```

## JWT private key (RS256)

Production (`DEBUG=false`) requires an RSA private key for JWT signing. Local dev can skip this when `DEBUG=true` (HS256 with `SECRET_KEY`).

Generate a key pair and print suggested env vars:

```bash
python manage.py generate_jwt_keys
```

Copy the output into `.env` (or your secret manager). The private key must stay on one line with `\n` for newlines:

```bash
JWT_KEY_ID=abc123...
JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"
```

`JWT_PUBLIC_KEY` is optional (derived from the private key). Verifiers fetch the public key from `GET /.well-known/jwks.json` — see [docs/jwks.md](docs/jwks.md).

With Docker Compose, add `JWT_PRIVATE_KEY` to `.env` before running when `DEBUG=false`.

## ShellUI Frontend Config

In your ShellUI config (`shellui.config.ts`):

```ts
backend: {
  type: "shellui",
  url: "http://localhost:8000",
  login: {
    methods: ["oauth"],
    oauthProviders: ["github"]
  }
}
```

## OAuth App (GitHub) Values

- Homepage URL: `http://localhost:4000`
- Authorization callback URL: `http://localhost:8000/api/v1/oauth/callback`

## Notes

- `/api/v1/settings` only enables providers configured for the requested company.
- Avatar URL from provider userinfo is included in JWT metadata (`user_metadata.avatar_url`) for ShellUI profile display.

## Documentation (Docusaurus)

Project docs live in `docs/` and are built with Docusaurus config in `tools/docusaurus/`.

Generate docs:

```bash
./tools/generate-docs.sh
```

Output is generated in `tools/docusaurus/build`.

## Releases (Docker Hub)

See [docs/RELEASES.md](docs/RELEASES.md) for the pre-release checklist, tagging conventions, and steps to build and push `shellui/identity-service` to Docker Hub.

## Docker (local run)

Build image:

```bash
docker build -t shellui/identity-service:local .
```

Run container:

```bash
docker volume create identity-service-data
docker run --rm -p 8000:8000 \
  -v identity-service-data:/app/data \
  -e CORS_ALLOWED_ORIGINS="http://localhost:4000,http://localhost:5174" \
  --name identity-service \
  shellui/identity-service:local
```

The container runs migrations automatically, stores SQLite at `/app/data/db.sqlite3`, then starts with Gunicorn on `0.0.0.0:8000`. Production images run `collectstatic` at build time; [WhiteNoise](https://whitenoise.readthedocs.io/) serves `/admin/` and other collected static files from the app process (no separate static server required).

Runtime env vars:

- `SECRET_KEY` (required; Django sessions/CSRF — not used for JWT signing when `JWT_PRIVATE_KEY` is set)
- `JWT_PRIVATE_KEY` (required in production; RS256 private key PEM — generate with `python manage.py generate_jwt_keys`, see [JWT private key](#jwt-private-key-rs256))
- `JWT_PUBLIC_KEY`, `JWT_KEY_ID`, `JWT_PREVIOUS_PUBLIC_KEY`, `JWT_PREVIOUS_KEY_ID` (optional; see JWKS docs)
- `JWT_ACCEPT_HS256_LEGACY` (default `true`; set `false` after RS256 migration)
- `JWT_ACCESS_TOKEN_LIFETIME` (default `5m`; e.g. `30s`, `5m`, `2h` — bare integer = seconds)
- `JWT_REFRESH_TOKEN_LIFETIME` (default `7d`)
- `DEBUG` (default `false`)
- `ALLOWED_HOSTS` (comma-separated hostnames; empty → `localhost,127.0.0.1`)
- `CSRF_TRUSTED_ORIGINS` (comma-separated full URLs with scheme; empty → common local dev URLs including ShellUI ports)
- `POSTGRES_DATABASE_URL` (optional; when set, Postgres is used instead of SQLite)
- `GUNICORN_WORKERS` (default `2`)
- `GUNICORN_THREADS` (default `2`)
- `GUNICORN_TIMEOUT` (default `60`)

## Docker Compose (recommended local run)

```bash
cp .env.example .env
docker compose up --build
```

Stop:

```bash
docker compose down
```

Data persists in named volume `identity-service-data` (`/app/data/db.sqlite3` in container).