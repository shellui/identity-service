# Publish and deploy

How to build, publish, and run the `shellui/identity-service` Docker image on [Docker Hub](https://hub.docker.com/r/shellui/identity-service).

Publishing is **manual** — there is no CI workflow for Docker Hub yet.

## Image overview

| Item        | Value                                                |
| ----------- | ---------------------------------------------------- |
| Registry    | Docker Hub                                           |
| Repository  | `shellui/identity-service`                           |
| Listen port | `8000`                                               |
| Data volume | `/app/data` (SQLite default: `/app/data/db.sqlite3`) |

The image contains application code and collected static files only. Secrets and runtime configuration are supplied via environment variables at container start (see `.env.example`).

## Pre-release checklist

Complete these steps **before** building and pushing a release tag.

### 1. Version alignment

Ensure these match the release version (e.g. `0.2.0`):

- `VERSION` in `config/settings.py` (OpenAPI / API metadata)
- `CHANGELOG.md` entry with date
- Git tag `v0.2.0` (optional but recommended)

### 2. No secrets in the build context

Confirm locally:

```bash
# .env must not be tracked or copied into the image
test ! -f .env || grep -q '^\.env$' .gitignore

docker build -t shellui/identity-service:release-check .
docker run --rm --entrypoint sh shellui/identity-service:release-check \
  -c 'test ! -f /app/.env && echo "OK: .env not in image"'
```

`.dockerignore` excludes `.env`, `*.sqlite3`, `.git`, and local tooling artifacts. Only `.env.example` is included (placeholders only).

### 3. Smoke test the image

```bash
export SECRET_KEY="$(python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())")"
export JWT_PRIVATE_KEY="$(python manage.py generate_jwt_keys 2>/dev/null | awk -F'\"' '/JWT_PRIVATE_KEY=/ {print $2}')"

VERSION=0.2.0
docker build -t "shellui/identity-service:${VERSION}" .

docker run --rm -d --name identity-release-smoke -p 18000:8000 \
  -e SECRET_KEY \
  -e JWT_PRIVATE_KEY \
  -e ALLOWED_HOSTS=localhost,127.0.0.1 \
  "shellui/identity-service:${VERSION}"

# Expect HTTP response (400 with company_id is fine — proves Gunicorn + Django are up)
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18000/api/v1/settings

# JWKS should return at least one RSA key
curl -s http://127.0.0.1:18000/.well-known/jwks.json | python -c "import sys,json; d=json.load(sys.stdin); assert len(d.get('keys',[]))>=1"

docker stop identity-release-smoke
```

## Publish to Docker Hub

### Prerequisites

1. Docker Hub account with push access to the `shellui` organization (or your namespace).
2. Docker CLI logged in:

```bash
docker login
```

3. Clean git tree at the commit you intend to release.

### Tagging

For semver release `0.2.0`, typical Docker Hub tags:

| Tag      | Purpose                                  |
| -------- | ---------------------------------------- |
| `0.2.0`  | Exact release (pin in production)        |
| `0.2`    | Latest patch in the 0.2 line             |
| `latest` | Newest published release (use with care) |

### Option A — single platform (fastest)

From the repository root:

```bash
VERSION=0.2.0
IMAGE=shellui/identity-service

docker build -t "${IMAGE}:${VERSION}" .
docker push "${IMAGE}:${VERSION}"

# Optional extra tags
docker tag "${IMAGE}:${VERSION}" "${IMAGE}:0.2"
docker tag "${IMAGE}:${VERSION}" "${IMAGE}:latest"
docker push "${IMAGE}:0.2"
docker push "${IMAGE}:latest"
```

### Option B — multi-arch (recommended for production)

If you build on Apple Silicon, a plain `docker build` may produce `linux/arm64` only. Most cloud VMs expect `linux/amd64`. Publish both with buildx:

```bash
VERSION=0.2.0
IMAGE=shellui/identity-service

docker buildx create --use --name multi 2>/dev/null || docker buildx use multi

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t "${IMAGE}:${VERSION}" \
  -t "${IMAGE}:latest" \
  --push .
```

### Git tag (recommended)

```bash
VERSION=0.2.0
git tag -a "v${VERSION}" -m "Release ${VERSION}"
git push origin "v${VERSION}"
```

## Deploy

Pull and run the published image:

```bash
docker volume create identity-service-data

docker run -d \
  --name identity-service \
  -p 8000:8000 \
  -v identity-service-data:/app/data \
  -e SECRET_KEY='replace-with-generated-key' \
  -e JWT_PRIVATE_KEY='replace-with-pem-from-generate_jwt_keys' \
  -e ALLOWED_HOSTS='auth.example.com' \
  -e CSRF_TRUSTED_ORIGINS='https://auth.example.com,https://app.example.com' \
  -e CORS_ALLOWED_ORIGINS='https://app.example.com' \
  shellui/identity-service:0.2.0
```

The entrypoint runs migrations on start, then starts Gunicorn as user `appuser`.

### Required runtime env vars (production)

| Variable               | Notes                                                                             |
| ---------------------- | --------------------------------------------------------------------------------- |
| `SECRET_KEY`           | Required; Django sessions/CSRF. Generate with `get_random_secret_key()`.          |
| `JWT_PRIVATE_KEY`      | Required when `DEBUG=false`; RS256 JWT signing. See [docs/jwks.md](docs/jwks.md). |
| `ALLOWED_HOSTS`        | Comma-separated hostnames, no scheme.                                             |
| `CSRF_TRUSTED_ORIGINS` | Full URLs with scheme when using browser flows behind HTTPS.                      |
| `CORS_ALLOWED_ORIGINS` | ShellUI / admin front-end origins.                                                |

### Optional runtime env vars

| Variable                     | Notes                           |
| ---------------------------- | ------------------------------- |
| `POSTGRES_DATABASE_URL`      | Use Postgres instead of SQLite. |
| `SENTRY_DSN`                 | Sentry error reporting.         |
| `SENTRY_ENVIRONMENT`         | e.g. `staging`, `production`.   |
| `JWT_ACCESS_TOKEN_LIFETIME`  | Default `5m`.                   |
| `JWT_REFRESH_TOKEN_LIFETIME` | Default `7d`.                   |

OAuth credentials are configured **per company** in the database (Django admin or `/api/v1/admin/oauth-social-apps`), not via container environment variables.

With Postgres:

```bash
-e POSTGRES_DATABASE_URL='postgres://user:pass@host:5432/dbname'
```

## Security notes

| Topic                     | Status                                                 |
| ------------------------- | ------------------------------------------------------ |
| `.env` in image           | Excluded via `.dockerignore`                           |
| Runtime `JWT_PRIVATE_KEY` | Must be provided in production; never baked into image |
| JWKS endpoint             | `/.well-known/jwks.json` exposes public keys only      |
| Build-time `SECRET_KEY`   | Used only for `collectstatic` during `docker build`    |
| SQLite / DB files         | Excluded from image; use volume or Postgres            |
| `DEBUG`                   | Defaults to `false` in Dockerfile                      |

Do not commit `.env` or real OAuth secrets to git. Do not pass secrets as Docker build args unless you accept they may appear in image history.

## Rollback

Pull and run a previous tag or digest:

```bash
docker pull shellui/identity-service:0.1.0
```

Data in `identity-service-data` (or Postgres) is independent of the image tag; test migrations when downgrading.
