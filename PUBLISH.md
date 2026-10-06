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

Complete these steps **before** building and pushing a release tag. Prefer the automated script (same checks run on PRs to `main`):

```bash
./tools/pre-release-check.sh
```

| Step              | What it verifies                                                                                                |
| ----------------- | --------------------------------------------------------------------------------------------------------------- |
| Version alignment | `pyproject.toml` version matches a dated `CHANGELOG.md` entry (`## [x.y.z] - YYYY-MM-DD`) and `uv.lock`         |
| Build secrets     | `.env` / `*.sqlite3` not tracked; `.gitignore` / `.dockerignore` exclude `.env`; built image has no `/app/.env` |
| Image smoke test  | Container serves `/api/v1/settings` and `/.well-known/jwks.json` with ≥1 RSA key                                |

Options: `--skip-docker` (version + git hygiene only), `--image TAG`, `--port PORT`.

GitHub Actions: [`.github/workflows/pre-release.yml`](.github/workflows/pre-release.yml) runs this script on every pull request targeting `main` (and via **workflow_dispatch**).

Manual equivalents (if you are not using the script):

### 1. Version alignment

Ensure these match the release version (e.g. `0.7.0`):

- `version` in `pyproject.toml` (OpenAPI / API metadata via `config.settings.VERSION`)
- `CHANGELOG.md` entry with date
- Git tag `v0.7.0` (optional but recommended; not enforced by the script)
- CI green on the release commit (`.github/workflows/ci.yml` + pre-release workflow)

### 2. No secrets in the build context

```bash
# .env must not be tracked or copied into the image
test ! -f .env || grep -qE '^\.env$' .gitignore

docker build -t shellui/identity-service:release-check .
docker run --rm --entrypoint sh shellui/identity-service:release-check \
  -c 'test ! -f /app/.env && echo "OK: .env not in image"'
```

`.dockerignore` excludes `.env`, `*.sqlite3`, `.git`, and local tooling artifacts. Only `.env.example` is included (placeholders only).

### 3. Smoke test the image

Covered by `./tools/pre-release-check.sh`. Manual form:

```bash
export SECRET_KEY="$(uv run python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())")"
eval "$(uv run python manage.py generate_jwt_keys --shell)"

VERSION=0.7.0
docker build -t "shellui/identity-service:${VERSION}" .

docker run --rm -d --name identity-release-smoke -p 18000:8000 \
  -e SECRET_KEY \
  -e JWT_PRIVATE_KEY \
  -e ALLOWED_HOSTS=localhost,127.0.0.1 \
  "shellui/identity-service:${VERSION}"

sleep 3
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18000/api/v1/settings
curl -s http://127.0.0.1:18000/.well-known/jwks.json | python -c "import sys,json; d=json.load(sys.stdin); assert len(d.get('keys',[]))>=1, d"
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

For semver release `0.7.0`, typical Docker Hub tags:

| Tag      | Purpose                                  |
| -------- | ---------------------------------------- |
| `0.7.0`  | Exact release (pin in production)        |
| `0.7`    | Latest patch in the 0.7 line             |
| `latest` | Newest published release (use with care) |

### Option A — single platform (fastest, not recommended, see option B)

From the repository root:

```bash
VERSION=0.7.0
IMAGE=shellui/identity-service

docker build -t "${IMAGE}:${VERSION}" .
docker push "${IMAGE}:${VERSION}"

# Optional extra tags
docker tag "${IMAGE}:${VERSION}" "${IMAGE}:0.7"
docker tag "${IMAGE}:${VERSION}" "${IMAGE}:latest"
docker push "${IMAGE}:0.7"
docker push "${IMAGE}:latest"
```

### Option B — multi-arch (recommended for production)

If you build on Apple Silicon, a plain `docker build` may produce `linux/arm64` only. Most cloud VMs expect `linux/amd64`. Publish both with buildx:

```bash
VERSION=0.7.0
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
VERSION=0.7.0
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
  -e REDIS_URL='redis://redis:6379/0' \
  shellui/identity-service:0.7.0
```

`REDIS_URL` is required: with `DEBUG=false` (the image default) the container logs `REDIS_URL is required when DEBUG is false (example: redis://redis:6379/0)` and exits with status 1 when it is missing. The container also runs the scheduled jobs (`retry_webhooks` every minute, `purge_expired_data` every hour) in a Celery worker next to gunicorn. There is no cron to set up. See [docs/scheduled-jobs.md](docs/scheduled-jobs.md) for a dedicated worker container (`worker` command) or `SCHEDULER_ENABLED=false`.

The entrypoint runs migrations on start, then starts **Gunicorn** (`config.wsgi:application`) as user `appuser`, not ASGI or uvicorn. Env vars `GUNICORN_WORKERS`, `GUNICORN_THREADS`, `GUNICORN_TIMEOUT`, `GUNICORN_GRACEFUL_TIMEOUT`, `GUNICORN_KEEP_ALIVE`, `GUNICORN_MAX_REQUESTS` and `GUNICORN_MAX_REQUESTS_JITTER` are passed through. The worker class is **`gthread`** (threaded sync workers). Access and error logs go to stdout, with the request duration and request id on each access log line.

**`GUNICORN_TIMEOUT` does not kill stuck `gthread` workers.** A worker keeps sending heartbeats while one of its threads is blocked, so gunicorn does not restart it. Per-request deadlines come from `EMAIL_TIMEOUT`, `POSTGRES_STATEMENT_TIMEOUT`, `POSTGRES_LOCK_TIMEOUT`, the OAuth HTTP timeouts, and a response timeout on the reverse proxy. See [docs/configuration.md](docs/configuration.md#gunicorn-docker-entrypoint).

**Concurrency:** with defaults after this release, up to `workers × threads` requests run at once (e.g. `4 × 4 = 16`). With `GUNICORN_WORKERS=2` and `GUNICORN_THREADS=2` you only get **four** concurrent handlers. OAuth callbacks and token refresh perform several DB writes and up to ~20s outbound HTTP each; when all handlers are busy, **even `GET /` queues** (session middleware + DB) until the client or reverse proxy times out — intermittent “hang then works again”.

**Liveness:** point health checks at `GET /health/live` (no session/DB). Do not use `/` or `/api/v1/settings` as the only probe if traffic is bursty.

**Immediate VPS tuning (no image change):** raise workers/threads (e.g. `GUNICORN_WORKERS=4`, `GUNICORN_THREADS=4`), use `POSTGRES_DATABASE_URL` for production load, and aim health checks at `/health/live`.

### Post-deploy production config check

After deploying a release (e.g. `0.7.0`), run the smoke script against the live HTTPS URL:

```bash
./tools/prod-config-check.sh https://id.shellui.com
./tools/prod-config-check.sh https://id.shellui.com --company-id 1
```

The script prints explicit `PASS:` / `FAIL:` / `WARN:` / `INFO:` lines and exits non-zero if any hard check fails. It verifies HTTPS reachability, JWKS (RSA keys present), pre-login `/api/v1/settings`, permissive CORS for preview origins, that `/` is not an open superuser signup form, and that `/api/v1/authorize` and `/api/v1/token` respond without server errors.

Optional environment:

| Variable               | Default                         |
| ---------------------- | ------------------------------- |
| `EXPECTED_JWT_ISSUER`  | Origin of the base URL          |
| `EXPECTED_JWT_AUDIENCE`| `shellui`                       |
| `COMPANY_ID`           | (none; use `--company-id` flag) |

Full OAuth login (fragment vs code delivery) cannot be verified without a configured IdP — the script prints guidance to set `OAUTH_TOKEN_DELIVERY=fragment` until Shellui #66.

### Required runtime env vars (production)

| Variable               | Notes                                                                             |
| ---------------------- | --------------------------------------------------------------------------------- |
| `SECRET_KEY`           | Required; Django sessions/CSRF. Generate with `get_random_secret_key()`.          |
| `JWT_PRIVATE_KEY`      | Required when `DEBUG=false`; RS256 JWT signing. See [docs/jwks.md](docs/jwks.md). |
| `ALLOWED_HOSTS`        | Comma-separated hostnames, no scheme.                                             |
| `CSRF_TRUSTED_ORIGINS` | Full URLs with scheme when using browser flows behind HTTPS.                      |
| `REDIS_URL`            | Required when `DEBUG=false`, also with `SCHEDULER_ENABLED=false`; the container refuses to start without it. Shared cache (rate limits, logout denylist, OAuth and SAML state) and broker for the scheduled jobs. Example: `redis://redis:6379/0`. |

### Optional runtime env vars

| Variable                     | Notes                                                                                          |
| ---------------------------- | ---------------------------------------------------------------------------------------------- |
| `JWT_ISSUER`, `JWT_AUDIENCE` | Required when `DEBUG=false`; issued tokens include `iss`/`aud`.                                |
| `JWT_ACCEPT_HS256_LEGACY`    | Default `false` in production with RS256; set `true` only during HS256 migration.              |
| `CORS_ALLOW_ALL_ORIGINS`     | Default `true` (permissive API CORS; Bearer JWT is the auth boundary). Set `false` to lock down. |
| `CORS_ALLOWED_ORIGINS`       | Used when `CORS_ALLOW_ALL_ORIGINS=false`; Shellui / admin front-end origins.                   |
| `CORS_ALLOW_CREDENTIALS`     | Default `false`; must stay `false` when allow-all is enabled.                                  |
| `POSTGRES_DATABASE_URL`      | Use Postgres instead of SQLite.                                                                |
| `SCHEDULER_ENABLED`          | Default `true`: the container runs the scheduled jobs next to gunicorn. Set `false` with a dedicated `worker` container or external cron. See [docs/scheduled-jobs.md](docs/scheduled-jobs.md). |
| `SENTRY_DSN`                 | Sentry error reporting.                                                                        |
| `SENTRY_ENVIRONMENT`         | e.g. `staging`, `production`.                                                                  |
| `JWT_ACCESS_TOKEN_LIFETIME`  | Default `5m`.                                                                                  |
| `JWT_REFRESH_TOKEN_LIFETIME` | Default `7d`.                                                                                  |
| `TRUSTED_PROXY_IPS`          | Comma-separated proxy IPs/CIDRs. When `REMOTE_ADDR` matches, client IP for rate limits and audit is the rightmost untrusted hop in `X-Forwarded-For`. Set this for Coolify, Traefik, or nginx ingress so clients cannot spoof the leftmost XFF entry. |
| `SELF_SERVICE_ACCOUNT_DELETE_MAX_IAT_AGE` | Default `5m`. Session access JWT `iat` window for `DELETE /api/v1/user`. |

OAuth credentials are configured **per company** in the database (Django admin or `/api/v1/admin/oauth-social-apps`), not via container environment variables.

With Postgres:

```bash
-e POSTGRES_DATABASE_URL='postgres://user:pass@host:5432/dbname'
```

### Redis (required in production)

Since 0.7.0, a production container (`DEBUG=false`) refuses to start without `REDIS_URL`: the entrypoint logs `REDIS_URL is required when DEBUG is false (example: redis://redis:6379/0)` and exits with status 1, before migrations. Auth rate limits, the logout access-token denylist, OAuth PKCE state and SAML replay protection rely on Django cache, and in-process LocMem is **not** shared between Gunicorn workers or containers. Redis is also the broker for the scheduled jobs (`retry_webhooks`, `purge_expired_data`), which the container runs on its own: no Coolify Scheduled Tasks to add.

1. Add a **Redis** service in Coolify (or run Redis on the VPS).
2. On the identity-service container, set **`REDIS_URL`** to the Redis connection URL, for example:
   - Same Coolify project, internal hostname: `redis://redis:6379/0`
   - Managed Redis with password: `redis://:password@host:6379/0`
3. Set it on every identity-service container (web and `worker`), also with `SCHEDULER_ENABLED=false` or `CELERY_BROKER_URL` set.
4. Redeploy identity-service. `manage.py check --deploy` reports `authapi.E004` when `REDIS_URL` is missing with `DEBUG=false`.

**Upgrading a deployment without Redis:** add the Redis service and `REDIS_URL` before you deploy 0.7.0, otherwise the new container does not start.

Only local development with `DEBUG=true` can leave `REDIS_URL` unset: the container logs a warning, serves the web app and does not run the scheduled jobs. See [docs/scheduled-jobs.md](docs/scheduled-jobs.md).

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
docker pull shellui/identity-service:0.2.0
```

Data in `identity-service-data` (or Postgres) is independent of the image tag; test migrations when downgrading.
