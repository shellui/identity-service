---
description: How maintainers cut an identity-service release, smoke test the image, and publish it to Docker Hub.
---

# Releases and Docker Hub

This page is for maintainers: how to cut an identity-service release and publish the `shellui/identity-service` image to [Docker Hub](https://hub.docker.com/). The canonical guide is [PUBLISH.md](https://github.com/shellui/identity-service/blob/main/PUBLISH.md) at the repository root. Operators upgrading a deployment should read the [Upgrade notes](upgrading.md) instead.

## Image overview

| Item | Value |
| --- | --- |
| Registry | Docker Hub |
| Repository | `shellui/identity-service` |
| Recommended tags | `0.7.0`, `0.7`, `latest` (see [Tagging](#tagging)) |
| Listen port | `8000` |
| Data volume | `/app/data` (SQLite default path: `/app/data/db.sqlite3`) |

The image contains the application code and collected static files only. Secrets and configuration come from environment variables at container start (see [Configuration](configuration.md)).

## 0.7.0 at a glance

0.7.0 has breaking changes: Redis is required in production, and magic link webhooks no longer carry the link. It also runs the scheduled jobs inside the container, and deprecates `/api/v1/login-events`. The steps are in [Upgrade to 0.7.0](upgrading.md#upgrade-to-070), and the full list in `CHANGELOG.md`.

## Pre-release checklist

Run the automated checklist, the same script as pull requests to `main`:

```bash
./tools/pre-release-check.sh
```

See [PUBLISH.md](https://github.com/shellui/identity-service/blob/main/PUBLISH.md) for options and the manual breakdown. In short:

### 1. Version alignment

These must match the release version (for example `0.7.0`):

- `version` in `pyproject.toml` (also the OpenAPI version, through `config.settings.VERSION`)
- the `CHANGELOG.md` entry, with its date
- green CI and pre-release workflows on the release commit
- the Git tag `v0.7.0` (recommended, not checked by the script)

The docs at [docs.shellui.com/identity](https://docs.shellui.com/identity) are built and published by [shellui/shellui](https://github.com/shellui/shellui), not by a tag in this repository. CI here only checks that `docs/` builds (the **Docs build** job in `.github/workflows/ci.yml`).

### 2. No secrets in the build context

```bash
# .env must not be tracked or copied into the image
test ! -f .env || grep -q '^\.env$' .gitignore
docker build -t shellui/identity-service:release-check .
docker run --rm --entrypoint sh shellui/identity-service:release-check \
  -c 'test ! -f /app/.env && echo "OK: .env not in image"'
```

`.dockerignore` excludes `.env`, `*.sqlite3`, `.git`, and local tooling files. Only `.env.example` is included, with placeholder values.

### 3. Smoke test the image

The script starts the image in production mode (`DEBUG=false`) next to a Redis container. To do it by hand:

```bash
eval "$(uv run python manage.py generate_jwt_keys --shell)"
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"

docker build -t shellui/identity-service:0.7.0 .
docker network create identity-smoke
docker run --rm -d --name identity-smoke-redis --network identity-smoke redis:8-alpine

docker run --rm -d --name identity-release-smoke --network identity-smoke -p 18000:8000 \
  -e SECRET_KEY \
  -e JWT_PRIVATE_KEY \
  -e JWT_ISSUER=https://auth.local \
  -e JWT_AUDIENCE=shellui \
  -e REDIS_URL=redis://identity-smoke-redis:6379/0 \
  -e SECURE_SSL_REDIRECT=false \
  -e ALLOWED_HOSTS=localhost,127.0.0.1 \
  shellui/identity-service:0.7.0

# 400 (missing company_id) proves gunicorn and Django are up
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18000/api/v1/settings

# JWKS must return at least one RSA key
curl -s http://127.0.0.1:18000/.well-known/jwks.json \
  | python3 -c "import sys,json; assert len(json.load(sys.stdin).get('keys',[]))>=1"

docker rm -f identity-release-smoke identity-smoke-redis
docker network rm identity-smoke
```

`SECURE_SSL_REDIRECT=false` is only there so `curl` can use plain HTTP. Keep it on in real deployments.

### 4. Multi-architecture build

On Apple Silicon, the default image is `linux/arm64` only, and most cloud VMs expect `linux/amd64`. Publish both with buildx:

```bash
docker buildx create --use --name multi 2>/dev/null || docker buildx use multi

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t shellui/identity-service:0.7.0 \
  --push .
```

## Tagging

For release `0.7.0`, publish these tags:

| Tag | Purpose |
| --- | --- |
| `0.7.0` | Exact release, pin it in production |
| `0.7` | Latest patch of the 0.7 line |
| `latest` | Newest release, use with care |

## Publish to Docker Hub

You need push access to the `shellui` organization on Docker Hub, `docker login`, and a clean Git tree at the release commit. There is no GitHub Actions workflow for the Docker publish yet: releases are manual.

From the repository root, build and push all tags for both platforms:

```bash
VERSION=0.7.0
IMAGE=shellui/identity-service

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t "${IMAGE}:${VERSION}" \
  -t "${IMAGE}:0.7" \
  -t "${IMAGE}:latest" \
  --push .

git tag -a "v${VERSION}" -m "Release ${VERSION}"
git push origin "v${VERSION}"
```

For a single-platform push from your machine, use `docker build` and `docker push "${IMAGE}:${VERSION}"`, then `docker tag` and push the other tags.

## Run the published image

The production checklist is in [Run identity-service](getting-started.md#deploy-to-production). A minimal production run looks like this:

```bash
docker run -d \
  --name identity-service \
  -p 8000:8000 \
  -v identity-service-data:/app/data \
  -e SECRET_KEY='your_secret_key_here' \
  -e JWT_PRIVATE_KEY='your_pem_private_key_here' \
  -e JWT_ISSUER='https://auth.example.com' \
  -e JWT_AUDIENCE='shellui' \
  -e REDIS_URL='redis://redis:6379/0' \
  -e ALLOWED_HOSTS='auth.example.com' \
  -e CSRF_TRUSTED_ORIGINS='https://auth.example.com' \
  -e POSTGRES_DATABASE_URL='postgres://user:password@db:5432/identity' \
  shellui/identity-service:0.7.0
```

OAuth credentials are stored per company in the database (Shellui admin, `POST /api/v1/oauth-social-apps`, or Django admin), not in environment variables. The entrypoint runs migrations on start, then starts gunicorn and the scheduled jobs as user `appuser`.

## Security notes

| Topic | Status |
| --- | --- |
| `.env` in the image | Excluded by `.dockerignore`, and checked by the pre-release script |
| `JWT_PRIVATE_KEY` | Provided at runtime, never baked into the image |
| JWKS endpoint | `/.well-known/jwks.json` exposes public keys only |
| Build-time `SECRET_KEY` | Used only for `collectstatic` during `docker build`. It shows in the build history as `build-only-not-for-runtime` and is not used at runtime |
| SQLite and database files | Excluded from the image. Use a volume or PostgreSQL |
| Process user | gunicorn and the worker run as `appuser`. The entrypoint may run brief setup as root |
| `DEBUG` | `false` in the Dockerfile. `docker-compose.yml` sets `true` for local runs |

Do not commit `.env` or real OAuth secrets. Do not pass secrets as Docker build arguments: they can appear in the image history.

## Known limitations

- No `HEALTHCHECK` in the Dockerfile. Point your orchestrator at `GET /health/live`
- No automated Docker Hub publish in CI
- SQLite on a volume is fine for a single-node trial. Use `POSTGRES_DATABASE_URL` in production
- Behind a TLS-terminating proxy, set `CSRF_TRUSTED_ORIGINS`; the app relies on `SECURE_PROXY_SSL_HEADER`

## Rollback

Pull and run a previous tag or digest:

```bash
docker pull shellui/identity-service:0.6.0
```

Data in the `identity-service-data` volume or PostgreSQL does not depend on the image tag. Migrations do not run backwards on their own, so test a downgrade before you rely on it.
