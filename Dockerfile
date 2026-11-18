# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim AS frontend

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY assets ./assets
COPY templates ./templates
RUN npm run build:css

# Local dev stack (shellui/dev): deps in /opt/venv, source bind-mounted at /app.
FROM python:3.14-slim AS dev

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    SQLITE_PATH=/app/data/db.sqlite3 \
    DEBUG=true

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.12.1 /uv /uvx /bin/

COPY pyproject.toml uv.lock /app/
RUN uv sync --frozen --no-dev --no-install-project

COPY tools/docker-dev-entrypoint.sh /usr/local/bin/docker-dev-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-dev-entrypoint.sh

ENV PATH="/opt/venv/bin:$PATH"

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/docker-dev-entrypoint.sh"]

# Production image (default build target for publish and CI smoke tests).
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    SQLITE_PATH=/app/data/db.sqlite3 \
    DEBUG=false

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.12.1 /uv /uvx /bin/

COPY pyproject.toml uv.lock /app/
RUN uv sync --frozen --no-dev --no-install-project

COPY . /app
COPY --from=frontend /app/static/css/site.css /app/static/css/site.css

# Build-time only; runtime SECRET_KEY must be supplied via env (see .env.example).
# Coolify injects runtime env/build-args before this step — override them here so
# collectstatic does not load production JWT config or fail on compose "$" mangling.
RUN DEBUG=true \
    SECRET_KEY=build-only-not-for-runtime \
    JWT_PRIVATE_KEY= \
    JWT_PUBLIC_KEY= \
    JWT_PREVIOUS_PUBLIC_KEY= \
    JWT_ACCESS_TOKEN_LIFETIME=300 \
    JWT_REFRESH_TOKEN_LIFETIME=604800 \
    uv run python manage.py collectstatic --noinput --skip-checks

RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app \
    && chmod +x /app/tools/docker-entrypoint.sh

ENV PATH="/app/.venv/bin:$PATH"

VOLUME ["/app/data"]

EXPOSE 8000

# Coolify and Docker pick this up with no config. Worker mode passes (see the script).
# start-period covers migrations and check --deploy on first boot; start-interval
# probes every 5s during it, so a new deploy turns healthy quickly.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --start-interval=5s --retries=3 \
  CMD ["python", "/app/tools/healthcheck.py"]

ENTRYPOINT ["/app/tools/docker-entrypoint.sh"]
