# syntax=docker/dockerfile:1
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

ENTRYPOINT ["/app/tools/docker-entrypoint.sh"]
