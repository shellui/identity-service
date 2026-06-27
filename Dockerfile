FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SQLITE_PATH=/app/data/db.sqlite3 \
    DEBUG=false

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

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
    python manage.py collectstatic --noinput --skip-checks

RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

VOLUME ["/app/data"]

EXPOSE 8000

ENTRYPOINT ["/app/tools/docker-entrypoint.sh"]
