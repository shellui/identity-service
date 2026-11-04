#!/usr/bin/env bash
# Local dev stack entrypoint (Dockerfile target: dev).
#
# Bind-mounts replace /app at runtime; dependencies live in /opt/venv so the mount
# does not hide them. Runs migrations, then Django runserver with autoreload.
set -euo pipefail

cd /app

if [ -n "${POSTGRES_DATABASE_URL:-}" ]; then
  : # Postgres from compose
elif [ -n "${SQLITE_PATH:-}" ]; then
  sqlite_dir="$(dirname "${SQLITE_PATH}")"
  mkdir -p "${sqlite_dir}"
fi

python manage.py migrate --noinput
exec python manage.py runserver 0.0.0.0:8000
