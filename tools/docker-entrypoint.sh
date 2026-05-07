#!/usr/bin/env sh
set -eu

SQLITE_FILE="${SQLITE_PATH:-/app/data/db.sqlite3}"
SQLITE_DIR="$(dirname "${SQLITE_FILE}")"

mkdir -p "${SQLITE_DIR}"
chown -R appuser:appuser "${SQLITE_DIR}"

if [ "${SQLITE_DIR}" = "/app/data" ] && [ -z "${POSTGRES_DATABASE_URL:-}" ]; then
  echo "INFO: For persistent data when using --rm, run with a named volume: -v identity-service-data:/app/data" >&2
fi

runuser -u appuser -- python manage.py migrate --noinput
exec runuser -u appuser -- gunicorn \
  --bind 0.0.0.0:8000 \
  --workers "${GUNICORN_WORKERS:-2}" \
  --threads "${GUNICORN_THREADS:-2}" \
  --timeout "${GUNICORN_TIMEOUT:-60}" \
  config.wsgi:application
