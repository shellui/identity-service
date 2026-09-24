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
runuser -u appuser -- python manage.py check --deploy
# Gunicorn 26 maps sync + --threads>1 to gthread; -k gthread makes that explicit in logs/ops.
exec runuser -u appuser -- gunicorn \
  --bind 0.0.0.0:8000 \
  --worker-class gthread \
  --workers "${GUNICORN_WORKERS:-4}" \
  --threads "${GUNICORN_THREADS:-4}" \
  --timeout "${GUNICORN_TIMEOUT:-60}" \
  config.wsgi:application
