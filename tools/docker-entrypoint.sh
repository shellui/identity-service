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
#
# Note on --timeout: with gthread, the worker's main loop keeps sending heartbeats while
# a handler thread is blocked, so --timeout does NOT kill a worker whose threads are stuck
# on a slow call (SMTP, database, outbound HTTP). It only catches a frozen worker process.
# Per-request deadlines come from the app: EMAIL_TIMEOUT, POSTGRES_STATEMENT_TIMEOUT,
# POSTGRES_LOCK_TIMEOUT and the OAuth HTTP timeouts.
#
# --max-requests with jitter recycles workers over time, so a worker with a stuck thread
# that still serves other requests is eventually replaced (after --graceful-timeout).
# --worker-tmp-dir /dev/shm keeps the heartbeat file off the container disk, so disk
# pressure (for example an image build on the same host) cannot cause false timeouts.
# --keep-alive is above the reverse proxy idle time, so the proxy does not reuse a
# connection gunicorn is closing (that gives random 502s).
#
# Access log format: gunicorn default plus request duration in ms and the X-Request-ID
# returned by the app.
exec runuser -u appuser -- gunicorn \
  --bind 0.0.0.0:8000 \
  --worker-class gthread \
  --workers "${GUNICORN_WORKERS:-4}" \
  --threads "${GUNICORN_THREADS:-4}" \
  --timeout "${GUNICORN_TIMEOUT:-60}" \
  --graceful-timeout "${GUNICORN_GRACEFUL_TIMEOUT:-30}" \
  --keep-alive "${GUNICORN_KEEP_ALIVE:-75}" \
  --max-requests "${GUNICORN_MAX_REQUESTS:-1000}" \
  --max-requests-jitter "${GUNICORN_MAX_REQUESTS_JITTER:-200}" \
  --worker-tmp-dir /dev/shm \
  --access-logfile - \
  --error-logfile - \
  --access-logformat '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(M)sms req=%({x-request-id}o)s' \
  config.wsgi:application
