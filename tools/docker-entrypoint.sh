#!/usr/bin/env bash
# Container entrypoint.
#
# Modes (first argument, default "web"):
#   web     migrate, then gunicorn plus the scheduler (Celery worker and beat)
#   worker  only the scheduler (worker and beat); for a dedicated worker container
#   other   run the given command as appuser, for example: python manage.py shell
#
# Production (DEBUG false, the image default) requires REDIS_URL in web and worker modes:
# without it the entrypoint logs an error and exits 1 before migrations. Redis backs the
# shared cache (rate limits, logout denylist, OAuth PKCE state, SAML replay protection)
# and the scheduled jobs, so it is required even with SCHEDULER_ENABLED=false. The same
# rule is the authapi.E004 deploy check, run below by `check --deploy`.
# With DEBUG=true (local development), Redis stays optional: without it the web app runs
# alone and logs a warning.
#
# The scheduler needs REDIS_URL (or CELERY_BROKER_URL). Set SCHEDULER_ENABLED=false to
# keep it out of the web container. See docs/scheduled-jobs.md.
#
# Supervision: gunicorn, the Celery worker, and Celery beat run as children of this
# script (web mode). A SIGTERM or SIGINT is forwarded to all of them, and if any one
# exits the others are stopped and the container exits with that status, so Docker or
# Coolify restarts it. Beat is a process of its own, not a child of the worker, so a
# Beat crash restarts the container.
set -euo pipefail

MODE="${1:-web}"
if [ "$#" -gt 0 ]; then
  shift
fi

APP_USER="${APP_USER:-appuser}"

log() {
  echo "entrypoint: $*" >&2
}

# Prefix that runs a command as appuser. setpriv execs the command directly, so it
# receives signals itself. runuser forks and SIGKILLs the child 2 seconds after a
# SIGTERM, which cuts graceful shutdown short.
AS_APP=(
  setpriv --reuid="${APP_USER}" --regid="${APP_USER}" --init-groups --
  env HOME="/home/${APP_USER}" USER="${APP_USER}"
)

# Same truthy values as config/settings.py (surrounding whitespace ignored).
is_true() {
  case "$(printf '%s' "${1:-}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in
    1 | true | yes | on) return 0 ;;
    *) return 1 ;;
  esac
}

# Set and not only whitespace (settings strips it).
is_set() {
  [ -n "$(printf '%s' "${1:-}" | tr -d '[:space:]')" ]
}

broker_configured() {
  is_set "${CELERY_BROKER_URL:-}" || is_set "${REDIS_URL:-}"
}

# DEBUG defaults to false, like config/settings.py (the image sets DEBUG=false).
require_redis_in_production() {
  if is_true "${DEBUG:-false}" || is_set "${REDIS_URL:-}"; then
    return 0
  fi
  log "ERROR: REDIS_URL is required when DEBUG is false (example: redis://redis:6379/0)."
  log "ERROR: Redis backs the shared cache, OAuth and SAML state and the scheduled jobs, so it is required also with SCHEDULER_ENABLED=false or CELERY_BROKER_URL set."
  log "ERROR: Add a Redis service and set REDIS_URL, or set DEBUG=true for local development only. See docs/configuration.md."
  exit 1
}

prepare_data_dir() {
  local sqlite_file sqlite_dir
  sqlite_file="${SQLITE_PATH:-/app/data/db.sqlite3}"
  sqlite_dir="$(dirname "${sqlite_file}")"
  mkdir -p "${sqlite_dir}"
  chown -R "${APP_USER}:${APP_USER}" "${sqlite_dir}"
  if [ "${sqlite_dir}" = "/app/data" ] && [ -z "${POSTGRES_DATABASE_URL:-}" ]; then
    log "INFO: For persistent data when using --rm, run with a named volume: -v identity-service-data:/app/data"
  fi
}

gunicorn_cmd() {
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
  # Access log format: method, path WITHOUT the query string (%(U)s), protocol, status,
  # size, user agent, duration in ms and the X-Request-ID returned by the app.
  # Never log the full request line (%(r)s), the query string (%(q)s) or the Referer
  # (%(f)s): they carry magic-link tokens, OAuth codes, confirm_token and setup_token.
  GUNICORN_ARGS=(
    gunicorn
    --bind 0.0.0.0:8000
    --worker-class gthread
    --workers "${GUNICORN_WORKERS:-4}"
    --threads "${GUNICORN_THREADS:-4}"
    --timeout "${GUNICORN_TIMEOUT:-60}"
    --graceful-timeout "${GUNICORN_GRACEFUL_TIMEOUT:-30}"
    --keep-alive "${GUNICORN_KEEP_ALIVE:-75}"
    --max-requests "${GUNICORN_MAX_REQUESTS:-1000}"
    --max-requests-jitter "${GUNICORN_MAX_REQUESTS_JITTER:-200}"
    --worker-tmp-dir /dev/shm
    --access-logfile -
    --logger-class config.safe_access_log.SafeAccessLogger
    --error-logfile -
    --access-logformat '%(h)s %(l)s %(u)s %(t)s "%(m)s %(U)s %(H)s" %(s)s %(b)s "%(a)s" %(M)sms req=%({x-request-id}o)s'
    config.wsgi:application
  )
}

# Marker read by tools/healthcheck.py: worker mode has no HTTP server.
WORKER_MODE_MARKER="/tmp/identity-worker-mode"

worker_cmd() {
  # One worker process with a small thread pool. Threads keep memory low: a purge run
  # (up to 5 minutes) never blocks webhook retries with the default concurrency of 2.
  # --quiet drops the startup banner, which prints the broker URL.
  WORKER_ARGS=(
    celery -A config --quiet worker
    --pool threads
    --concurrency "${CELERY_WORKER_CONCURRENCY:-2}"
    --hostname "identity-service@%h"
    --without-gossip
    --without-mingle
    --without-heartbeat
  )
}

beat_cmd() {
  # In-memory scheduler: no shelve or dbm schedule file. On Python 3.13 and later the
  # default PersistentScheduler uses dbm.sqlite3, which can crash Beat with
  # "locking protocol" while the worker stays up, so the container looks healthy
  # after jobs have stopped. The schedule lives in CELERY_BEAT_SCHEDULE, so a restart
  # starts a fresh run from those definitions.
  # --quiet drops the startup banner, which prints the broker URL.
  BEAT_ARGS=(
    celery -A config --quiet beat
    --scheduler celery.beat.Scheduler
  )
}

start_scheduler_processes() {
  worker_cmd
  beat_cmd
  log "starting Celery worker"
  "${AS_APP[@]}" "${WORKER_ARGS[@]}" &
  PIDS+=("$!")
  log "starting Celery beat"
  "${AS_APP[@]}" "${BEAT_ARGS[@]}" &
  PIDS+=("$!")
}

PIDS=()
STOP_SIGNAL=""

stop_children() {
  local pid
  for pid in "${PIDS[@]}"; do
    kill -TERM "${pid}" 2>/dev/null || true
  done
}

# Reap children after SIGTERM. Celery beat can ignore or delay SIGTERM (for
# example a non-daemon telemetry thread), which would hang `wait` until Docker
# SIGKILLs the container (exit 137). After a short grace period, SIGKILL any
# process that is still running so the container can exit 0 on a clean stop.
reap_or_kill() {
  local grace=8
  # Optional test hook (plain expansion, not a documented setting).
  if [ -n "${STOP_GRACE_SECONDS}" ]; then
    grace="${STOP_GRACE_SECONDS}"
  fi
  local pid still
  local deadline=$((SECONDS + grace))
  while true; do
    still=0
    for pid in "${PIDS[@]}"; do
      if kill -0 "${pid}" 2>/dev/null; then
        still=1
        break
      fi
    done
    if [ "${still}" -eq 0 ]; then
      break
    fi
    if [ "${SECONDS}" -ge "${deadline}" ]; then
      for pid in "${PIDS[@]}"; do
        if kill -0 "${pid}" 2>/dev/null; then
          log "process ${pid} did not stop, sending SIGKILL"
          kill -KILL "${pid}" 2>/dev/null || true
        fi
      done
      break
    fi
    sleep 0.2
  done
  wait "${PIDS[@]}" 2>/dev/null || true
}

on_signal() {
  STOP_SIGNAL="$1"
  log "received ${STOP_SIGNAL}, stopping"
  stop_children
}

# Run with the commands already started in PIDS: forward SIGTERM and SIGINT, and exit as
# soon as one of them exits.
supervise() {
  trap 'on_signal SIGTERM' TERM
  trap 'on_signal SIGINT' INT

  local status=0
  set +e
  # Returns when the first child exits, or early when a trapped signal arrives.
  wait -n "${PIDS[@]}"
  status=$?
  stop_children
  reap_or_kill
  set -e
  if [ -n "${STOP_SIGNAL}" ]; then
    log "stopped"
    exit 0
  fi
  log "a process exited with status ${status}, stopping the container"
  if [ "${status}" -eq 0 ]; then
    status=1
  fi
  exit "${status}"
}

case "${MODE}" in
  web)
    require_redis_in_production
    prepare_data_dir
    "${AS_APP[@]}" python manage.py migrate --noinput
    "${AS_APP[@]}" python manage.py check --deploy
    gunicorn_cmd

    start_scheduler=false
    if ! is_true "${SCHEDULER_ENABLED:-true}"; then
      log "SCHEDULER_ENABLED=false: scheduled jobs are not started in this container."
    elif ! broker_configured; then
      # Only reachable with DEBUG=true: production already exited above.
      log "WARNING: REDIS_URL is not set (DEBUG=true), so scheduled jobs (retry_webhooks, purge_expired_data) are not running."
      log "WARNING: Set REDIS_URL to run them in this container. It is required when DEBUG is false. See docs/scheduled-jobs.md."
    else
      start_scheduler=true
    fi

    if [ "${start_scheduler}" = false ]; then
      exec "${AS_APP[@]}" "${GUNICORN_ARGS[@]}"
    fi

    "${AS_APP[@]}" "${GUNICORN_ARGS[@]}" &
    PIDS+=("$!")
    start_scheduler_processes
    supervise
    ;;
  worker)
    require_redis_in_production
    if ! broker_configured; then
      log "ERROR: worker mode needs REDIS_URL (or CELERY_BROKER_URL)."
      exit 1
    fi
    prepare_data_dir
    : > "${WORKER_MODE_MARKER}"
    start_scheduler_processes
    supervise
    ;;
  *)
    prepare_data_dir
    exec "${AS_APP[@]}" "${MODE}" "$@"
    ;;
esac
