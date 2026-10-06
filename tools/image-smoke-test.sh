#!/usr/bin/env bash
# Image smoke test for the web server and the scheduled jobs worker.
#
#   ./tools/image-smoke-test.sh shellui/identity-service:ci
#
# Starts Redis and the image on a private Docker network, then checks that:
#   1. web mode serves /health/live and starts the Celery worker with beat
#   2. docker stop shuts both processes down cleanly (exit status 0)
#   3. worker mode starts only the worker
#   4. without REDIS_URL the web app still starts and logs a warning
set -euo pipefail

IMAGE="${1:?usage: $0 IMAGE}"
SUFFIX="smoke-$$"
NETWORK="identity-${SUFFIX}"
REDIS="identity-redis-${SUFFIX}"
WEB="identity-web-${SUFFIX}"
WORKER="identity-worker-${SUFFIX}"
NOREDIS="identity-noredis-${SUFFIX}"
REDIS_IMAGE="${SMOKE_REDIS_IMAGE:-redis:8-alpine}"

log() { printf '==> %s\n' "$*"; }
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  for c in "${WEB}" "${WORKER}" "${NOREDIS}"; do
    if docker inspect "${c}" >/dev/null 2>&1; then
      printf '%s\n' "----- logs: ${c}" >&2
      docker logs "${c}" 2>&1 | tail -n 60 >&2 || true
    fi
  done
  exit 1
}

cleanup() {
  docker rm -f "${WEB}" "${WORKER}" "${NOREDIS}" "${REDIS}" >/dev/null 2>&1 || true
  docker network rm "${NETWORK}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Wait until the container logs match a regex. Fails if the container stops first.
wait_for_log() {
  local container="$1" pattern="$2" timeout="${3:-60}"
  for _ in $(seq 1 "${timeout}"); do
    if grep -Eq "${pattern}" <<<"$(docker logs "${container}" 2>&1)"; then
      return 0
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "${container}")" != "true" ]; then
      fail "${container} stopped while waiting for: ${pattern}"
    fi
    sleep 1
  done
  fail "${container}: no log line matching '${pattern}' after ${timeout}s"
}

# Print "<user> <command line>" for each process in the container (slim images have no ps).
procs() {
  docker exec "$1" python -c '
import os, pwd
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        cmd = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode().strip()
        user = pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
    except (OSError, KeyError):
        continue
    if cmd:
        print(user, cmd)
'
}

REDIS_PASSWORD="smoke-redis-pw-$$"
REDIS_URL_SMOKE="redis://:${REDIS_PASSWORD}@${REDIS}:6379/0"

COMMON_ENV=(
  -e SECRET_KEY=smoke-test-only-0123456789abcdefghijklmnopqrstuvwxyz
  -e DEBUG=true
  -e LOG_LEVEL=INFO
  -e GUNICORN_WORKERS=1
  -e GUNICORN_THREADS=2
)

docker network create "${NETWORK}" >/dev/null
docker run -d --name "${REDIS}" --network "${NETWORK}" "${REDIS_IMAGE}" \
  redis-server --requirepass "${REDIS_PASSWORD}" >/dev/null

log "1/4 web mode: gunicorn and the scheduler"
docker run -d --name "${WEB}" --network "${NETWORK}" \
  "${COMMON_ENV[@]}" -e REDIS_URL="${REDIS_URL_SMOKE}" \
  "${IMAGE}" >/dev/null
wait_for_log "${WEB}" 'Listening at: http://0.0.0.0:8000' 90
wait_for_log "${WEB}" 'identity-service@.* ready\.' 60
docker exec "${WEB}" python -c '
import urllib.request
with urllib.request.urlopen("http://127.0.0.1:8000/health/live", timeout=5) as r:
    assert r.status == 200, r.status
print("OK: /health/live 200")
'
web_procs="$(procs "${WEB}")"
grep -q '^appuser .*celery -A config' <<<"${web_procs}" || fail 'celery is not running as appuser'
grep -q '^appuser .*gunicorn' <<<"${web_procs}" || fail 'gunicorn is not running as appuser'
echo 'OK: gunicorn and celery run as appuser'
docker exec "${WEB}" python manage.py shell -c '
from apps.actions import tasks
from config.celery import app
assert "actions.retry_webhooks" in app.tasks and "actions.purge_expired_data" in app.tasks
print("OK: tasks registered")
' || fail 'tasks are not registered'
if grep -qF "${REDIS_PASSWORD}" <<<"$(docker logs "${WEB}" 2>&1)"; then
  fail 'Redis password printed in the logs'
fi

log "2/4 docker stop: graceful shutdown"
docker stop -t 30 "${WEB}" >/dev/null
status="$(docker inspect -f '{{.State.ExitCode}}' "${WEB}")"
[ "${status}" = "0" ] || fail "web container exited with ${status} on docker stop"
grep -q 'entrypoint: stopped' <<<"$(docker logs "${WEB}" 2>&1)" || fail 'entrypoint did not report a clean stop'
echo 'OK: exit status 0'

log "3/4 worker mode"
docker run -d --name "${WORKER}" --network "${NETWORK}" \
  "${COMMON_ENV[@]}" -e REDIS_URL="${REDIS_URL_SMOKE}" \
  "${IMAGE}" worker >/dev/null
wait_for_log "${WORKER}" 'identity-service@.* ready\.' 60
if grep -q gunicorn <<<"$(procs "${WORKER}")"; then
  fail 'gunicorn runs in worker mode'
fi
echo 'OK: worker ready, no gunicorn'

log "4/4 web mode without REDIS_URL"
docker run -d --name "${NOREDIS}" "${COMMON_ENV[@]}" "${IMAGE}" >/dev/null
wait_for_log "${NOREDIS}" 'Listening at: http://0.0.0.0:8000' 90
grep -q 'WARNING: REDIS_URL is not set' <<<"$(docker logs "${NOREDIS}" 2>&1)" || fail 'missing REDIS_URL warning'
if grep -q 'celery -A config' <<<"$(procs "${NOREDIS}")"; then
  fail 'celery started without REDIS_URL'
fi
echo 'OK: web only, warning logged'

log 'Image smoke test passed'
