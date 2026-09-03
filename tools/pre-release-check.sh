#!/usr/bin/env bash
# Pre-release checklist for identity-service (see PUBLISH.md).
# Usage:
#   ./tools/pre-release-check.sh
#   ./tools/pre-release-check.sh --skip-docker   # version + git hygiene only
#   ./tools/pre-release-check.sh --image mytag   # custom local image tag
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

SKIP_DOCKER=0
IMAGE_TAG=""
HOST_PORT="${PRE_RELEASE_HOST_PORT:-}"
CONTAINER_NAME="${PRE_RELEASE_CONTAINER_NAME:-identity-release-smoke-$$}"

usage() {
  cat <<'EOF'
Usage: ./tools/pre-release-check.sh [options]

Automates the PUBLISH.md pre-release checklist:
  1. Version alignment (pyproject.toml ↔ CHANGELOG dated entry)
  2. No secrets in git / Docker build context
  3. Image smoke test (settings + JWKS RSA key)

Options:
  --skip-docker     Skip Docker build and smoke test
  --image TAG       Image tag to build/run (default: shellui/identity-service:pre-release)
  --port PORT       Host port for smoke test (default: free port, or PRE_RELEASE_HOST_PORT)
  -h, --help        Show this help
EOF
}

log() { printf '==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

pick_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-docker) SKIP_DOCKER=1; shift ;;
    --image)
      IMAGE_TAG="${2:-}"
      [[ -n "${IMAGE_TAG}" ]] || fail '--image requires a tag'
      shift 2
      ;;
    --port)
      HOST_PORT="${2:-}"
      [[ -n "${HOST_PORT}" ]] || fail '--port requires a value'
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

command -v uv >/dev/null 2>&1 || fail 'uv is required (https://docs.astral.sh/uv/)'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'

VERSION="$(
  uv run python - <<'PY'
import tomllib
from pathlib import Path
data = tomllib.loads(Path('pyproject.toml').read_text(encoding='utf-8'))
print(data['project']['version'])
PY
)"
[[ -n "${VERSION}" ]] || fail 'could not read project.version from pyproject.toml'

if [[ -z "${IMAGE_TAG}" ]]; then
  IMAGE_TAG="shellui/identity-service:pre-release"
fi

if [[ -z "${HOST_PORT}" ]]; then
  HOST_PORT="$(pick_free_port)"
fi

log "Pre-release check for identity-service ${VERSION}"

# ---------------------------------------------------------------------------
# 1. Version alignment
# ---------------------------------------------------------------------------
log "1/3 Version alignment"

if ! grep -E "^## \[${VERSION}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md >/dev/null; then
  fail "CHANGELOG.md must contain a dated entry exactly like: ## [${VERSION}] - YYYY-MM-DD"
fi
if grep -E "^## \[${VERSION}\] - .*MM-DD" CHANGELOG.md >/dev/null; then
  fail "CHANGELOG.md entry for ${VERSION} still has a placeholder date (MM-DD)"
fi

LOCK_VERSION="$(
  uv run python - <<'PY'
from pathlib import Path
import re
text = Path('uv.lock').read_text(encoding='utf-8')
# First package block is the project itself when name = "identity-service"
m = re.search(
    r'(?m)^name = "identity-service"\nversion = "([^"]+)"',
    text,
)
print(m.group(1) if m else '')
PY
)"
if [[ -n "${LOCK_VERSION}" && "${LOCK_VERSION}" != "${VERSION}" ]]; then
  fail "uv.lock identity-service version (${LOCK_VERSION}) != pyproject.toml (${VERSION})"
fi

printf 'OK: version %s aligned in pyproject.toml, CHANGELOG.md, and uv.lock\n' "${VERSION}"

# ---------------------------------------------------------------------------
# 2. No secrets in build context
# ---------------------------------------------------------------------------
log "2/3 Secrets / build context"

if git ls-files --error-unmatch .env >/dev/null 2>&1; then
  fail '.env is tracked by git — remove it from the repository'
fi
if [[ -f .env ]] && ! grep -qE '^\.env$' .gitignore; then
  fail '.env exists locally but is not listed in .gitignore'
fi
if tracked_db="$(git ls-files '*.sqlite3')"; then
  if [[ -n "${tracked_db}" ]]; then
    printf '%s\n' "${tracked_db}" >&2
    fail 'SQLite database files must not be tracked'
  fi
fi
grep -qE '^\.env$' .gitignore || fail '.gitignore must exclude .env'
grep -qE '^\.env$' .dockerignore || fail '.dockerignore must exclude .env'

printf 'OK: .env / sqlite not tracked; ignore files look correct\n'

if [[ "${SKIP_DOCKER}" -eq 1 ]]; then
  log 'Skipping Docker steps (--skip-docker)'
  log 'Pre-release check passed (partial)'
  exit 0
fi

command -v docker >/dev/null 2>&1 || fail 'docker is required for image checks (or pass --skip-docker)'

log "Building image ${IMAGE_TAG}"
docker build -t "${IMAGE_TAG}" .

log 'Verifying .env is absent from the image'
docker run --rm --entrypoint sh "${IMAGE_TAG}" \
  -c 'test ! -f /app/.env && echo "OK: .env not in image"'

# ---------------------------------------------------------------------------
# 3. Smoke test
# ---------------------------------------------------------------------------
log "3/3 Image smoke test (host port ${HOST_PORT})"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

export SECRET_KEY="${SECRET_KEY:-$(uv run python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')}"
# Ignore a broken JWT_PRIVATE_KEY in local .env.
eval "$(uv run python manage.py generate_jwt_keys --shell)"
[[ -n "${JWT_PRIVATE_KEY:-}" ]] || fail 'generate_jwt_keys --shell did not set JWT_PRIVATE_KEY'

docker run --rm -d --name "${CONTAINER_NAME}" -p "${HOST_PORT}:8000" \
  -e SECRET_KEY \
  -e JWT_PRIVATE_KEY \
  -e ALLOWED_HOSTS=localhost,127.0.0.1 \
  "${IMAGE_TAG}" >/dev/null

log 'Waiting for Gunicorn…'
ready=0
for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${HOST_PORT}/api/v1/settings" || true)"
  if [[ "${code}" != "000" && -n "${code}" ]]; then
    ready=1
    printf 'OK: /api/v1/settings → HTTP %s\n' "${code}"
    break
  fi
  sleep 1
done
[[ "${ready}" -eq 1 ]] || fail 'service did not become ready on /api/v1/settings'

curl -s "http://127.0.0.1:${HOST_PORT}/.well-known/jwks.json" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
keys = doc.get("keys") or []
assert len(keys) >= 1, f"expected >=1 JWKS key, got {doc!r}"
assert keys[0].get("kty") == "RSA", f"expected RSA key, got {keys[0]!r}"
kid = keys[0].get("kid") or "?"
print(f"OK: JWKS has {len(keys)} RSA key(s), kid={kid[:16]}…")
'

log "Pre-release check passed for ${VERSION}"
