#!/usr/bin/env bash
# Post-deploy production configuration smoke test for identity-service.
# Run against a live HTTPS deployment (e.g. after 0.5.0) to verify prod wiring.
#
# Usage:
#   ./tools/prod-config-check.sh https://id.shellui.com
#   ./tools/prod-config-check.sh https://id.shellui.com --company-id 1
#
# Optional env:
#   EXPECTED_JWT_ISSUER   default: origin of base URL (https://host)
#   EXPECTED_JWT_AUDIENCE default: shellui
#   COMPANY_ID            same as --company-id
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: ./tools/prod-config-check.sh BASE_URL [--company-id ID]

Verify a deployed identity-service instance is correctly configured for production.

Environment (optional):
  EXPECTED_JWT_ISSUER    Expected JWT iss claim (default: BASE_URL origin)
  EXPECTED_JWT_AUDIENCE  Expected JWT aud claim (default: shellui)
  COMPANY_ID             Company id for /api/v1/settings?company_id= (or --company-id)

Checks: HTTPS reachability, JWKS, pre-login settings, CORS, bootstrap gate,
        authorize/token endpoints, security headers (warn-only).

Exit 0 when all hard checks pass; non-zero if any FAIL.
EOF
}

pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }
warn() { printf 'WARN: %s\n' "$*" >&2; }
info() { printf 'INFO: %s\n' "$*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'FAIL: required command not found: %s\n' "$1" >&2
    exit 2
  }
}

normalize_base_url() {
  local url="${1%/}"
  if [[ ! "${url}" =~ ^https?:// ]]; then
    printf 'FAIL: BASE_URL must include scheme (https://…)\n' >&2
    exit 2
  fi
  printf '%s' "${url}"
}

url_origin() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import urlsplit
parts = urlsplit(sys.argv[1])
print(f"{parts.scheme}://{parts.netloc}")
PY
}

FAILURES=0
BASE_URL=""
COMPANY_ID="${COMPANY_ID:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --company-id)
      COMPANY_ID="${2:-}"
      [[ -n "${COMPANY_ID}" ]] || {
        printf 'FAIL: --company-id requires a value\n' >&2
        exit 2
      }
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*)
      printf 'FAIL: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ -z "${BASE_URL}" ]]; then
        BASE_URL="$1"
      else
        printf 'FAIL: unexpected argument: %s\n' "$1" >&2
        exit 2
      fi
      shift
      ;;
  esac
done

[[ -n "${BASE_URL}" ]] || {
  usage >&2
  exit 2
}

require_cmd curl
require_cmd python3

BASE_URL="$(normalize_base_url "${BASE_URL}")"
ORIGIN="$(url_origin "${BASE_URL}")"
EXPECTED_JWT_ISSUER="${EXPECTED_JWT_ISSUER:-${ORIGIN}}"
EXPECTED_JWT_AUDIENCE="${EXPECTED_JWT_AUDIENCE:-shellui}"
CORS_PROBE_ORIGIN="${CORS_PROBE_ORIGIN:-https://example-customer-shell.test}"

info "Target: ${BASE_URL}"
info "Expected JWT issuer (manual verify after login): ${EXPECTED_JWT_ISSUER}"
info "Expected JWT audience (manual verify after login): ${EXPECTED_JWT_AUDIENCE}"
if [[ -n "${COMPANY_ID}" ]]; then
  info "Company id: ${COMPANY_ID}"
else
  info "No company_id — settings check verifies pre-login access only (pass --company-id for full settings JSON)"
fi

# ---------------------------------------------------------------------------
# 1. Reachable (HTTPS, follow redirects)
# ---------------------------------------------------------------------------
reachable_meta="$(
  curl -sS -L -o /dev/null -w '%{http_code}\t%{url_effective}\t%{num_redirects}' \
    --connect-timeout 15 --max-time 30 \
    "${BASE_URL}/" 2>/dev/null || printf '000\t\t0'
)"
IFS=$'\t' read -r reach_code reach_final reach_redirects <<<"${reachable_meta}"

if [[ "${reach_code}" == "000" || -z "${reach_code}" ]]; then
  fail "Reachable: no response from ${BASE_URL}/ (connection/TLS/timeout)"
elif [[ "${reach_code}" =~ ^[45][0-9][0-9]$ ]]; then
  fail "Reachable: ${BASE_URL}/ returned HTTP ${reach_code} (final: ${reach_final:-unknown})"
else
  reach_note="HTTP ${reach_code}"
  if [[ "${reach_redirects:-0}" -gt 0 ]]; then
    reach_note="${reach_note}, ${reach_redirects} redirect(s) → ${reach_final}"
    if [[ "${BASE_URL}/" != "${reach_final}" && "${BASE_URL}" != "${reach_final}" ]]; then
      reach_note="${reach_note} (note SSL/host redirect)"
    fi
  fi
  if [[ "${reach_final}" == http://* && "${BASE_URL}" == https://* ]]; then
    warn "Reachable: final URL is HTTP after redirect (${reach_final}) — prefer HTTPS in production"
  fi
  pass "Reachable: ${reach_note}"
fi

# ---------------------------------------------------------------------------
# 2. JWKS
# ---------------------------------------------------------------------------
jwks_body="$(mktemp)"
jwks_code="$(
  curl -sS -L -o "${jwks_body}" -w '%{http_code}' \
    --connect-timeout 15 --max-time 30 \
    "${BASE_URL}/.well-known/jwks.json" 2>/dev/null || echo '000'
)"

if [[ "${jwks_code}" != "200" ]]; then
  fail "JWKS: GET /.well-known/jwks.json → HTTP ${jwks_code} (expected 200; empty keys often means JWT_PRIVATE_KEY missing in prod)"
else
  jwks_result="$(
    JWKS_FILE="${jwks_body}" python3 <<'PY'
import json
import os
import sys

path = os.environ["JWKS_FILE"]
try:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
except json.JSONDecodeError as exc:
    print(f"FAIL\tinvalid JSON: {exc}")
    sys.exit(0)

keys = doc.get("keys")
if not isinstance(keys, list):
    print("FAIL\tresponse missing 'keys' array")
    sys.exit(0)
if len(keys) < 1:
    print("FAIL\tkeys array is empty — set JWT_PRIVATE_KEY in production (DEBUG=false)")
    sys.exit(0)

first = keys[0]
if first.get("kty") != "RSA":
    print(f"FAIL\tfirst key kty={first.get('kty')!r}, expected RSA")
    sys.exit(0)

kid = first.get("kid") or "?"
print(f"PASS\t{len(keys)} RSA key(s), first kid={kid[:24]}")
PY
  )" || jwks_result=$'FAIL\tpython3 JWKS parse error'

  jwks_status="${jwks_result%%$'\t'*}"
  jwks_detail="${jwks_result#*$'\t'}"
  if [[ "${jwks_status}" == "PASS" ]]; then
    pass "JWKS: ${jwks_detail}"
  else
    fail "JWKS: ${jwks_detail}"
  fi
fi
rm -f "${jwks_body}"

# ---------------------------------------------------------------------------
# 3. Auth settings (pre-login, no Bearer)
# ---------------------------------------------------------------------------
settings_path="/api/v1/settings"
if [[ -n "${COMPANY_ID}" ]]; then
  settings_path="/api/v1/settings?company_id=${COMPANY_ID}"
fi

settings_body="$(mktemp)"
settings_code="$(
  curl -sS -L -o "${settings_body}" -w '%{http_code}' \
    --connect-timeout 15 --max-time 30 \
    "${BASE_URL}${settings_path}" 2>/dev/null || echo '000'
)"

settings_kind="$(
  SETTINGS_FILE="${settings_body}" SETTINGS_CODE="${settings_code}" COMPANY_ID="${COMPANY_ID}" python3 <<'PY'
import json
import os
import sys

code = os.environ["SETTINGS_CODE"]
company_id = os.environ.get("COMPANY_ID", "")
path = os.environ["SETTINGS_FILE"]

if code in {"401", "403"}:
    print(f"FAIL\tHTTP {code} — settings must not require Bearer pre-login")
    sys.exit(0)
if code == "000":
    print("FAIL\tno response from /api/v1/settings")
    sys.exit(0)

try:
    with open(path, encoding="utf-8") as fh:
        body = fh.read()
except OSError as exc:
    print(f"FAIL\tcould not read response: {exc}")
    sys.exit(0)

try:
    data = json.loads(body) if body.strip() else None
except json.JSONDecodeError:
    print(f"FAIL\tHTTP {code} but body is not JSON")
    sys.exit(0)

if company_id:
    if code != "200":
        err = data.get("error") if isinstance(data, dict) else body[:120]
        print(f"FAIL\tHTTP {code} for company_id={company_id}: {err}")
        sys.exit(0)
    if not isinstance(data, dict):
        print("FAIL\texpected JSON object for settings")
        sys.exit(0)
    if "error" in data and not {"methods", "oauthProviders"} & set(data.keys()):
        print(f"FAIL\tauth/company error: {data.get('error')}")
        sys.exit(0)
    methods = data.get("methods")
    providers = data.get("oauthProviders")
    if methods is None and providers is None:
        print("FAIL\tsettings JSON missing methods/oauthProviders")
        sys.exit(0)
    print(f"PASS\tHTTP 200 company_id={company_id}, methods={methods!r}, oauthProviders={providers!r}")
else:
    if code == "200" and isinstance(data, dict):
        print("PASS\tHTTP 200 JSON without company_id (unexpected but OK)")
    elif code == "400" and isinstance(data, dict) and "company_id" in str(data.get("error", "")).lower():
        print("PASS\tHTTP 400 Missing company_id (pre-login, no Bearer) — pass --company-id for provider check")
    elif code in {"400", "404"} and isinstance(data, dict) and data.get("error"):
        print(f"PASS\tHTTP {code} validation error without company_id (no auth required): {data.get('error')}")
    else:
        print(f"WARN\tHTTP {code} without company_id — pass --company-id to verify provider/method payload")
PY
)"

settings_status="${settings_kind%%$'\t'*}"
settings_detail="${settings_kind#*$'\t'}"
case "${settings_status}" in
  PASS) pass "Auth settings: ${settings_detail}" ;;
  WARN) warn "Auth settings: ${settings_detail}" ;;
  *) fail "Auth settings: ${settings_detail}" ;;
esac
rm -f "${settings_body}"

# ---------------------------------------------------------------------------
# 4. CORS (multi-tenant preview origins)
# ---------------------------------------------------------------------------
cors_headers="$(mktemp)"
cors_code="$(
  curl -sS -L -D "${cors_headers}" -o /dev/null -w '%{http_code}' \
    -X OPTIONS \
    -H "Origin: ${CORS_PROBE_ORIGIN}" \
    -H 'Access-Control-Request-Method: GET' \
    -H 'Access-Control-Request-Headers: authorization' \
    --connect-timeout 15 --max-time 30 \
    "${BASE_URL}/.well-known/jwks.json" 2>/dev/null || echo '000'
)"

cors_result="$(
  CORS_HDR_FILE="${cors_headers}" CORS_CODE="${cors_code}" CORS_ORIGIN="${CORS_PROBE_ORIGIN}" python3 <<'PY'
import os
import sys

hdr_path = os.environ["CORS_HDR_FILE"]
code = os.environ["CORS_CODE"]
origin = os.environ["CORS_ORIGIN"]

headers = {}
try:
    with open(hdr_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
except OSError as exc:
    print(f"FAIL\tcould not read CORS headers: {exc}")
    sys.exit(0)

acao = headers.get("access-control-allow-origin")
if code == "000":
    print("FAIL\tOPTIONS preflight failed (no response)")
elif acao == "*":
    print(f"PASS\tAccess-Control-Allow-Origin: * (origin {origin})")
elif acao == origin:
    print(f"PASS\tAccess-Control-Allow-Origin reflects {origin}")
elif acao:
    print(f"WARN\tAccess-Control-Allow-Origin={acao!r} — unknown preview origins may be blocked; product default is allow-all (CORS_ALLOW_ALL_ORIGINS=true)")
else:
    print(
        "FAIL\tno Access-Control-Allow-Origin on OPTIONS — random hosting preview origins will fail in the browser; "
        "set CORS_ALLOW_ALL_ORIGINS=true or add origins to CORS_ALLOWED_ORIGINS"
    )
PY
)"
rm -f "${cors_headers}"

cors_status="${cors_result%%$'\t'*}"
cors_detail="${cors_result#*$'\t'}"
case "${cors_status}" in
  PASS) pass "CORS: ${cors_detail}" ;;
  WARN) warn "CORS: ${cors_detail}" ;;
  *) fail "CORS: ${cors_detail}" ;;
esac

# ---------------------------------------------------------------------------
# 5. Bootstrap gate (no open superuser form in production)
# ---------------------------------------------------------------------------
home_body="$(mktemp)"
home_code="$(
  curl -sS -L -o "${home_body}" -w '%{http_code}' \
    --connect-timeout 15 --max-time 30 \
    "${BASE_URL}/" 2>/dev/null || echo '000'
)"

bootstrap_result="$(
  HOME_FILE="${home_body}" HOME_CODE="${home_code}" python3 <<'PY'
import os
import re
import sys

path = os.environ["HOME_FILE"]
code = os.environ["HOME_CODE"]

if code == "000":
    print("FAIL\tno response from /")
    sys.exit(0)

try:
    html = open(path, encoding="utf-8", errors="replace").read().lower()
except OSError as exc:
    print(f"FAIL\tcould not read / body: {exc}")
    sys.exit(0)

markers = [
    "create superuser",
    "create the initial administrator",
    "initial administrator account",
    "show_setup_form",
]
hits = [m for m in markers if m in html]
if hits:
    print(
        "FAIL\t/ looks like open first-run superuser setup — prod should have users already "
        f"(matched: {', '.join(hits[:2])}). Ensure DEBUG=false and database is initialized."
    )
elif "shellui identity" in html or "openapi" in html or "swagger" in html:
    print("PASS\t/ does not expose open superuser signup (landing/docs page)")
else:
    print("WARN\t/ HTML is ambiguous — could not confirm bootstrap gate; inspect manually")
PY
)" || bootstrap_result=$'WARN\t/ bootstrap check error'
rm -f "${home_body}"

bootstrap_status="${bootstrap_result%%$'\t'*}"
bootstrap_detail="${bootstrap_result#*$'\t'}"
case "${bootstrap_status}" in
  PASS) pass "Bootstrap gate: ${bootstrap_detail}" ;;
  WARN) warn "Bootstrap gate: ${bootstrap_detail}" ;;
  *) fail "Bootstrap gate: ${bootstrap_detail}" ;;
esac

# ---------------------------------------------------------------------------
# 6. Authorize endpoint exists
# ---------------------------------------------------------------------------
authz_body="$(mktemp)"
authz_code="$(
  curl -sS -L -o "${authz_body}" -w '%{http_code}' \
    --connect-timeout 15 --max-time 30 \
    "${BASE_URL}/api/v1/authorize" 2>/dev/null || echo '000'
)"

if [[ "${authz_code}" == "500" ]]; then
  fail "Authorize: GET /api/v1/authorize without params → HTTP 500 (server misconfiguration)"
elif [[ "${authz_code}" == "000" ]]; then
  fail "Authorize: no response from /api/v1/authorize"
elif [[ "${authz_code}" =~ ^(200|302|400|401|404)$ ]]; then
  pass "Authorize: GET /api/v1/authorize without params → HTTP ${authz_code} (endpoint reachable)"
else
  pass "Authorize: GET /api/v1/authorize without params → HTTP ${authz_code}"
fi
rm -f "${authz_body}"

# ---------------------------------------------------------------------------
# 7. Token endpoint
# ---------------------------------------------------------------------------
token_body="$(mktemp)"
token_code="$(
  curl -sS -L -o "${token_body}" -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/json' \
    --connect-timeout 15 --max-time 30 \
    -d '{}' \
    "${BASE_URL}/api/v1/token" 2>/dev/null || echo '000'
)"

if [[ "${token_code}" == "500" ]]; then
  fail "Token: POST /api/v1/token without body → HTTP 500 (expected 4xx validation error)"
elif [[ "${token_code}" == "000" ]]; then
  fail "Token: no response from /api/v1/token"
elif [[ "${token_code}" =~ ^4[0-9][0-9]$ ]]; then
  pass "Token: POST /api/v1/token without refresh body → HTTP ${token_code} (expected client error)"
else
  warn "Token: POST /api/v1/token → HTTP ${token_code} (expected 4xx)"
fi
rm -f "${token_body}"

# ---------------------------------------------------------------------------
# 8. Security headers (warn-only)
# ---------------------------------------------------------------------------
sec_headers="$(mktemp)"
sec_code="$(
  curl -sS -L -D "${sec_headers}" -o /dev/null -w '%{http_code}' \
    --connect-timeout 15 --max-time 30 \
    "${BASE_URL}/" 2>/dev/null || echo '000'
)"

if [[ "${BASE_URL}" == https://* ]]; then
  if grep -qi '^strict-transport-security:' "${sec_headers}" 2>/dev/null; then
    hsts_val="$(grep -i '^strict-transport-security:' "${sec_headers}" | head -1 | cut -d: -f2- | xargs)"
    pass "Security headers: Strict-Transport-Security present (${hsts_val})"
  else
    warn "Security headers: Strict-Transport-Security missing on HTTPS response (configure reverse proxy or Django SECURE_HSTS_*)"
  fi
else
  info "Security headers: skipped HSTS check (BASE_URL is not HTTPS)"
fi
rm -f "${sec_headers}"

# ---------------------------------------------------------------------------
# OAuth / JWT notes (cannot fully verify without IdP)
# ---------------------------------------------------------------------------
info "Full OAuth login flow (fragment vs authorization code) cannot be verified without a configured IdP and allowlisted redirect_to."
info "After 0.5.0, production should set OAUTH_TOKEN_DELIVERY=fragment until Shellui issue #66 lands (code delivery for new shells)."
info "Decode a post-login access_token JWT to confirm iss=${EXPECTED_JWT_ISSUER} and aud=${EXPECTED_JWT_AUDIENCE}."

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
if [[ "${FAILURES}" -gt 0 ]]; then
  printf '\n%d check(s) failed.\n' "${FAILURES}" >&2
  exit 1
fi

printf '\nAll hard checks passed.\n'
exit 0
