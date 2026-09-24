# Next release: proposed priorities

**Audience:** Shellui maintainers (Sébastien / small team)  
**Repo:** `shellui/identity-service`  
**Baseline:** `main` at **v0.5.0** (`pyproject.toml`), security audit items through **0.5.0** (issues #7–#12 closed)  
**In flight:** [PR #24](https://github.com/shellui/identity-service/pull/24) — Gunicorn pool starvation, `GET /health/live`, SQLite WAL, Postgres connect timeout (do **not** re-implement here)

This doc is a **prioritized backlog** for the release **after** PR #24 merges. Effort: **S** ≈ ≤1 day, **M** ≈ 2–4 days, **L** ≈ multi-day / cross-repo.

---

## 1. Must / should for next release

| Priority | Item | Why | Effort | Risk if skipped |
| -------- | ---- | --- | ------ | --------------- |
| **P0** | **Cut a patch release containing PR #24** (suggest **0.5.1** or **0.6.0**), align `pyproject.toml`, `CHANGELOG.md`, Docker tags, close milestone **v0.5.0** | Prod symptoms (HTTP hang on `/`, pool saturation) match `config/views.py` root (`User.objects.exists()` + session middleware) and default **2×2** Gunicorn in `tools/docker-entrypoint.sh` / `.env.example` | **S** | Intermittent total stalls on `id.shellui.com` continue; probes on `/` amplify load |
| **P0** | **Run `id.shellui.com` on Postgres** (`POSTGRES_DATABASE_URL`) for real traffic | SQLite remains default in `Dockerfile` / `config/settings.py`; even with WAL (PR #24), writes serialize; refresh rotation + `UserActivity` touch contend on one file | **S** (ops) | OAuth/login/refresh bursts → 20s lock waits (`timeout: 20`), worker starvation |
| **P0** | **Shared cache backend** (Redis or similar) via `CACHES` env — replace default `LocMemCache` | `config/settings.py` uses **per-process** cache for: auth rate limits (`apps/authapi/throttling.py`), post-logout access **jti** denylist (`apps/authapi/refresh_sessions.py`), `shellui:user_metadata:*` and throttles (`apps/authapi/views.py`, `user_activity.py`). With Gunicorn **N workers**, limits are **N× weaker** and logout denylist **does not propagate** across workers until access JWT expires (~5m default) | **M** | Understated abuse protection; logout “works” on one worker only; stale/wrong JWT metadata across workers |
| **P1** | **Production email that actually sends** | Company join flows call `send_mail(..., fail_silently=True)` in `apps/companies/access.py`; prod default backend is SMTP (`config/settings.py`) with `EMAIL_HOST=localhost` — invite/domain notifications silently no-op | **S–M** | Owners never get access-request mail; users not notified when enabled |
| **P1** | **SMTP / outbound timeouts** (follow-up called out in PR #24) | OAuth IdP calls use 20s timeouts (`apps/authapi/oauth.py`, `views.py`); Django `send_mail` has **no** socket timeout — a dead SMTP can block a Gunicorn thread | **S** | Same class of “hang then recover” as PR #24, on access-denied email path |
| **P1** | **Update `tools/prod-config-check.sh`** after PR #24 | Script still uses `GET /` for reachability (`tools/prod-config-check.sh` ~L127–153); should prefer **`GET /health/live`** and warn if liveness missing | **S** | False negatives/timeouts during incidents; ops keep probing heavy `/` |
| **P2** | **Document multi-worker ops checklist** in `PUBLISH.md` / README | PR #24 adds concurrency + liveness guidance; main branch README still lists **2×2** workers and no liveness path | **S** | Operators stay on 4-slot pool after image upgrade |

### Architecture note (multi-tenant / “passe-partout”)

JWTs are **scoped by `company_id` claim** (issued in `apps/authapi/views.py`; validated on refresh in `refresh_sessions.py`). This matches Shellui’s **one company per session** model on shared `id.shellui.com`. A shared Redis cache is **required** for correct cross-worker behavior; it does **not** by itself merge tenants — keep company scoping in tokens and APIs.

---

## 2. High-value product / API gaps

| Priority | Item | Why | Effort | Risk if skipped |
| -------- | ---- | --- | ------ | --------------- |
| **P1** | **Session-code delivery as default in prod** (flip when Shellui ships) | Default in repo is `OAUTH_TOKEN_DELIVERY=code` (`.env.example`, `config/settings.py`); README + `prod-config-check.sh` still tell prod to use **`fragment` until [Shellui #66](https://github.com/shellui/shellui/issues/66)** | **S** (config) + **cross-repo** | Fragment tokens in URL/history; harder XSS recovery |
| **P1** | **Legacy OAuth surface sunset plan** | `POST /api/v1/oauth/exchange` documented as deprecated (README); **`/api/v1/providers/{provider}/authorize|login/`** still routed (`apps/authapi/urls.py`) with allowlist tests only (`test_legacy_oauth_redirect_uri.py`) | **M** | Two OAuth stacks to secure and explain forever |
| **P2** | **Opaque / public company identifier for pre-login settings** | `GET /api/v1/settings` still requires numeric `company_id` (see prod-config-check); audit **M-06** partially addressed (hide OAuth client IDs) but tenant id is enumerable | **M–L** | Competitors scrape provider config by guessing ids |
| **P2** | **PAT + metrics API tests** | Endpoints documented in `docs/metrics.md`; **no** `test_*` for PAT CRUD or `/api/v1/metrics` | **M** | Regressions on staff/owner authZ and `pat_ro` / `pat_agm` |
| **P2** | **Directory API tests** (`/api/v1/users`, groups, preferences) | README documents staff/owner user APIs; only company access and OAuth have broad tests | **M** | Admin panel relies on untested PUT/PATCH paths |
| **P3** | **Refresh / OAuth delivery table retention** | `RefreshTokenSession`, `OAuthSessionDeliveryCode` grow without purge (`apps/authapi/models.py`, migrations `0010_*`) | **S–M** | DB bloat on long-lived SQLite/Postgres |

### Conflicts / closed product bets

- **Custom identity hostname per customer on shared multi-tenant** — issue [#6](https://github.com/shellui/identity-service/issues/6) closed **not_planned**. Custom domains remain an **operator** concern: set `ALLOWED_HOSTS`, `JWT_ISSUER`, IdP callback URLs, and per-company OAuth apps accordingly — not a next identity-service feature.

---

## 3. DX / ops

| Priority | Item | Why | Effort | Risk if skipped |
| -------- | ---- | --- | ------ | --------------- |
| **P1** | **`GET /health/ready` (optional)** — DB ping, not for liveness | PR #24 adds **liveness only** (no DB); `docs/RELEASES.md` still lists “No HEALTHCHECK in Dockerfile” | **S** | Orchestrators cannot distinguish “process up” vs “can serve login” |
| **P1** | **Docker `HEALTHCHECK`** → `/health/live` | `Dockerfile` has no HEALTHCHECK; `docs/RELEASES.md` “First release limitations” | **S** | PaaS defaults to TCP-only checks |
| **P2** | **Prometheus metrics semantics** | `apps/authapi/metrics.py` uses in-process `prometheus_client` gauges/counters — **per-worker**, not cluster totals | **M** | Misleading `/api/v1/metrics/all` when scraped via load balancer |
| **P2** | **Fix README structure drift** | README says `src/config/` and `src/apps/` but tree is `config/`, `apps/` at repo root | **S** | Onboarding friction |
| **P3** | **Automated Docker Hub publish** | `docs/RELEASES.md`: “no GitHub Actions workflow for Docker publish yet” | **M** | Manual tag drift vs `project.version` |
| **P3** | **Optional GeoIP for login audit** | `SHELLUI_GEOIP_DATABASE_PATH` documented; `geoip2` **not** in `pyproject.toml` | **S** | Country/city columns in `LoginEvent` stay empty |

---

## 4. Nice-to-have / later

| Item | Why | Effort |
| ---- | --- | ------ |
| **Lightweight `/` landing without DB** on every GET | `root()` always hits `User.objects.exists()` (`config/views.py`) — unnecessary for prod docs page | **S** |
| **Management command: purge expired refresh/session codes** | Hygiene for rotation tables | **S** |
| **CI: one integration test with `GUNICORN_WORKERS=2`** | Catch pool-regression class under parallel requests | **M** |
| **Docusaurus publish** | `deploy-docs.yml` exists; keep in sync with `docs/NEXT-RELEASE.md` when priorities change | **S** |
| **Rate-limit scope for `/api/v1/oauth/session`** | Code exchange is one-time but brute-forceable within TTL | **S** |

---

## 5. Explicitly defer (with why)

| Item | Why defer |
| ---- | --------- |
| **Dynamic per-company CORS** | Accepted product model: allow-all + Bearer JWT (`docs/security-hardening.md`, 0.5.0 CHANGELOG). Conflicts with multi-tenant hosting previews unless shells move to server-side API. |
| **Email verification (`ACCOUNT_EMAIL_VERIFICATION`)** | `config/settings.py` sets `'none'`; OAuth-only login path; verification is a product change across Shellui + identity. |
| **Remove fragment token delivery** | Blocked on Shellui **#66** and prod `OAUTH_TOKEN_DELIVERY=fragment`; docs already mark deprecated (`docs/oauth-login.md`). |
| **Turn off `JWT_ACCEPT_HS256_LEGACY` in prod** | Already default **false** with RS256; only re-enable during migration (`apps/authapi/jwks.py`, `checks.py`). |
| **Per-customer custom domain on shared id host** | Issue #6 not planned; use dedicated deploy or correct env/JWT issuer per operator. |
| **HttpOnly / BFF session (audit H-09)** | Out of scope for identity-service per security issue #11; belongs in shell architecture. |
| **Re-do PR #24 work** | Merge PR #24; use this doc for **follow-ups** (prod-config-check, SMTP timeout, Postgres migration). |

---

## Suggested release sequencing

1. Merge **PR #24** → tag **0.5.1** (or **0.6.0** if you treat reliability as minor).  
2. Ops: Postgres + `GUNICORN_WORKERS/THREADS` + probe **`/health/live`**.  
3. Next code release: **shared cache** + **email** + **prod-config-check** + **PAT/metrics tests**.  
4. Coordinate with Shellui: **fragment → code** default, then schedule legacy OAuth removal.

---

## Evidence map (quick)

| Area | Where to look |
| ---- | ------------- |
| Version | `pyproject.toml` (`0.5.0`) |
| Security 0.5.0 | `CHANGELOG.md`, `docs/security-hardening.md`, closed issues #7–#12 |
| Runtime / Gunicorn | `tools/docker-entrypoint.sh`, `Dockerfile`, `.env.example` |
| Liveness (incoming) | PR #24 → `apps/authapi/middleware.py`, `config/tests/test_health_live.py` |
| Cache / multi-worker | `config/settings.py` `CACHES`, `refresh_sessions.py`, `throttling.py` |
| OAuth / delivery | `docs/oauth-login.md`, `apps/authapi/oauth_session_code.py` |
| Tests present | `apps/authapi/tests/`, `apps/companies/tests/`, `config/tests/` (15 modules; no PAT/metrics) |
| Prod smoke | `tools/prod-config-check.sh`, `PUBLISH.md` |
| CI | `.github/workflows/ci.yml`, `pre-release.yml` |

*Generated for roadmap review; edit freely in this PR.*
