---
description: OpenTelemetry traces and metrics for identity-service, and personal access tokens.
---

# Metrics and access tokens

identity-service exports traces and metrics with OpenTelemetry. A request can be followed from this service into other Shellui services and into Celery tasks. Telemetry stays off until `OTEL_EXPORTER_OTLP_ENDPOINT` is set.

`GET /api/v1/metrics` and `GET /api/v1/metrics/all` are removed. There is no Prometheus scrape endpoint. Scheduled job state is still available as JSON at `GET /api/v1/scheduled-jobs` (staff).

## Enable

The process entry points (gunicorn, the Celery worker and beat, and `manage.py`) call the shared setup. Do not wrap the process with `opentelemetry-instrument`.

| Variable | Role |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Turns telemetry on. Example: `https://signoz.example:4318` |
| `OTEL_EXPORTER_OTLP_HEADERS` | Exporter headers, including SigNoz basic auth |
| `OTEL_SERVICE_NAME` | Overrides `service.name`. The default is `identity-service` |
| `OTEL_RESOURCE_ATTRIBUTES` | Overrides `deployment.environment`, `service.version`, and `cloud.region` when those keys are present. Example: `deployment.environment=production,cloud.region=eu` |
| `SHELLUI_REGION` | Sets `cloud.region` when `OTEL_RESOURCE_ATTRIBUTES` does not |

Protocol is OTLP over HTTP protobuf. `OTEL_SDK_DISABLED=true` leaves telemetry off even when an endpoint is set.

identity-global and a regional identity share `service.name` `identity-service`. Each process sets the resource attribute `shellui.instance_role` from `SHELLUI_INSTANCE_ROLE`:

| Deployment | `shellui.instance_role` |
| --- | --- |
| identity-global (`SHELLUI_INSTANCE_ROLE=global`) | `global` |
| Regional identity (`SHELLUI_INSTANCE_ROLE=region`) | `region` |
| Standalone (unset) | `standalone` |

`OTEL_RESOURCE_ATTRIBUTES` wins when it already contains `shellui.instance_role`. `service.version` comes from the package version.

Logs keep `X-Request-ID` and also include `trace_id` and `span_id` (both `0` when there is no span). Spans can carry `shellui.company_id`, `shellui.user_id`, and `shellui.agent_id`. Emails, tokens, and other personal data are not attached.

Outbound `requests` calls send W3C `traceparent`, including the upstream token call and the MCP approval notify to ai-service. Celery task headers carry the same context. Paths ending in `health` or `live` are not traced.

## Instruments

Names follow OpenTelemetry conventions. A Prometheus `_total` suffix is dropped and underscores become dots. `company_id` stays an attribute where the old series had that label.

| Old Prometheus name | Instrument | Kind |
| --- | --- | --- |
| `shellui_auth_users_total` | `shellui.auth.users` | gauge |
| `shellui_auth_users_active` | `shellui.auth.users.active` | gauge |
| `shellui_auth_users_staff` | `shellui.auth.users.staff` | gauge |
| `shellui_auth_social_accounts_total` | `shellui.auth.social.accounts` | gauge |
| `shellui_auth_daily_active_users` | `shellui.auth.daily.active.users` | gauge |
| `shellui_auth_weekly_active_users` | `shellui.auth.weekly.active.users` | gauge |
| `shellui_auth_monthly_active_users` | `shellui.auth.monthly.active.users` | gauge |
| `shellui_auth_successful_logins_total` | `shellui.auth.successful.logins` | counter (`company_id`, `provider`) |
| `shellui_auth_company_users_total` | `shellui.auth.company.users` | gauge (`company_id`) |
| `shellui_auth_company_users_active` | `shellui.auth.company.users.active` | gauge (`company_id`) |
| `shellui_auth_company_users_staff` | `shellui.auth.company.users.staff` | gauge (`company_id`) |
| `shellui_auth_company_social_accounts_total` | `shellui.auth.company.social.accounts` | gauge (`company_id`) |
| `shellui_auth_company_daily_active_users` | `shellui.auth.company.daily.active.users` | gauge (`company_id`) |
| `shellui_auth_company_weekly_active_users` | `shellui.auth.company.weekly.active.users` | gauge (`company_id`) |
| `shellui_auth_company_monthly_active_users` | `shellui.auth.company.monthly.active.users` | gauge (`company_id`) |

The login counter counts sign-ins in that process since it started. Gauges are read from the database at export time. Django also records `http.server.request.duration` and `http.server.active_requests`. Each Gunicorn worker starts `http.server.active_requests` at 0, so a worker without traffic still exports it (health checks are not traced). The Celery worker does not export it. Process and Python runtime series that the Prometheus client added on the old global scrape are not re-exported. Collect those from the host or the collector.

Scheduled job instruments are in [Scheduled jobs](scheduled-jobs.md#opentelemetry-metrics).

## Personal access tokens

A PAT is a signed JWT with the same claims as a session token, plus `pat_id` and `pat_ro` (see [JWT and JWKS](jwks.md#claims)). Create one in Shellui admin **Access tokens**, or with `POST /api/v1/personal-access-tokens`. The response shows the `access_token` once. The response does not include `access_global_metrics`. Sending `access_global_metrics: true` returns **400**.

| Type | Allowed |
| --- | --- |
| Read-only (`pat_ro: true`) | `GET`, `HEAD`, and `OPTIONS` on the whole API |
| Read and write | The same endpoints and rules as a session token of your user |

PATs expire after `PERSONAL_ACCESS_TOKEN_LIFETIME` (30 days by default). Each request checks the PAT against its database row, so revoking it stops it right away, and every successful use updates `last_used_at`.

Treat PATs like passwords: send them over HTTPS only, keep them in a secret manager, and prefer read-only tokens for read APIs. New tokens do not include `pat_agm`. Tokens that already carry that claim still authenticate. The claim is ignored.

The `access_global_metrics` column remains on `PersonalAccessToken` so existing rows stay valid. It has no effect.

To try the API, open `/api/docs/`, click **Authorize**, choose **bearerAuth**, and paste your token.

## Related

- [JWT and JWKS](jwks.md): token claims and verification
- [Scheduled jobs](scheduled-jobs.md#monitoring): job health
- [Configuration](configuration.md#runtime-and-observability): environment variables
- [Security hardening](security-hardening.md): PAT rate limits
