# Send mail with email-service

identity-service sends sign-in and invitation mail through Shellui email-service when `EMAIL_SERVICE_API_KEY` is set. It also forwards every other webhook event so a company email rule can send its own message. With no key, SMTP (or the console backend when `DEBUG=true`) stays in place and no event rows are written.

## Direct send

Magic links and invitations call `POST /api/v1/send`. identity-service does not set `lane`. The template key selects the auth lane.

| Message | Template | TTL |
| ------- | -------- | --- |
| Magic link | `identity.auth.magic_link.requested` | 120s |
| Staff notice (sent instead of a magic link to a staff account, no link or token) | `identity.auth.magic_link.staff_blocked` | 300s |
| Invitation | `identity.user.invited` | 300s |

`identity.auth.magic_link.staff_blocked` uses Shellui's own copy in email-service. Companies cannot edit it, add rules on it, or receive it through `POST /api/v1/events`. Variables: `company_name` and `sign_in_url` (the origin of the request's `redirect_to`, omitted for a loopback callback). See [Staff accounts](magic-link.md#staff-accounts).

The idempotency key is stable for that magic-link row or that invitation. Retries send the same key and the same JSON body. The key does not contain the magic-link token, and identity-service does not log the token or the API key.

The magic-link email is always sent by identity-service. A webhook rule for `identity.auth.magic_link.requested` is a notification only: its payload never contains the sign-in link or the token. A webhook rule for `identity.user.invited` still replaces the invitation send: its payload carries `invitation_url` (an app URL, not a credential), and your endpoint delivers the message. See [webhooks](actions.md).

These two events are not also posted to `POST /api/v1/events`. The catalog enables them by default, so a second post would send a second message. `/send` still goes out when a company turns the email rule off.

## When SMTP is used

identity-service uses SMTP in two cases:

- `EMAIL_SERVICE_API_KEY` is unset
- email-service cannot be reached after the caller retry policy (connection errors, redirects, and HTTP 5xx)
- the staff notice only: email-service answers `template_not_found` (a version from before the template existed)

Retryable responses (`409`, `429`, and HTTP 5xx) are tried again with the same idempotency key, up to `EMAIL_SERVICE_SEND_ATTEMPTS`. The wait follows `Retry-After`, capped by `EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS` (default `1` second) so a sign-in request does not wait out the full webhook backoff.

These codes are not sent over SMTP. The API returns the code itself:

| Code | HTTP |
| ---- | ---- |
| `recipient_suppressed` | 422 |
| `company_rate_limited`, `recipient_rate_limited` | 429 |
| `provider_not_configured`, `platform_sender_not_allowed` | 409 |
| `auth_link_missing`, `auth_link_host_not_allowed` | 400 |

Other `400`, `401`, and `403` responses are not retried. The API returns **503** `email_unavailable`.

If SMTP also fails, the API returns **503** and this body:

```json
{"error_code": "email_unavailable"}
```

There is no translated sentence in the JSON. A magic-link request that cannot be mailed does not keep the token. An invitation that cannot be mailed is not stored, so the same POST can be retried.

An invitation with no `app_url` still calls `/send`. `invitation_url` is then the identity public base (`JWT_ISSUER`, or the request base URL when `DEBUG=true` and `JWT_ISSUER` is unset). The same URL is used if SMTP has to send the message after email-service cannot be reached. With the key unset, an invitation that has no `app_url` stays on the SMTP templates and has no link.

## Event forwarding

Every webhook event except the direct-send templates is posted to `POST /api/v1/events` after the database commit. Sign-in events (`identity.auth.login.succeeded` and `identity.auth.login.failed`) stay in the [event log](event-log.md) only.

The body includes:

- `service` set to `identity`
- `company_id`
- the catalog `event_type`
- `payload`, including `company_name` and the template fields identity already has
- `recipients` hints (`email`, and `user_id` when the event has one)
- `language` when the payload language is `en` or `fr`
- `idempotency_key` of the form `identity-event-<event log id>`

When the event payload has an email, that address is the hint. Otherwise identity-service sends the company owners. If the company has no owner email, it sends Django staff addresses. A payload with no address and no owner or staff email is not posted.

SCIM token events map the webhook field `name` to the template field `token_name`.

Delivery uses the same outbox and `retry_webhooks` scheduled job as Shellui webhooks. Each try is one POST. A 2xx response is finished, including `skipped_reason` (`rule_disabled` or `no_recipients`). `400`, `401`, `403`, `405`, `410`, `413`, and `422` are not retried. `404`, `408`, `409`, `425`, `429`, any other 4xx, 5xx, timeouts, and connection errors are retried with the same idempotency key: 30 seconds times 2^(attempt-1), capped at 1 hour, 8 attempts. `429` and `503` honor `Retry-After`, still capped at 1 hour. The request that emitted the event does not wait for this HTTP call.

Each row keeps `last_trigger` (`dispatch` or `automatic_retry`) and, for retries, `last_scheduled_job_run_id`. Posts made during a scheduled job carry `X-Request-ID: sjr-<run id>`, so email-service logs show which run sent them. See [Scheduled jobs monitoring](scheduled-jobs.md#from-a-run-to-its-webhooks-and-emails).

Unset `EMAIL_SERVICE_API_KEY` and identity-service does not insert these rows.

## Configuration

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `EMAIL_SERVICE_URL` | `https://email.shellui.com` | Origin only. identity-service appends `/api/v1/send` and `/api/v1/events`. Local: `http://localhost:8003`. From a container: `http://host.docker.internal:8003` |
| `EMAIL_SERVICE_API_KEY` | empty | Service key (`esk_`). Sent as `Authorization: Bearer` |
| `EMAIL_SERVICE_TIMEOUT_SECONDS` | `5` | HTTP timeout for one attempt |
| `EMAIL_SERVICE_SEND_ATTEMPTS` | `3` | Attempts for one direct send. Event posts use the outbox (8 attempts) |
| `EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS` | `1` | Cap on the pause between direct-send retries |

Issue the key in email-service with lanes `auth` and `transactional`, and template prefix `identity.`. Store it next to `SECRET_KEY`.

Auth links (`magic_link_url`, and `invitation_url` when it points at identity) must use a host listed in email-service `EMAIL_AUTH_LINK_HOSTS`. Put the host of `JWT_ISSUER` there. For a local identity at `http://localhost:8000`, that host is `localhost`, and email-service must run with `DEBUG=true`. When email-service `DEBUG=false`, `localhost`, `127.0.0.1`, and `::1` are removed from the list even if the environment includes them, so a production-like email-service needs the public identity host (for example `id.shellui.com`).

Local SMTP settings (`EMAIL_HOST`, `DEFAULT_FROM_EMAIL`) still apply to the fallback and to company access notifications. See [Configuration](configuration.md).

## Related

- [Magic link](magic-link.md)
- [Company access](company-access.md)
- [Action triggers](actions.md)
- [Scheduled jobs](scheduled-jobs.md)
