# Send mail with email-service

identity-service sends sign-in and invitation mail through Shellui email-service when `EMAIL_SERVICE_API_KEY` is set. It also forwards every other webhook event so a company email rule can send its own message. With no key, SMTP (or the console backend when `DEBUG=true`) stays in place and no event rows are written.

## Direct send

Magic links and invitations call `POST /api/v1/send`. identity-service does not set `lane`. The template key selects the auth lane.

| Message | Template | TTL |
| ------- | -------- | --- |
| Magic link | `identity.auth.magic_link.requested` | 120s |
| Invitation | `identity.user.invited` | 300s |

The idempotency key is stable for that magic-link row or that invitation. Retries send the same key and the same JSON body. The key does not contain the magic-link token, and identity-service does not log the token or the API key.

A company Shellui Actions rule for either event still replaces this send. The webhook payload carries `magic_link_url` or `invitation_url`, and your endpoint delivers the message. See [Action triggers](actions.md).

These two events are not also posted to `POST /api/v1/events`. The catalog enables them by default, so a second post would send a second message. `/send` still goes out when a company turns the email rule off.

## When SMTP is used

identity-service uses SMTP in two cases:

- `EMAIL_SERVICE_API_KEY` is unset
- email-service cannot be reached after the caller retry policy (connection errors, redirects, and HTTP 5xx)

`409 lane_paused` and `429` are retried with the same idempotency key. The wait follows `Retry-After`, capped by `EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS` (default `1` second) so a sign-in request does not wait out the full webhook backoff. After those retries, identity-service does not send that message over SMTP.

`422 recipient_suppressed` is not retried and is not sent over SMTP. The API returns that code.

`400`, `401`, `403`, and `404` are not retried. The API returns **503** `email_unavailable`.

If SMTP also fails, the API returns **503** and this body:

```json
{"error_code": "email_unavailable"}
```

There is no translated sentence in the JSON. A magic-link request that cannot be mailed does not keep the token. An invitation that cannot be mailed is not stored, so the same POST can be retried.

An invitation with no `app_url` stays on the SMTP templates. The email-service template requires `invitation_url`, and identity-service allows that field to be empty.

## Event forwarding

Every webhook event except the two direct-send templates is posted to `POST /api/v1/events` after the database commit. Sign-in events (`identity.auth.login.succeeded` and `identity.auth.login.failed`) stay in the [event log](event-log.md) only.

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

Delivery uses the same outbox and `manage.py retry_webhooks` cron as Shellui Actions. A failed post is retried with the webhook backoff (30s, doubling, capped at 1 hour, 8 attempts). `400`, `401`, `403`, `404`, and `422` are not retried. The request that emitted the event does not wait for this HTTP call.

Unset `EMAIL_SERVICE_API_KEY` and identity-service does not insert these rows.

## Configuration

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `EMAIL_SERVICE_URL` | `https://email.shellui.com` | Origin only. identity-service appends `/api/v1/send` and `/api/v1/events` |
| `EMAIL_SERVICE_API_KEY` | empty | Service key (`esk_`). Sent as `Authorization: Bearer` |
| `EMAIL_SERVICE_TIMEOUT_SECONDS` | `5` | HTTP timeout for one attempt |
| `EMAIL_SERVICE_SEND_ATTEMPTS` | `3` | Attempts for one direct send, or for one event-delivery try |
| `EMAIL_SERVICE_RETRY_MAX_SLEEP_SECONDS` | `1` | Cap on the pause between direct-send retries |

Issue the key in email-service with lanes `auth` and `transactional`, and template prefix `identity.`. Store it next to `SECRET_KEY`. Local SMTP settings (`EMAIL_HOST`, `DEFAULT_FROM_EMAIL`) still apply to the fallback and to company access notifications. See [Configuration](configuration.md).

## Related

- [Magic link](magic-link.md)
- [Company access](company-access.md)
- [Action triggers](actions.md)
- [Scheduled jobs](scheduled-jobs.md)
