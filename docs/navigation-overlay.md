---
description: Read, replace, and clear the navigation overlay saved for the signed-in account.
---

# Sync a navigation overlay

`/api/v1/navigation-overlay` stores the navigation overlay for the signed-in account. Call it with the same bearer access token as `GET /api/v1/user` and `GET /api/v1/preferences`. The access token does not include this document.

The record is one JSON document per account. It is shared by every company that account belongs to. The token `company_id` still has to be a company the account is a member of, same as preferences.

## Call the endpoint

Pass the access token in `Authorization`. `company_id` comes from the token. A `company_id` query value has to match that claim.

```http
GET /api/v1/navigation-overlay
Authorization: Bearer your_access_token_here
```

| Method | Result |
| --- | --- |
| `GET` | `200` with the saved document, or `200` with JSON `null` when nothing is saved |
| `PUT` | Replaces the saved document after validation. `200` returns the saved document |
| `DELETE` | Removes the saved document. `204` with an empty body |

A missing or invalid token returns `401`. A `user_id` or `userId` that is not the signed-in account returns `403`, and the saved document stays as it was. Repeating `DELETE` after the document is already gone returns `204`.

## Document shape

`PUT` sends one JSON object. These fields are required. Any other field is rejected. `company_id`, `user_id`, and `userId` are not part of the document: `company_id` selects the company, and `user_id` or `userId` must be the signed-in account or the request returns `403`.

```json
{
  "version": 1,
  "installedApps": [
    {
      "id": "notes",
      "name": "Notes",
      "url": "https://notes.example.com/",
      "capabilities": ["theme", "locale", "navigate"]
    }
  ],
  "order": ["notes", "/home"],
  "hiddenPaths": ["/archive"],
  "updatedAt": "2026-11-20T02:43:00Z"
}
```

`version` is the number `1`. `installedApps`, `order`, and `hiddenPaths` are arrays. `updatedAt` is an ISO-8601 timestamp with a timezone.

Each installed app includes `id`, `name`, `url`, and `capabilities`. `url` is an `https` URL with a host and no username or password. Optional fields:

- `path`: a navigation path, such as `notes` or `/notes`
- `iconUrl`: another `https` URL
- `firstParty`: `true` or `false`. Omit it for a third-party app

`order` and `hiddenPaths` hold navigation paths or app ids. `..`, spaces, and a second scheme are rejected.

## Capabilities

A third-party app may list only these names: `theme`, `locale`, `ui`, `navigate`, `storage`, and `ai`.

`auth` on a third-party app is rejected. Any other name is rejected too. Set `firstParty` to `true` when the app ships inside the same product and needs `auth`. Unknown names are still rejected on a first-party app.

## Limits

identity-service rejects the `PUT` before it writes a row when a limit is exceeded:

- The raw body is larger than `64 KB`
- `installedApps` has more than 100 entries
- `order` or `hiddenPaths` has more than 200 entries

A rejected `PUT` leaves the previous document in place.

## Errors

| Case | Response |
| --- | --- |
| No bearer token, or a token that does not verify | `401` |
| `user_id` names a different account | `403` `Forbidden.` |
| `company_id` does not match the token, or the account is not a member of that company | `403` |
| Body is not the version 1 document | `400` with `error` |
| Body is larger than `64 KB`, or `installedApps` has more than 100 entries | `400` with `error` |
| Read-only personal access token on `PUT` or `DELETE` | `403` |
| `PUT` or `DELETE` with a missing or stale `If-Match` once a document exists | `412` with `error`, and the current `ETag` header. Read the document before you retry: it can change again |

`GET` with a read-only personal access token still returns the saved document.
