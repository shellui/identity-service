---
description: The JWT access, refresh, and personal access tokens issued by identity-service, their claims, and how other services verify them with JWKS.
---

# JWT and JWKS

identity-service issues JWT access tokens, refresh tokens, and personal access tokens (PATs). In production they are signed with RS256, and other services verify them with the public keys at `/.well-known/jwks.json`, without sharing `SECRET_KEY`.

## Tokens

| Token | Default lifetime | Variable |
| --- | --- | --- |
| Access token | 5 minutes | `JWT_ACCESS_TOKEN_LIFETIME` |
| Refresh token | 7 days, rotated on every refresh | `JWT_REFRESH_TOKEN_LIFETIME` |
| Personal access token | 30 days | `PERSONAL_ACCESS_TOKEN_LIFETIME` |

### Claims

Besides the standard claims (`iss`, `aud`, `exp`, `iat`, `jti`, and `user_id`), access tokens carry:

| Claim | Content |
| --- | --- |
| `email` | The user's email |
| `company_id` | The company the token is for. A token is valid for one company only |
| `user_metadata` | `name`, `full_name`, `avatar_url`, `is_staff`, `is_company_owner`, `shelluiPreferences`, and `groups` |
| `app_metadata` | `provider`: how the user signed in (`google`, `magic_link`, `personal_access_token`, …) |
| `auth_time` | When the user last signed in. A refresh keeps the original value |
| `pat_id`, `pat_ro`, `pat_agm` | PATs only: the token ID, read-only flag, and global metrics flag |

### Groups claim

`user_metadata.groups` is the sorted list of the user's effective group names (`display_name`) in the token's company. It includes groups where the user is a direct member, plus every parent group reached through nested [SCIM](scim.md) groups. `GET /api/v1/user` returns the same list.

Services that authorize on groups can read this claim directly: membership is already transitive. SCIM user resources list direct memberships only.

## JWKS endpoint

`GET /.well-known/jwks.json` is public and cached for 15 minutes (`Cache-Control: public, max-age=900`):

```bash
curl -s https://auth.example.com/.well-known/jwks.json | jq .
```

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "your_key_id",
      "n": "…",
      "e": "AQAB"
    }
  ]
}
```

Tokens have a `kid` header that matches the active signing key. During a [key rotation](#rotate-the-signing-key), the endpoint lists the previous key too.

## Verify a token

1. Fetch `/.well-known/jwks.json` and cache it for 15 minutes.
2. Read `alg` (expect `RS256`) and `kid` from the JWT header.
3. Pick the JWK with the same `kid`, or try each RSA key when there is no `kid`.
4. Check the signature, `exp`, `iss`, `aud`, and the claims your service needs, such as `company_id`.

With [PyJWT](https://pyjwt.readthedocs.io/):

```python
import jwt
from jwt import PyJWKClient

jwks_client = PyJWKClient("https://auth.example.com/.well-known/jwks.json")

token = "your_access_token_here"
signing_key = jwks_client.get_signing_key_from_jwt(token)
payload = jwt.decode(
    token,
    signing_key.key,
    algorithms=["RS256"],
    audience="shellui",
    issuer="https://auth.example.com",
)
```

In JavaScript, [jose](https://github.com/panva/jose) does the same with `createRemoteJWKSet`.

## Configure signing

With `DEBUG=false`, identity-service refuses to start without an RSA private key, an issuer, and an audience.

| Variable | Required | Description |
| --- | --- | --- |
| `JWT_PRIVATE_KEY` | Production | PEM RSA private key. Use `\n` for newlines in `.env` |
| `JWT_ISSUER` | Production | `iss` claim, for example `https://auth.example.com` |
| `JWT_AUDIENCE` | Production | `aud` claim, for example `shellui` |
| `JWT_PUBLIC_KEY` | No | PEM public key. Derived from the private key when unset |
| `JWT_KEY_ID` | No | `kid`. Defaults to the RFC 7638 JWK thumbprint |
| `JWT_PREVIOUS_PUBLIC_KEY` | No | Previous public key during a rotation, still published in JWKS |
| `JWT_PREVIOUS_KEY_ID` | No | `kid` of the previous key. Derived when unset |
| `JWT_ACCEPT_HS256_LEGACY` | No | `false` by default once RS256 is set. Set `true` only while moving from HS256, when old tokens may still be valid |

Generate a key with `uv run python manage.py generate_jwt_keys`, or with Docker as shown in [Run identity-service](getting-started.md#deploy-to-production). The key is 3072-bit RSA by default (2048 bits minimum).

`SECRET_KEY` is still required for Django sessions and CSRF, but it does not sign JWTs once `JWT_PRIVATE_KEY` is set. Never share it with services that verify tokens.

### Paste the key into Coolify or a secret store

`generate_jwt_keys` prints a quoted `.env` line. In Coolify or any secret UI, paste only the PEM value, not `JWT_PRIVATE_KEY="…"`:

```text
-----BEGIN PRIVATE KEY-----
MIIE…
-----END PRIVATE KEY-----
```

The same text with literal `\n` instead of line breaks also works, as long as there are no surrounding quotes. With the quotes, the key fails to load with `InvalidByte(0, 92)`.

### Local development

With `DEBUG=true` and no `JWT_PRIVATE_KEY`, tokens are signed with HS256 and `SECRET_KEY`, and the JWKS endpoint returns `{"keys":[]}`. To test RS256 locally, set `JWT_PRIVATE_KEY` as in production.

## Rotate the signing key

1. Generate a new key with `generate_jwt_keys`.
2. Move the current public key to `JWT_PREVIOUS_PUBLIC_KEY`, and its `kid` to `JWT_PREVIOUS_KEY_ID` if you set a custom one.
3. Set the new private key as `JWT_PRIVATE_KEY`, and update `JWT_KEY_ID` if you use a custom `kid`.
4. Deploy. New tokens use the new key, and JWKS lists both keys.
5. Wait until every token signed with the old key has expired: the longest of `PERSONAL_ACCESS_TOKEN_LIFETIME` (30 days by default) and `JWT_REFRESH_TOKEN_LIFETIME` (7 days).
6. Remove the `JWT_PREVIOUS_*` variables. If you moved from HS256, set `JWT_ACCEPT_HS256_LEGACY=false`.

## Security notes

- Keep `JWT_PRIVATE_KEY` in a secret manager or a mounted file, and never commit it
- JWKS publishes public keys only, which is expected
- Verifiers should always check `iss` and `aud`
- Keep `JWT_ACCEPT_HS256_LEGACY=true` only for the duration of an HS256 migration

## Related

- [Metrics and access tokens](metrics.md): personal access tokens
- [OAuth login](oauth-login.md): how tokens reach the shell
- [Security hardening](security-hardening.md)
