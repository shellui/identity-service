# JWT signing and JWKS

identity-service issues JWT access and refresh tokens for ShellUI sessions and personal access tokens (PATs). External services can verify those tokens **without** sharing `SECRET_KEY` by fetching the public keys from the JWKS endpoint.

## Endpoint

| Item | Value |
|------|--------|
| URL | `GET /.well-known/jwks.json` |
| Auth | None (public) |
| Cache | `Cache-Control: public, max-age=900` (15 minutes) |

Example:

```bash
curl -s https://auth.example.com/.well-known/jwks.json | jq .
```

Response shape (RS256):

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "abc123...",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

Tokens include a `kid` header matching the active signing key. Verifiers should select the JWK with the same `kid`, or try each key when `kid` is absent.

## Configuration

### Production (required)

Set an RSA private key. The service refuses to start in production (`DEBUG=false`) without it.

```bash
# Generate a key pair and suggested env vars
python manage.py generate_jwt_keys
```

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_PRIVATE_KEY` | Yes (production) | PEM-encoded RSA private key. Use `\n` for newlines in `.env`. |
| `JWT_PUBLIC_KEY` | No | PEM public key. Derived from the private key when omitted. |
| `JWT_KEY_ID` | No | Key id (`kid`). Defaults to RFC 7638 JWK thumbprint. |
| `JWT_PREVIOUS_PUBLIC_KEY` | No | Previous public key during rotation (still published in JWKS). |
| `JWT_PREVIOUS_KEY_ID` | No | `kid` for the previous key (auto-derived if omitted). |
| `JWT_ACCEPT_HS256_LEGACY` | No | Default `true`. Accept old HS256 tokens signed with `SECRET_KEY` during migration. Set `false` once all clients use RS256. |

`SECRET_KEY` remains required for Django sessions and CSRF. It is **not** used for JWT signing when `JWT_PRIVATE_KEY` is set.

### Local development

When `DEBUG=true` and `JWT_PRIVATE_KEY` is unset, JWTs continue to use HS256 with `SECRET_KEY` (backward compatible). The JWKS endpoint returns `{"keys":[]}`.

For local RS256 testing, set `JWT_PRIVATE_KEY` the same way as production.

## Verifying tokens (consumer services)

1. Fetch `/.well-known/jwks.json` and cache it (respect `Cache-Control`, or refresh every 15 minutes).
2. Parse the JWT header; read `alg` (expect `RS256`) and `kid`.
3. Find the matching JWK by `kid`, or try each RSA key.
4. Verify signature, `exp`, and any claims your service requires (`company_id`, `email`, etc.).

Libraries: [PyJWT](https://pyjwt.readthedocs.io/) with `PyJWKClient`, [jose](https://github.com/panva/jose), or your language’s JWT/JWKS stack.

Example with PyJWT:

```python
import jwt
from jwt import PyJWKClient

JWKS_URL = "https://auth.example.com/.well-known/jwks.json"
jwks_client = PyJWKClient(JWKS_URL)

token = "..."  # Bearer token
signing_key = jwks_client.get_signing_key_from_jwt(token)
payload = jwt.decode(
    token,
    signing_key.key,
    algorithms=["RS256"],
    options={"verify_aud": False},
)
```

## Key rotation

1. Generate a new key pair (`python manage.py generate_jwt_keys`).
2. Move the current public key to `JWT_PREVIOUS_PUBLIC_KEY` (and `JWT_PREVIOUS_KEY_ID` if you set a custom `kid`).
3. Set the new private key as `JWT_PRIVATE_KEY` and update `JWT_KEY_ID` if needed.
4. Deploy. New tokens use the new key; JWKS lists both keys.
5. Wait until all outstanding tokens expire (up to 90 days for PATs, 7 days for refresh tokens).
6. Remove `JWT_PREVIOUS_*` and set `JWT_ACCEPT_HS256_LEGACY=false` if migrating from HS256.

## Security notes

| Topic | Guidance |
|-------|----------|
| Private key storage | Use a secret manager or mounted file. Never commit `JWT_PRIVATE_KEY`. |
| Key size | Minimum 2048-bit RSA; `generate_jwt_keys` defaults to 3072 bits. |
| JWKS exposure | Only public keys are published. This is expected and safe. |
| HS256 legacy | Disable with `JWT_ACCEPT_HS256_LEGACY=false` after migration. |
| `SECRET_KEY` | Still required; do not share it with token verifiers when using RS256. |
