# identity-service

identity-service is the Shellui service for sign-in, companies, and tokens. People sign in with OAuth, a magic link, or SAML 2.0. A shell with `backend.type` set to `shellui` sends that sign-in here. storage-service, hosting-service, and email-service verify the JSON Web Tokens (JWTs) this service issues.

## What the image contains

You use this image to run identity-service in production. Gunicorn listens on port 8000.

| Piece | Value |
| --- | --- |
| Base image | `python:3.14-slim` |
| Port | `8000` |
| Entrypoint | `/app/tools/docker-entrypoint.sh` |
| User | `appuser` |
| Data volume | `/app/data` |

The entrypoint starts as root, creates `/app/data`, and runs Gunicorn and the scheduler as `appuser`. The default command is `web`. Pass `worker` to run the scheduler without Gunicorn.

Gunicorn binds `0.0.0.0:8000`. A `PORT` setting does not change the port.

## Start the image

Start Redis, then start identity-service on the same network. Replace `your_secret_key_here` and `your_jwt_private_key_here` before you run the commands. With `DEBUG=false`, the image refuses `your_secret_key_here` and any `SECRET_KEY` under 50 characters.

```bash
docker network create identity-net
docker run -d --name redis --network identity-net redis:8-alpine
docker run --rm --name identity-service \
  --network identity-net \
  -p 8000:8000 \
  -v identity-data:/app/data \
  -e SECRET_KEY=your_secret_key_here \
  -e DEBUG=false \
  -e ALLOWED_HOSTS=auth.example.com \
  -e CSRF_TRUSTED_ORIGINS=https://auth.example.com \
  -e JWT_ISSUER=https://auth.example.com \
  -e JWT_AUDIENCE=shellui \
  -e JWT_PRIVATE_KEY=your_jwt_private_key_here \
  -e REDIS_URL=redis://redis:6379/0 \
  -e POSTGRES_DATABASE_URL= \
  shellui/identity-service:latest
```

The `--rm` flag removes the container on exit. The named volume `identity-data` keeps `/app/data`.

Compose starts the same containers. With an empty `POSTGRES_DATABASE_URL`, the service writes SQLite on `identity-data`.

```yaml
services:
  identity-service:
    image: shellui/identity-service:latest
    ports:
      - "8000:8000"
    environment:
      SECRET_KEY: your_secret_key_here
      DEBUG: "false"
      ALLOWED_HOSTS: auth.example.com
      CSRF_TRUSTED_ORIGINS: https://auth.example.com
      JWT_ISSUER: https://auth.example.com
      JWT_AUDIENCE: shellui
      JWT_PRIVATE_KEY: your_jwt_private_key_here
      REDIS_URL: redis://redis:6379/0
      POSTGRES_DATABASE_URL: ""
    volumes:
      - identity-data:/app/data
    depends_on:
      - redis
  redis:
    image: redis:8-alpine
volumes:
  identity-data:
```

Print a block with a real `SECRET_KEY` and `JWT_PRIVATE_KEY`. Replace every `change-me` in the output. The database URL in that block uses the host name `postgres`.

```bash
docker run --rm shellui/identity-service:latest \
  python manage.py generate_env --host auth.example.com
```

## Required environment variables

A standalone instance with `DEBUG` set to `false` needs these variables to start. That is the image default.

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Signs the session cookie and the cross-site request token. At least 50 characters |
| `DEBUG` | `false` in this image. Set `true` only for local development |
| `ALLOWED_HOSTS` | Public host names, comma-separated, no scheme |
| `CSRF_TRUSTED_ORIGINS` | Full HTTPS origin for admin and sign-in forms |
| `JWT_ISSUER` | `iss` claim. The public identity URL |
| `JWT_AUDIENCE` | `aud` claim. The generated value is `shellui` |
| `JWT_PRIVATE_KEY` | RS256 signing key on one line, with `\n` between lines |
| `REDIS_URL` | Shared cache and the job broker |
| `POSTGRES_DATABASE_URL` | PostgreSQL URL. Empty uses SQLite at `/app/data/db.sqlite3` |

Leave `SHELLUI_INSTANCE_ROLE` unset for this standalone set. A `global` or `region` instance needs more variables. Optional settings stay at their defaults until you set them. The [configuration reference](https://docs.shellui.com/identity/configuration) lists every variable.

## Image tags

Publishing a release adds the version and the minor line. A stable release also moves `latest`.

| Tag | What it tracks |
| --- | --- |
| `X.Y.Z` | That release, for example `0.11.0` |
| `X.Y` | Newest patch on that minor line, for example `0.11` |
| `latest` | Stable releases. A pre-release does not move it |

## Container health check

The image probes `GET /health/live` on port 8000. During the first 60s it probes every 5s, then every 30s.

The probe does not query the database or Redis. A `worker` container does not listen on port 8000. The check passes while the scheduler is PID 1.

## Project links

Source, docs, and the MIT license:

- [identity-service on GitHub](https://github.com/shellui/identity-service)
- [identity-service docs](https://docs.shellui.com/identity)
- [Changelog](https://github.com/shellui/identity-service/blob/develop/CHANGELOG.md)
- [MIT license](https://github.com/shellui/identity-service/blob/develop/LICENSE)
- [Shellui](https://shellui.com)
