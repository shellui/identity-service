# identity-service

Sign-in, companies and tokens for Shellui apps.

[![CI](https://github.com/shellui/identity-service/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/shellui/identity-service/actions/workflows/ci.yml)
[![Docker Hub](https://img.shields.io/docker/v/shellui/identity-service?sort=semver&label=docker)](https://hub.docker.com/r/shellui/identity-service)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

identity-service is the auth backend a Shellui shell talks to when you set `backend.type: "shellui"`. It signs users in with OAuth (15 providers), SAML 2.0 or magic links, issues RS256 JWTs, and publishes its public keys at `/.well-known/jwks.json`. storage-service, hosting-service and email-service verify those tokens. Each company gets its own sign-in methods, join mode, SCIM provisioning and webhooks.

## Get started

You need Docker and Git.

```bash
git clone https://github.com/shellui/identity-service.git
cd identity-service
cp .env.example .env   # then set SECRET_KEY
docker compose up --build
```

The API runs on [http://localhost:8000](http://localhost:8000). On an empty database, `/` shows a one-time form to create the first superuser. `/admin/` is Django admin and `/api/docs/` is the OpenAPI reference.

Point a Shellui app at it:

```ts
backend: {
  type: 'shellui',
  url: 'http://localhost:8000',
}
```

The full path, from an empty folder to a working sign-in, is in [Run identity-service](docs/getting-started.md).

## Configuration

`.env.example` lists only the required settings. For production, `python manage.py generate_env --host auth.example.com` prints them with a fresh `SECRET_KEY` and `JWT_PRIVATE_KEY`.

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Django sessions and CSRF. Also signs JWTs in local development |
| `JWT_PRIVATE_KEY` | RS256 signing key, required when `DEBUG=false` |
| `JWT_ISSUER`, `JWT_AUDIENCE` | Claims every verifier checks |
| `REDIS_URL` | Required when `DEBUG=false`. Rate limits, token denylist and scheduled jobs |
| `SHELLUI_INSTANCE_ROLE` | Unset for standalone, `global` or `region` for multi-region |

Every setting is in [Configuration](docs/configuration.md).

## Documentation

The handbook lives in [`docs/`](docs/index.md) and is published at [docs.shellui.com/identity](https://docs.shellui.com/identity).

- [OAuth login](docs/oauth-login.md) and [OAuth providers](docs/oauth-providers.md)
- [SAML](docs/saml.md), [magic links](docs/magic-link.md) and [desktop apps](docs/desktop-apps.md)
- [Company access](docs/company-access.md) and [SCIM](docs/scim.md)
- [JWKS and key rotation](docs/jwks.md) and [instance roles](docs/instance-roles.md)
- [Webhooks](docs/actions.md), [event log](docs/event-log.md) and [scheduled jobs](docs/scheduled-jobs.md)
- [Security hardening](docs/security-hardening.md) and [upgrading](docs/upgrading.md)

## Development

```bash
uv sync
uv run python manage.py migrate
uv run python manage.py runserver
uv run python manage.py test
```

To preview the docs site, clone [shellui/shellui](https://github.com/shellui/shellui) next to this repository and run `DOCS_SERVICES=identity pnpm docs:start` there. See [Build the docs site](https://github.com/shellui/shellui/blob/main/docs/docs-site.md).

Releases go to Docker Hub as `shellui/identity-service`. The checklist is in [PUBLISH.md](PUBLISH.md) and changes are in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Open an issue or a pull request against `develop`. CI runs the tests, a dependency audit, a secret scan, a link check and the docs build. Coding agents start with [AGENTS.md](AGENTS.md).

## Shellui projects

| Project | What it does |
| --- | --- |
| [shellui](https://github.com/shellui/shellui) | The shell, CLI and SDK |
| [admin](https://github.com/shellui/admin) | Administration app inside the shell |
| [files](https://github.com/shellui/files) | File explorer for storage-service |
| [identity-service](https://github.com/shellui/identity-service) | Sign-in, companies and tokens |
| [storage-service](https://github.com/shellui/storage-service) | File storage |
| [hosting-service](https://github.com/shellui/hosting-service) | Deploys and serves Shellui apps |
| [email-service](https://github.com/shellui/email-service) | Templates and sends email |
| [skills](https://github.com/shellui/skills) | Agent Skills for coding agents |
| [playground](https://github.com/shellui/playground) | Live demo of the shell |

## License

[MIT](LICENSE)
