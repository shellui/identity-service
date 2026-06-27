# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

<!---
## [Unreleased] - yyyy-mm-dd

### ✨ Feature – for new features
### 🛠 Improvements – for general improvements
### 🚨 Changed – for changes in existing functionality
### ⚠️ Deprecated – for soon-to-be removed features
### 📚 Documentation – for documentation update
### 🗑 Removed – for removed features
### 🐛 Bug Fixes – for any bug fixes
### 🔒 Security – in case of vulnerabilities
### 🏗 Chore – for tidying code

See for sample https://raw.githubusercontent.com/favoloso/conventional-changelog-emoji/master/CHANGELOG.md
-->



## [Unreleased] - yyyy-mm-dd

### 🚨 Changed

- OAuth provider credentials are company-scoped only; global `GITHUB_*` / `GOOGLE_*` / `MICROSOFT_*` environment variables are removed.

### 🗑 Removed

- Global OAuth env vars from `docker-compose.yml`, `.env.example`, and `config/settings.py`.

## [0.2.0] - 2026-06-26

### ✨ Feature

- Added **JWKS** endpoint at `GET /.well-known/jwks.json` for public RS256 key discovery.
- Added **RS256 JWT signing** when `JWT_PRIVATE_KEY` is configured.
- Added `python manage.py generate_jwt_keys` to generate RSA key pairs and suggested env vars.
- Tokens now include a `kid` header for key rotation and verifier key selection.

### 🔒 Security

- Production (`DEBUG=false`) requires `JWT_PRIVATE_KEY`; JWTs are no longer signed with `SECRET_KEY` in production.
- External services can verify JWTs via JWKS without sharing `SECRET_KEY`.
- Optional `JWT_PREVIOUS_PUBLIC_KEY` supports safe key rotation with overlapping JWKS keys.
- `JWT_ACCEPT_HS256_LEGACY` (default `true`) allows gradual migration from HS256; disable after cutover.

### 📚 Documentation

- Added [docs/jwks.md](docs/jwks.md) with configuration, verification, rotation, and security guidance.
- Updated README, `.env.example`, and release checklist for JWT key requirements.

## [0.1.0] - 2026-05-23

### ✨ Feature

- Initial release of `identity-service`.
- Added **API scaffolding** for **identity endpoints**.
- Added **configuration** for **local development** and **environment variables**.
- Added project setup for future **authentication** and **user management** workflows.
- Added OAuth login support for GitHub, Google, and Microsoft providers.
- Added JWT session lifecycle endpoints (`/api/v1/token`, `/api/v1/logout`) and authenticated user profile APIs.
- Added staff directory endpoints for users and groups administration workflows.

### 🛠 Improvements

- Added OpenAPI documentation with drf-spectacular integration and improved API tagging.
- Expanded local container workflow with migration-on-start entrypoint.

### 🚨 Changed

- Updated Docker runtime to persist SQLite data at `/app/data/db.sqlite3`.
- Added Docker volume declaration to avoid SQLite reset when the container or VM restarts.

### 📚 Documentation

- Added clearer Docker run examples using a named volume (`identity-service-data`) for persistent data.
