"""``manage.py generate_env``: print a production env block with fresh secrets.

Runs before Django settings load (see manage.py), so it works with zero env,
no database and no Redis. Secrets go to stdout only. Nothing is logged or written.
"""

from __future__ import annotations

import argparse
import secrets
import sys

from config import env_registry as reg

SECRET_KEY_BYTES = 64  # token_urlsafe(64) is about 86 characters


def _secret_key() -> str:
    return secrets.token_urlsafe(SECRET_KEY_BYTES)


def _jwt_keys(bits: int) -> tuple[str, str]:
    from apps.authapi.jwks import compute_rsa_kid, generate_rsa_key_pair

    private_pem, public_pem = generate_rsa_key_pair(key_size=bits)
    return private_pem.replace('\n', '\\n'), compute_rsa_kid(public_pem)


def _values(host: str, role: str, bits: int) -> dict[str, str]:
    origin = f'https://{host}'
    private_key, kid = _jwt_keys(bits)
    ph = reg.PLACEHOLDER
    return {
        'SECRET_KEY': _secret_key(),
        'DEBUG': 'false',
        'ALLOWED_HOSTS': host,
        'CSRF_TRUSTED_ORIGINS': origin,
        'JWT_ISSUER': origin,
        'JWT_AUDIENCE': 'shellui',
        'JWT_PRIVATE_KEY': f'"{private_key}"',
        'JWT_KEY_ID': kid,
        'REDIS_URL': 'redis://redis:6379/0',
        'POSTGRES_DATABASE_URL': f'postgres://{ph}:{ph}@postgres:5432/identity',
        'SHELLUI_INSTANCE_ROLE': role,
        'OIDC_CLIENTS': f'[{{"client_id":"{ph}","client_secret":"{secrets.token_urlsafe(32)}","redirect_uris":["https://{ph}/oauth/upstream-callback"]}}]',
        'EMAIL_SERVICE_URL': f'https://{ph}',
        'GLOBAL_ISSUER_URL': f'https://{ph}',
        'GLOBAL_JWKS': ph,
        'GLOBAL_CLIENT_ID': ph,
        'GLOBAL_CLIENT_SECRET': ph,
        'PROVISIONING_PUBLIC_KEY': ph,
        'PROVISIONING_ISSUER': f'https://{ph}',
    }


def render(*, host: str, role: str, optional: bool, bits: int = 3072) -> str:
    values = _values(host, role, bits)
    lines = [f'# identity-service, role {role}. Replace every {reg.PLACEHOLDER}.']
    printed: set[str] = set()
    for var in reg.REQUIRED:
        if role not in var.roles:
            continue
        lines.append(f'# {var.comment}')
        lines.append(f'{var.name}={values[var.name]}')
        printed.add(var.name)
        if var.name == 'JWT_PRIVATE_KEY':
            lines.append(f'JWT_KEY_ID={values["JWT_KEY_ID"]}')
            printed.add('JWT_KEY_ID')
    if optional:
        lines.extend(['', '# Optional (defaults shown)'])
        lines.extend(reg.optional_lines(skip=frozenset(printed)))
    return '\n'.join(lines) + '\n'


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog='manage.py generate_env',
        description='Print the required production settings with fresh secrets.',
    )
    parser.add_argument('--host', default=f'{reg.PLACEHOLDER}.example.com', help='Public host, for example id.example.com.')
    parser.add_argument('--role', choices=reg.ROLES, default='standalone')
    parser.add_argument('--optional', action='store_true', help='Also print optional settings with their defaults.')
    parser.add_argument('--bits', type=int, default=3072, help='RSA key size (minimum 2048).')
    parser.add_argument('--example', action='store_true', help='Print .env.example (local development, no secrets).')
    args = parser.parse_args(argv)
    if args.example:
        sys.stdout.write(reg.render_example())
        return 0
    host = args.host.strip().lower().removeprefix('https://').removeprefix('http://').rstrip('/')
    sys.stdout.write(render(host=host, role=args.role, optional=args.optional, bits=args.bits))
    sys.stderr.write('generate_env: this output holds secrets. Store it in a secret manager and do not commit it.\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
