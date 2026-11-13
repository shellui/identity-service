"""Seed the local dev stack: company 1, an admin superuser and a magic link user.

Local only. Refuses to run unless DEBUG is true and IDENTITY_DEV_SEED=true.
Idempotent: existing rows are left as they are, so a rerun never resets the
admin password or overwrites company settings changed in the admin.
"""

import os

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction

from apps.companies.models import Company, CompanyMembership, CompanyOAuthRedirect

COMPANY_ID = 1
COMPANY_NAME = 'Shellui Dev'
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin'
ADMIN_EMAIL = 'admin@localhost'
DEV_USERNAME = 'dev'
DEV_EMAIL = 'dev@localhost'
# Loopback origins always seeded. IDENTITY_DEV_PUBLIC_HOST adds the same ports on a
# LAN/Tailscale host so OAuth redirect_uri checks match browsers that are not on localhost.
_DEV_ORIGIN_PORTS = (
    (4000, 'Shell'),
    (5173, 'Admin'),
    (5174, 'Dashboard'),
    (5175, 'Files'),
    (5176, 'Playground'),
)


def _dev_oauth_origins() -> list[tuple[str, str]]:
    hosts = ['localhost']
    extra = os.getenv('IDENTITY_DEV_PUBLIC_HOST', '').strip()
    if extra and extra.lower() not in {'localhost', '127.0.0.1'} and extra not in hosts:
        hosts.append(extra)
    origins: list[tuple[str, str]] = []
    for host in hosts:
        for port, label in _DEV_ORIGIN_PORTS:
            suffix = '' if host == 'localhost' else f' ({host})'
            origins.append((f'http://{host}:{port}', f'{label}{suffix}'))
    return origins


def seed_allowed() -> bool:
    flag = os.getenv('IDENTITY_DEV_SEED', '').strip().lower() in {'1', 'true', 'yes', 'on'}
    return bool(settings.DEBUG) and flag


class Command(BaseCommand):
    help = 'Local dev only: create company 1, admin/admin and dev@localhost. Needs DEBUG and IDENTITY_DEV_SEED=true.'

    def handle(self, *args, **options):
        if not seed_allowed():
            raise CommandError('seed_dev refused: it needs DEBUG=true and IDENTITY_DEV_SEED=true (local dev only).')
        with transaction.atomic():
            company, created = Company.all_objects.get_or_create(
                pk=COMPANY_ID,
                defaults={
                    'name': COMPANY_NAME,
                    'access_mode': Company.ACCESS_PUBLIC,
                    'enable_magic_link': True,
                },
            )
            if created:
                self._fix_sequence()
            for base_url, label in _dev_oauth_origins():
                CompanyOAuthRedirect.objects.get_or_create(
                    company=company, base_url=base_url, defaults={'label': label}
                )

            User = get_user_model()
            admin, admin_created = User.objects.get_or_create(
                username=ADMIN_USERNAME,
                defaults={'email': ADMIN_EMAIL, 'is_staff': True, 'is_superuser': True},
            )
            if admin_created:
                admin.set_password(ADMIN_PASSWORD)
                admin.save()
            dev, dev_created = User.objects.get_or_create(
                username=DEV_USERNAME, defaults={'email': DEV_EMAIL}
            )
            if dev_created:
                dev.set_unusable_password()
                dev.save()
            for user in (admin, dev):
                CompanyMembership.objects.get_or_create(company=company, user=user)
            company.owners.add(admin)

        self.stdout.write(
            f'seed_dev: company {company.pk} {"created" if created else "kept"}, '
            f'admin {"created" if admin_created else "kept"}, dev user {"created" if dev_created else "kept"}'
        )

    def _fix_sequence(self):
        """Explicit id 1 does not move the Postgres sequence, so the next company would clash."""
        if connection.vendor != 'postgresql':
            return
        table = Company._meta.db_table
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                f'(SELECT MAX(id) FROM {table}))'
            )
