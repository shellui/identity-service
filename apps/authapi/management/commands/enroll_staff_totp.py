"""Enroll a TOTP authenticator for a Django staff account."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.authapi.models import StaffAdminGuard
from apps.authapi.staff_totp import generate_totp_secret, provisioning_uri, totp_matches


class Command(BaseCommand):
    help = 'Enroll a TOTP authenticator for a Django staff account (required when DEBUG is false).'

    def add_arguments(self, parser):
        parser.add_argument('username')
        parser.add_argument(
            '--code',
            default='',
            help='Current 6-digit authenticator code. Confirms the stored secret.',
        )
        parser.add_argument(
            '--rotate',
            action='store_true',
            help='Replace the secret. Confirm the new secret with --code on a later run.',
        )

    def handle(self, *args, **options):
        User = get_user_model()
        username = options['username']
        try:
            user = User.objects.get(**{User.USERNAME_FIELD: username})
        except User.DoesNotExist as exc:
            raise CommandError(f'No account named {username!r}.') from exc
        if not (user.is_staff or user.is_superuser):
            raise CommandError('That account is not a Django staff account.')

        guard, _created = StaffAdminGuard.objects.get_or_create(user=user)
        code = (options['code'] or '').strip()
        if options['rotate'] or not guard.totp_secret:
            secret = generate_totp_secret()
            guard.totp_secret = secret
            guard.totp_confirmed_at = None
            guard.save(update_fields=['totp_secret', 'totp_confirmed_at'])
            self.stdout.write(secret)
            self.stdout.write(provisioning_uri(secret, user.get_username()))
            self.stdout.write(f'Confirm with: manage.py enroll_staff_totp {username} --code <code>')
            return

        if guard.totp_confirmed_at and not code:
            raise CommandError('Already enrolled. Pass --rotate to replace the secret.')
        if not code:
            self.stdout.write(guard.totp_secret)
            self.stdout.write(provisioning_uri(guard.totp_secret, user.get_username()))
            self.stdout.write(f'Confirm with: manage.py enroll_staff_totp {username} --code <code>')
            return
        if not totp_matches(guard.totp_secret, code):
            raise CommandError('That code does not match.')
        guard.totp_confirmed_at = timezone.now()
        guard.failed_attempts = 0
        guard.locked_until = None
        guard.save(update_fields=['totp_confirmed_at', 'failed_attempts', 'locked_until'])
        self.stdout.write('Authenticator confirmed.')
