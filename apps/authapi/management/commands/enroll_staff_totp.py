"""Enroll a TOTP authenticator for a Django staff account."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.authapi.models import StaffAdminGuard
from apps.authapi.staff_totp import generate_totp_secret, provisioning_uri, totp_match_step


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
        parser.add_argument(
            '--show-secret',
            action='store_true',
            help='Print the base32 secret of an unconfirmed enrollment. Nothing secret is printed without this or --show-uri.',
        )
        parser.add_argument(
            '--show-uri',
            action='store_true',
            help='Print the otpauth:// URI (it contains the secret) of an unconfirmed enrollment.',
        )

    def _show(self, guard, user, options, username):
        shown = False
        if options['show_secret']:
            self.stdout.write(guard.secret)
            shown = True
        if options['show_uri']:
            self.stdout.write(provisioning_uri(guard.secret, user.get_username()))
            shown = True
        if not shown:
            self.stdout.write(
                f'Secret stored. Run: manage.py enroll_staff_totp {username} --show-secret '
                '(or --show-uri) to display it.'
            )
        self.stdout.write(f'Confirm with: manage.py enroll_staff_totp {username} --code <code>')

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
        if options['rotate'] or not guard.secret:
            guard.set_secret(generate_totp_secret())
            guard.totp_confirmed_at = None
            guard.save(update_fields=['totp_secret', 'totp_last_step', 'totp_confirmed_at'])
            self._show(guard, user, options, username)
            return

        if not code:
            if guard.totp_confirmed_at:
                raise CommandError('Already enrolled. Pass --rotate to replace the secret.')
            self._show(guard, user, options, username)
            return
        step = totp_match_step(guard.secret, code)
        if step is None:
            raise CommandError('That code does not match.')
        guard.totp_confirmed_at = timezone.now()
        guard.totp_last_step = step
        guard.failed_attempts = 0
        guard.locked_until = None
        guard.save(update_fields=['totp_confirmed_at', 'totp_last_step', 'failed_attempts', 'locked_until'])
        self.stdout.write('Authenticator confirmed.')
