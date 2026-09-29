"""Report auth users whose email differs only by case or duplicates."""

from __future__ import annotations

from collections import defaultdict

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from apps.scim.email_normalization import normalize_scim_email


class Command(BaseCommand):
    help = 'List users that share the same normalized email (case-insensitive duplicates).'

    def handle(self, *args, **options):
        User = get_user_model()
        buckets: dict[str, list[int]] = defaultdict(list)
        for pk, email in User.objects.values_list('pk', 'email'):
            key = normalize_scim_email(email or '')
            if not key:
                continue
            buckets[key].append(pk)

        duplicates = {email: pks for email, pks in buckets.items() if len(pks) > 1}
        if not duplicates:
            self.stdout.write(self.style.SUCCESS('No duplicate emails found.'))
            return

        self.stdout.write(self.style.WARNING(f'Found {len(duplicates)} duplicate email bucket(s):'))
        for email in sorted(duplicates):
            pks = duplicates[email]
            self.stdout.write(f'  {email}: user ids {pks}')
