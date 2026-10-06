"""Bind a GitLab SocialAccount to one SocialApp so migration 0015 can scope it."""

from __future__ import annotations

import importlib

from allauth.socialaccount.models import SocialAccount, SocialApp, SocialToken
from django.core.management.base import BaseCommand, CommandError

from apps.companies.models import CompanyMembership, CompanyOAuthClient

_migration = importlib.import_module('apps.authapi.migrations.0015_scope_self_hosted_gitlab_uids')

_BINDING_TOKEN = 'gitlab-uid-scope-binding'


class Command(BaseCommand):
    help = (
        'List GitLab SocialAccount rows migration 0015 cannot scope, or bind one row '
        'to a GitLab SocialApp so the next migrate can prefix its uid.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--account-id', type=int, help='SocialAccount id to bind.')
        parser.add_argument('--social-app-id', type=int, help='GitLab SocialApp id to bind that account to.')

    def handle(self, *args, **options):
        account_id = options['account_id']
        social_app_id = options['social_app_id']
        if (account_id is None) ^ (social_app_id is None):
            raise CommandError('Pass both --account-id and --social-app-id.')
        if account_id is not None:
            self._bind(account_id, social_app_id)
            return
        failures, updates = _migration.gitlab_uid_migration_plan(
            SocialAccount,
            SocialToken,
            CompanyMembership,
            CompanyOAuthClient,
        )
        if not failures:
            self.stdout.write(f'{len(updates)} GitLab account(s) can be scoped by migration 0015.')
            return
        for row_id, reason in failures:
            self.stdout.write(f'social_account_id={row_id}: {reason}')
        ids = ', '.join(str(row_id) for row_id, _reason in failures)
        raise CommandError(
            f'GitLab accounts need a single SocialApp before migrate: {ids}. '
            'Re-run with --account-id and --social-app-id.'
        )

    def _bind(self, account_id: int, social_app_id: int) -> None:
        try:
            account = SocialAccount.objects.get(pk=account_id, provider='gitlab')
        except SocialAccount.DoesNotExist as exc:
            raise CommandError(f'No gitlab SocialAccount with id {account_id}.') from exc
        try:
            app = SocialApp.objects.get(pk=social_app_id, provider='gitlab')
        except SocialApp.DoesNotExist as exc:
            raise CommandError(f'No gitlab SocialApp with id {social_app_id}.') from exc
        SocialToken.objects.filter(account=account).exclude(app=app).delete()
        SocialToken.objects.update_or_create(
            app=app,
            account=account,
            defaults={'token': _BINDING_TOKEN},
        )
        self.stdout.write(
            f'Bound social_account_id={account.id} to social_app_id={app.id}. '
            'Run migrate to prefix a self-hosted uid. gitlab.com stays raw.'
        )
