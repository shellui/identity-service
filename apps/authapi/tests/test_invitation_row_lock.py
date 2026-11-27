"""Revoking and deleting an invitation lock the invitation row, not the nullable ``invited_by`` join.

SQLite ignores ``FOR UPDATE``, so the PostgreSQL error ("FOR UPDATE cannot be applied to the
nullable side of an outer join") only shows when this module runs against Postgres, which CI
does in the "Postgres row lock regression" step. The query shape is asserted on every backend.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.invitation_views import _company_invitation_lock_queryset
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyInvitation

User = get_user_model()


@override_settings(ALLOWED_HOSTS=['testserver'], AUTH_RATE_LIMIT_ENABLED=False)
class InvitationRowLockTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Lock Co', slug='inv-lock-co', access_mode=Company.ACCESS_INVITE)
        self.owner = User.objects.create_user('inv-lock-owner', 'owner@inv-lock.test', 'x')
        set_company_access(self.company, self.owner, enabled=True)
        self.company.owners.add(self.owner)
        self.client = APIClient()
        self.client.force_authenticate(user=self.owner)

    def _invitation(self, email, *, invited_by, status=CompanyInvitation.STATUS_PENDING):
        return CompanyInvitation.objects.create(
            company=self.company, email=email, invited_by=invited_by, status=status
        )

    def _revoke(self, pk):
        return self.client.post(f'/api/v1/invitations/{pk}/revoke?company_id={self.company.pk}')

    def _delete(self, pk):
        return self.client.delete(f'/api/v1/invitations/{pk}?company_id={self.company.pk}')

    def test_lock_query_targets_the_invitation_row_only(self):
        qs = _company_invitation_lock_queryset(self.company, 1)
        self.assertTrue(qs.query.select_for_update)
        self.assertEqual(tuple(qs.query.select_for_update_of), ('self',))
        if connection.vendor == 'postgresql':
            sql = str(qs.query).upper().replace('"', '')
            self.assertIn('FOR UPDATE OF', sql)
            self.assertIn('COMPANIES_COMPANYINVITATION', sql.split('FOR UPDATE OF', 1)[1])

    def test_revoke_works_with_and_without_an_inviter(self):
        for email, inviter in (('with@inv-lock.test', self.owner), ('without@inv-lock.test', None)):
            invitation = self._invitation(email, invited_by=inviter)
            with self.subTest(inviter=bool(inviter)):
                response = self._revoke(invitation.pk)
                self.assertEqual(response.status_code, 200, response.content)
                invitation.refresh_from_db()
                self.assertEqual(invitation.status, CompanyInvitation.STATUS_REVOKED)

    def test_delete_works_with_and_without_an_inviter(self):
        for email, inviter in (('with@inv-lock.test', self.owner), ('without@inv-lock.test', None)):
            invitation = self._invitation(email, invited_by=inviter, status=CompanyInvitation.STATUS_REVOKED)
            with self.subTest(inviter=bool(inviter)):
                response = self._delete(invitation.pk)
                self.assertEqual(response.status_code, 204, response.content)
                self.assertFalse(CompanyInvitation.objects.filter(pk=invitation.pk).exists())

    def test_delete_of_a_pending_invitation_is_still_refused(self):
        invitation = self._invitation('pending@inv-lock.test', invited_by=None)
        self.assertEqual(self._delete(invitation.pk).status_code, 409)
        self.assertTrue(CompanyInvitation.objects.filter(pk=invitation.pk).exists())

    def test_unknown_invitation_is_404(self):
        self.assertEqual(self._revoke(999999).status_code, 404)
