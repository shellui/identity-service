from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings

from apps.companies.access import (
    ERROR_ACCESS_DENIED,
    ERROR_ACCESS_PENDING,
    apply_company_join,
    email_matches_allowed_domains,
    is_company_access_enabled,
    normalize_allowed_domains,
    notify_user_access_enabled,
    set_company_access,
)
from apps.companies.models import Company

User = get_user_model()


class DomainHelpersTests(TestCase):
    def test_normalize_allowed_domains(self):
        self.assertEqual(
            normalize_allowed_domains(['@Acme.COM', 'acme.com', ' other.io ', '']),
            ['acme.com', 'other.io'],
        )

    def test_email_matches_allowed_domains(self):
        self.assertTrue(email_matches_allowed_domains('alice@acme.com', ['acme.com']))
        self.assertTrue(email_matches_allowed_domains('bob@mail.acme.com', ['acme.com']))
        self.assertFalse(email_matches_allowed_domains('eve@evil.com', ['acme.com']))
        self.assertFalse(email_matches_allowed_domains('nodomain', ['acme.com']))


@override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
class CompanyJoinTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Acme')
        self.owner = User.objects.create_user(
            username='owner',
            email='owner@acme.com',
            password='x',
        )
        set_company_access(self.company, self.owner, enabled=True)
        self.company.owners.add(self.owner)

    def test_public_join_allows_access(self):
        user = User.objects.create_user(username='u1', email='u1@example.com', password='x')
        decision = apply_company_join(self.company, user, email=user.email)
        self.assertTrue(decision.allowed)
        self.assertTrue(self.company.members.filter(pk=user.pk).exists())
        self.assertTrue(is_company_access_enabled(self.company, user))

    def test_domain_match_allows_access(self):
        self.company.access_mode = Company.ACCESS_DOMAIN
        self.company.allowed_email_domains = ['acme.com']
        self.company.save()
        user = User.objects.create_user(username='u2', email='u2@acme.com', password='x')
        decision = apply_company_join(self.company, user, email=user.email)
        self.assertTrue(decision.allowed)
        self.assertTrue(is_company_access_enabled(self.company, user))

    def test_domain_mismatch_blocks_and_emails_admin(self):
        self.company.access_mode = Company.ACCESS_DOMAIN
        self.company.allowed_email_domains = ['acme.com']
        self.company.save()
        user = User.objects.create_user(username='u3', email='u3@other.com', password='x')
        decision = apply_company_join(self.company, user, email=user.email)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error_code, ERROR_ACCESS_DENIED)
        self.assertFalse(is_company_access_enabled(self.company, user))
        self.assertTrue(self.company.members.filter(pk=user.pk).exists())
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(self.owner.email, mail.outbox[0].to)

    def test_invite_blocks_and_emails_admin(self):
        self.company.access_mode = Company.ACCESS_INVITE
        self.company.save()
        user = User.objects.create_user(username='u4', email='u4@example.com', password='x')
        decision = apply_company_join(self.company, user, email=user.email)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error_code, ERROR_ACCESS_PENDING)
        self.assertFalse(is_company_access_enabled(self.company, user))
        self.assertEqual(len(mail.outbox), 1)

    def test_disabled_member_stays_blocked_without_extra_email(self):
        self.company.access_mode = Company.ACCESS_INVITE
        self.company.save()
        user = User.objects.create_user(username='u5', email='u5@example.com', password='x')
        set_company_access(self.company, user, enabled=False)
        decision = apply_company_join(self.company, user, email=user.email)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error_code, ERROR_ACCESS_PENDING)
        self.assertEqual(len(mail.outbox), 0)

    def test_access_is_scoped_per_company(self):
        other = Company.objects.create(name='Other Co', access_mode=Company.ACCESS_PUBLIC)
        user = User.objects.create_user(username='u6', email='u6@example.com', password='x')
        self.company.access_mode = Company.ACCESS_INVITE
        self.company.save()

        invite_decision = apply_company_join(self.company, user, email=user.email)
        self.assertFalse(invite_decision.allowed)
        self.assertFalse(is_company_access_enabled(self.company, user))

        public_decision = apply_company_join(other, user, email=user.email)
        self.assertTrue(public_decision.allowed)
        self.assertTrue(is_company_access_enabled(other, user))
        # Disabling company A must not affect company B.
        self.assertFalse(is_company_access_enabled(self.company, user))
        self.assertTrue(user.is_active)

    def test_notify_user_when_enabled(self):
        user = User.objects.create_user(username='u7', email='u7@example.com', password='x')
        notify_user_access_enabled(self.company, user)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [user.email])
