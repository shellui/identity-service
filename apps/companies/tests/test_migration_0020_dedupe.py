import importlib

from django.test import SimpleTestCase

_report = importlib.import_module('apps.companies.migrations.0020_companyoauthclient_dedupe_key')


class CompanyOAuthClientDedupeMigrationTests(SimpleTestCase):
    def test_duplicate_groups_raises_actionable_message(self):
        class _Row:
            def __init__(self, pk, company_id, dedupe_key):
                self.id = pk
                self.company_id = company_id
                self.dedupe_key = dedupe_key

        class _Qs:
            def exclude(self, **kwargs):
                return self

            def iterator(self):
                yield _Row(1, 9, 'google')
                yield _Row(2, 9, 'google')

        class _Model:
            objects = _Qs()

        duplicates = _report.duplicate_dedupe_key_groups(_Model)
        self.assertEqual(duplicates, {(9, 'google'): [1, 2]})
        class _Apps:
            @staticmethod
            def get_model(app_label, model_name):
                assert app_label == 'companies' and model_name == 'CompanyOAuthClient'
                return _Model

        with self.assertRaises(RuntimeError) as ctx:
            _report._report_duplicate_dedupe_keys(_Apps(), None)
        self.assertIn('company_oauth_client_ids=[1, 2]', str(ctx.exception))
