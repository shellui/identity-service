"""Public vs internal service URL resolution."""

from django.test import SimpleTestCase

from config.service_urls import internal_origin


class InternalOriginTests(SimpleTestCase):
    def test_prefers_internal(self):
        self.assertEqual(
            internal_origin('http://localhost:8004', 'http://email:8000'),
            'http://email:8000',
        )

    def test_falls_back_to_public(self):
        self.assertEqual(internal_origin('http://localhost:8002', ''), 'http://localhost:8002')

    def test_empty_when_both_missing(self):
        self.assertEqual(internal_origin('', ''), '')
