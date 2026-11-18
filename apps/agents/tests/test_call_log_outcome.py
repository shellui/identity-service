from django.test import SimpleTestCase

from apps.agents.call_log_outcome import (
    OUTCOME_ALLOWED,
    OUTCOME_FAILED,
    canonical_outcome_ingest,
    display_outcome_for_read,
)


class CanonicalOutcomeIngestTests(SimpleTestCase):
    def test_maps_legacy_success_to_allowed(self):
        self.assertEqual(canonical_outcome_ingest('success'), OUTCOME_ALLOWED)

    def test_maps_rate_limited_to_failed(self):
        self.assertEqual(canonical_outcome_ingest('rate_limited'), OUTCOME_FAILED)

    def test_rejects_unknown(self):
        self.assertIsNone(canonical_outcome_ingest('bogus'))


class DisplayOutcomeForReadTests(SimpleTestCase):
    def test_legacy_stored_success(self):
        self.assertEqual(
            display_outcome_for_read('success', result='', status_code=0, error_code=''),
            OUTCOME_ALLOWED,
        )

    def test_error_code_timeout_maps_failed(self):
        self.assertEqual(
            display_outcome_for_read('', result='', status_code=0, error_code='timeout'),
            OUTCOME_FAILED,
        )

    def test_error_code_rate_limited_maps_failed(self):
        self.assertEqual(
            display_outcome_for_read('', result='', status_code=0, error_code='rate_limited'),
            OUTCOME_FAILED,
        )

    def test_unknown_maps_to_failed(self):
        self.assertEqual(
            display_outcome_for_read('weird', result='', status_code=500, error_code=''),
            OUTCOME_FAILED,
        )
