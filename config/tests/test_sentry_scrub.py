"""Sentry events and breadcrumbs never carry query strings, request bodies, the Referer or secret locals."""

from django.test import SimpleTestCase

from config.sentry_scrub import FILTERED, before_breadcrumb, before_send, event_scrubber

_SECRET = 'S3cretMagicToken_abc123'


class SentryScrubTests(SimpleTestCase):
    def test_before_send_strips_request_secrets(self):
        event = {
            'request': {
                'url': f'https://auth.example.com/api/v1/magic-link/verify?token={_SECRET}',
                'query_string': f'token={_SECRET}&company_id=1',
                'data': {'token': _SECRET, 'company_id': 1},
                'headers': {'Referer': f'https://mail.example.com/?token={_SECRET}', 'User-Agent': 'UA'},
            },
            'breadcrumbs': {
                'values': [
                    {'category': 'httplib', 'data': {'url': f'https://idp.example.com/token?code={_SECRET}', 'http.query': f'code={_SECRET}'}},
                ]
            },
        }
        cleaned = before_send(event, {})
        self.assertNotIn(_SECRET, repr(cleaned))
        self.assertEqual(cleaned['request']['url'], 'https://auth.example.com/api/v1/magic-link/verify')
        self.assertEqual(cleaned['request']['query_string'], FILTERED)
        self.assertEqual(cleaned['request']['data'], FILTERED)
        self.assertEqual(cleaned['request']['headers']['User-Agent'], 'UA')

    def test_before_breadcrumb_strips_query(self):
        crumb = before_breadcrumb(
            {'category': 'httplib', 'data': {'url': f'https://x.example.com/a?state={_SECRET}', 'http.fragment': _SECRET}},
            {},
        )
        self.assertNotIn(_SECRET, repr(crumb))
        self.assertEqual(crumb['data']['url'], 'https://x.example.com/a')

    def test_event_scrubber_hides_secret_named_frame_locals(self):
        event = {
            'exception': {
                'values': [
                    {
                        'stacktrace': {
                            'frames': [
                                {
                                    'vars': {
                                        'raw_token': _SECRET,
                                        'magic_link_url': f'https://a/verify?token={_SECRET}',
                                        'code': _SECRET,
                                        'confirm_token': _SECRET,
                                        'company_id': 1,
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
        event_scrubber().scrub_event(event)
        frame_vars = event['exception']['values'][0]['stacktrace']['frames'][0]['vars']
        self.assertNotIn(_SECRET, repr(frame_vars))
        self.assertEqual(frame_vars['company_id'], 1)
