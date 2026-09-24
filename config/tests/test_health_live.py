from django.test import Client, TestCase


class HealthLiveTests(TestCase):
    def test_health_live_short_circuits_before_session_db(self):
        client = Client()
        with self.assertNumQueries(0):
            response = client.get('/health/live')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'ok')
