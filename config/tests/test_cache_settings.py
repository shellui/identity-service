from django.conf import settings
from django.core.checks import run_checks
from django.test import SimpleTestCase, override_settings

from apps.authapi.checks import redis_required_in_production
from config.settings import _caches_config


class CachesConfigTests(SimpleTestCase):
    def test_locmem_when_redis_url_empty(self):
        caches = _caches_config('')
        self.assertEqual(
            caches['default']['BACKEND'],
            'django.core.cache.backends.locmem.LocMemCache',
        )
        self.assertEqual(caches['default']['LOCATION'], 'identity-service-auth')

    def test_redis_when_redis_url_set(self):
        url = 'redis://127.0.0.1:6379/1'
        caches = _caches_config(url)
        self.assertEqual(
            caches['default']['BACKEND'],
            'django.core.cache.backends.redis.RedisCache',
        )
        self.assertEqual(caches['default']['LOCATION'], url)

    def test_loaded_settings_default_to_locmem_without_redis_url(self):
        backend = settings.CACHES['default']['BACKEND']
        self.assertIn('LocMem', backend)


class RedisRequiredDeployCheckTests(SimpleTestCase):
    """authapi.E004: production (DEBUG=false) refuses to deploy without REDIS_URL."""

    @override_settings(DEBUG=False, REDIS_URL='', CACHES=_caches_config(''))
    def test_error_without_redis_url_in_production(self):
        errors = redis_required_in_production(None)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].id, 'authapi.E004')
        self.assertTrue(errors[0].is_serious())
        self.assertIn('REDIS_URL is required when DEBUG is false', errors[0].msg)
        self.assertIn('redis://redis:6379/0', errors[0].msg)

    @override_settings(DEBUG=False, REDIS_URL='   ', CACHES=_caches_config(''))
    def test_blank_redis_url_counts_as_unset(self):
        self.assertEqual([e.id for e in redis_required_in_production(None)], ['authapi.E004'])

    @override_settings(DEBUG=False, REDIS_URL='', SCHEDULER_ENABLED=False)
    def test_still_required_when_scheduler_disabled(self):
        # Redis also backs the cache, OAuth PKCE state and SAML replay protection.
        self.assertEqual([e.id for e in redis_required_in_production(None)], ['authapi.E004'])

    @override_settings(
        DEBUG=False, REDIS_URL='', CELERY_BROKER_URL='redis://broker:6379/1'
    )
    def test_celery_broker_url_does_not_replace_redis_url(self):
        self.assertEqual([e.id for e in redis_required_in_production(None)], ['authapi.E004'])

    @override_settings(
        DEBUG=False,
        REDIS_URL='redis://redis:6379/0',
        CACHES=_caches_config('redis://redis:6379/0'),
    )
    def test_silent_when_redis_configured(self):
        self.assertEqual(redis_required_in_production(None), [])

    @override_settings(DEBUG=True, REDIS_URL='', CACHES=_caches_config(''))
    def test_silent_in_debug(self):
        self.assertEqual(redis_required_in_production(None), [])

    @override_settings(DEBUG=False, REDIS_URL='', CACHES=_caches_config(''))
    def test_registered_as_deploy_check_only(self):
        deploy_ids = {m.id for m in run_checks(include_deployment_checks=True)}
        self.assertIn('authapi.E004', deploy_ids)
        # Not part of the plain checks, so tests and other management commands still run.
        plain_ids = {m.id for m in run_checks(include_deployment_checks=False)}
        self.assertNotIn('authapi.E004', plain_ids)
