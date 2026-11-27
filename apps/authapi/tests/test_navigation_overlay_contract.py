"""Shared navigation overlay schema must accept the Shellui shell record shape."""

from __future__ import annotations

import json
from pathlib import Path

from django.test import SimpleTestCase

from apps.authapi.navigation_overlay import (
    RESERVED_PATH_SEGMENTS,
    OverlayValidationError,
    validate_navigation_overlay,
)

SCHEMA_DIR = Path(__file__).resolve().parents[1] / 'schemas'
SCHEMA_PATH = SCHEMA_DIR / 'navigation-overlay.v1.json'
EXAMPLE_PATH = SCHEMA_DIR / 'shell-navigation-overlay.v1.example.json'


class NavigationOverlayContractTests(SimpleTestCase):
    def setUp(self):
        self.schema = json.loads(SCHEMA_PATH.read_text())
        self.example = json.loads(EXAMPLE_PATH.read_text())

    def test_schema_is_third_party_only_and_matches_the_shell_record(self):
        app = self.schema['$defs']['installedApp']
        required = set(app['required'])
        self.assertTrue(
            {
                'id',
                'name',
                'origin',
                'url',
                'path',
                'thirdParty',
                'capabilities',
                'installedAt',
                'updatedAt',
            }.issubset(required)
        )
        self.assertNotIn('firstParty', app['properties'])
        self.assertNotIn('iconUrl', app['properties'])
        self.assertEqual(app['properties']['thirdParty']['const'], True)
        self.assertFalse(app['additionalProperties'])
        self.assertNotIn('auth', app['properties']['capabilities']['items']['enum'])
        self.assertEqual(
            set(app['properties']['capabilities']['items']['enum']),
            {'theme', 'locale', 'ui', 'navigate', 'storage', 'ai'},
        )
        self.assertEqual(self.schema['properties']['installedApps']['maxItems'], 100)

    def test_shell_example_validates_and_preserves_shell_fields(self):
        cleaned = validate_navigation_overlay(self.example)
        app = cleaned['installedApps'][0]
        self.assertEqual(app['id'], 'notes')
        self.assertEqual(app['origin'], 'https://notes.example.com')
        self.assertEqual(app['url'], 'https://notes.example.com/app')
        self.assertEqual(app['path'], 'notes')
        self.assertEqual(app['icon'], 'https://notes.example.com/icon.svg')
        self.assertIs(app['thirdParty'], True)
        self.assertEqual(app['capabilities'], ['theme', 'locale', 'ui', 'storage'])
        self.assertEqual(app['installedAt'], '2026-11-20T02:43:00.000Z')
        self.assertEqual(app['updatedAt'], '2026-11-20T02:43:00.000Z')
        self.assertNotIn('firstParty', app)
        self.assertNotIn('auth', app['capabilities'])

    def test_schema_and_validator_reject_auth_and_first_party(self):
        first_party = json.loads(json.dumps(self.example))
        first_party['installedApps'][0]['firstParty'] = True
        with self.assertRaises(OverlayValidationError) as raised:
            validate_navigation_overlay(first_party)
        self.assertIn('firstParty', raised.exception.message)

        with_auth = json.loads(json.dumps(self.example))
        with_auth['installedApps'][0]['capabilities'] = ['theme', 'auth']
        with self.assertRaises(OverlayValidationError) as raised:
            validate_navigation_overlay(with_auth)
        self.assertIn('auth', raised.exception.message)

    def test_reserved_segments_match_the_shell_list(self):
        # The shell keeps the same list in packages/sdk (RESERVED_PATH_SEGMENTS). Its contract
        # test reads the same schema description, so a change on one side fails on the other.
        shell_segments = {'admin', '__settings', 'legal', 'files', 'login', 'marketplace', 'settings'}
        self.assertEqual(set(RESERVED_PATH_SEGMENTS), shell_segments)
        description = self.schema['$defs']['installedApp']['properties']['path']['description']
        for segment in shell_segments:
            self.assertIn(segment, description)

    def test_refuses_what_the_shell_validator_refuses(self):
        # Mirrors the cases in packages/sdk/src/marketplace/overlayContract.spec.ts.
        def with_app(**changes):
            doc = json.loads(json.dumps(self.example))
            doc['installedApps'][0].update(changes)
            return doc

        refused = [
            with_app(thirdParty=False),
            with_app(safeForAuthToken=True),
            with_app(url='http://notes.example.com/app', origin='http://notes.example.com'),
            with_app(url='https://127.0.0.1/app', origin='https://127.0.0.1'),
            with_app(origin='https://other.example.com'),
        ]
        for path in (
            'admin',
            'Admin/x',
            '__settings',
            'legal/terms',
            'files',
            'login',
            'marketplace',
            'settings',
            '../x',
            'a/..',
            '/a//b',
        ):
            refused.append(with_app(path=path))
        for doc in refused:
            with self.subTest(app=doc['installedApps'][0]):
                with self.assertRaises(OverlayValidationError):
                    validate_navigation_overlay(doc)

    def test_stray_document_keys_are_refused(self):
        doc = json.loads(json.dumps(self.example))
        doc['extra'] = 1
        with self.assertRaises(OverlayValidationError):
            validate_navigation_overlay(doc)
