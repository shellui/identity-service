from django.test import SimpleTestCase

from apps.authapi.jwks import generate_rsa_key_pair, load_signing_key, normalize_pem


class NormalizePemTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.private_pem, cls.public_pem = generate_rsa_key_pair(key_size=2048)

    def test_multiline_pem(self):
        self.assertTrue(normalize_pem(self.private_pem).startswith('-----BEGIN'))

    def test_literal_backslash_n(self):
        encoded = self.private_pem.replace('\n', '\\n')
        self.assertEqual(normalize_pem(encoded), self.private_pem.strip())

    def test_quoted_generate_jwt_keys_output(self):
        wrapped = '"' + self.private_pem.replace('\n', '\\n') + '"'
        self.assertEqual(normalize_pem(wrapped), self.private_pem.strip())

    def test_escaped_quotes_from_coolify(self):
        wrapped = '\\"' + self.private_pem.replace('\n', '\\n') + '\\"'
        normalized = normalize_pem(wrapped)
        self.assertTrue(normalized.startswith('-----BEGIN'))
        self.assertFalse(normalized.startswith('\\'))
        load_signing_key(private_pem=wrapped)

    def test_double_escaped_newlines(self):
        wrapped = self.private_pem.replace('\n', '\\\\n')
        load_signing_key(private_pem=wrapped)
