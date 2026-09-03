from io import StringIO

from django.core.management import call_command
from django.test import SimpleTestCase

from apps.authapi.jwks import load_signing_key, normalize_pem


class GenerateJwtKeysCommandTests(SimpleTestCase):
    def test_shell_output_is_eval_safe(self):
        out = StringIO()
        call_command('generate_jwt_keys', '--shell', '--bits', '2048', stdout=out)
        text = out.getvalue()

        self.assertIn('export JWT_KEY_ID=', text)
        self.assertIn('export JWT_PRIVATE_KEY="', text)
        self.assertIn('export JWT_PUBLIC_KEY="', text)
        self.assertNotIn('Generated RSA', text)
        self.assertNotIn('Keep JWT_PRIVATE_KEY', text)

        private_line = next(
            line for line in text.splitlines() if line.startswith('export JWT_PRIVATE_KEY=')
        )
        # Strip export JWT_PRIVATE_KEY="..." wrapping.
        quoted = private_line.split('=', 1)[1]
        self.assertTrue(quoted.startswith('"') and quoted.endswith('"'))
        pem = normalize_pem(quoted)
        load_signing_key(private_pem=pem)
