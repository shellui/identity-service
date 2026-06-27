"""Generate an RSA key pair for JWT signing (RS256)."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.authapi.jwks import compute_rsa_kid, generate_rsa_key_pair


class Command(BaseCommand):
    help = 'Generate an RSA key pair for JWT_PRIVATE_KEY (RS256 signing).'
    # Keys are generated before JWT_PRIVATE_KEY exists — skip the production JWT check.
    requires_system_checks = []

    def add_arguments(self, parser):
        parser.add_argument(
            '--bits',
            type=int,
            default=3072,
            help='RSA key size in bits (minimum 2048, default 3072).',
        )

    def handle(self, *args, **options):
        private_pem, public_pem = generate_rsa_key_pair(key_size=options['bits'])
        kid = compute_rsa_kid(public_pem)

        self.stdout.write(self.style.SUCCESS('Generated RSA key pair for JWT signing.\n'))
        self.stdout.write('Add these to your environment (.env or secret manager):\n')
        self.stdout.write('')
        self.stdout.write(f'JWT_KEY_ID={kid}')
        self.stdout.write('')
        self.stdout.write('JWT_PRIVATE_KEY="' + private_pem.replace('\n', '\\n') + '"')
        self.stdout.write('')
        self.stdout.write('# Optional (derived automatically when omitted):')
        self.stdout.write('JWT_PUBLIC_KEY="' + public_pem.replace('\n', '\\n') + '"')
        self.stdout.write('')
        self.stdout.write(self.style.WARNING(
            'Keep JWT_PRIVATE_KEY secret. Mount it via a secret manager or file — never commit it.'
        ))
