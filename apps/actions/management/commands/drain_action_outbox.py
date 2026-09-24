from django.core.management.base import BaseCommand

from apps.actions.delivery import drain_pending_outbox


class Command(BaseCommand):
    help = 'Deliver pending or failed action outbox rows (retries with backoff).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--batch-size',
            type=int,
            default=50,
            help='Maximum outbox rows to process in one run (default: 50).',
        )

    def handle(self, *args, **options):
        batch_size = max(1, int(options['batch_size']))
        processed = drain_pending_outbox(batch_size=batch_size)
        self.stdout.write(self.style.SUCCESS(f'Processed {processed} outbox row(s).'))
