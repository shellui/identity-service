from django.core.management.base import BaseCommand

from apps.companies.deletion import purge_deleted_companies


class Command(BaseCommand):
    help = 'Purge companies flagged for deletion (Celery runs this every 60 seconds).'

    def handle(self, *args, **options):
        stats = purge_deleted_companies()
        self.stdout.write('purge_deleted_companies: ' + ' '.join(f'{k}={v}' for k, v in stats.items()))
