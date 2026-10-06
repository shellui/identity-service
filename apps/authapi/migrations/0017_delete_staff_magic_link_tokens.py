"""Delete unused magic-link tokens that belong to staff or superuser accounts.

Staff no longer sign in with a magic link. A token issued before this release could
still be in a company's email provider logs, so it is removed (verify also refuses it).
"""

from django.conf import settings
from django.db import migrations
from django.db.models import Q


def delete_staff_tokens(apps, schema_editor):
    MagicLinkToken = apps.get_model('authapi', 'MagicLinkToken')
    User = apps.get_model(settings.AUTH_USER_MODEL)
    staff = User.objects.filter(Q(is_staff=True) | Q(is_superuser=True))
    unused = MagicLinkToken.objects.filter(consumed_at__isnull=True)
    unused.filter(user__in=staff).delete()
    for email in staff.exclude(email='').values_list('email', flat=True):
        unused.filter(email__iexact=email).delete()


class Migration(migrations.Migration):
    dependencies = [
        ('authapi', '0016_delete_loginevent'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RunPython(delete_staff_tokens, migrations.RunPython.noop),
    ]
