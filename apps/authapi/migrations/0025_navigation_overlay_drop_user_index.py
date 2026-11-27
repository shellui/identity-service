# The (user, company) unique constraint already indexes user_id first, so drop the separate FK index.

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authapi', '0024_user_navigation_overlay'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='usernavigationoverlay',
            name='user',
            field=models.ForeignKey(db_index=False, on_delete=django.db.models.deletion.CASCADE, related_name='navigation_overlays', to=settings.AUTH_USER_MODEL),
        ),
    ]
