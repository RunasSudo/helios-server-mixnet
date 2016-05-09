# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('helios', '0003_castvote_cast_from'),
    ]

    operations = [
        migrations.RenameField(
            model_name='castvote',
            old_name='cast_from',
            new_name='cast_ip',
        ),
    ]
