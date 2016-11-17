# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('helios', '0006_auto_20161117_1445'),
    ]

    operations = [
        migrations.AddField(
            model_name='castvote',
            name='browser_fingerprint',
            field=models.CharField(max_length=131072, null=True),
            preserve_default=True,
        ),
    ]
