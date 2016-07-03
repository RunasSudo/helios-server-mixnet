# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import helios.datatypes.djangofield


class Migration(migrations.Migration):

    dependencies = [
        ('helios', '0004_auto_20160509_1804'),
    ]

    operations = [
        migrations.AddField(
            model_name='election',
            name='trustee_threshold',
            field=models.IntegerField(default=0),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='trustee',
            name='commitment',
            field=helios.datatypes.djangofield.LDObjectField(null=True),
            preserve_default=True,
        ),
    ]
