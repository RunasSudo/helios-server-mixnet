# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('helios', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='electionmixnet',
            name='email',
            field=models.EmailField(max_length=75, null=True, blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='electionmixnet',
            name='secret',
            field=models.CharField(default='', max_length=100),
            preserve_default=False,
        ),
    ]
