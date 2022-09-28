# -*- coding: utf-8 -*-
# Generated by Django 1.10.2 on 2016-10-04 16:51
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("openach", "0030_auto_20161004_0443"),
    ]

    operations = [
        migrations.AlterField(
            model_name="usersettings",
            name="digest_frequency",
            field=models.PositiveSmallIntegerField(
                choices=[(0, "Never"), (1, "Daily"), (2, "Weekly")],
                default=1,
                help_text="How frequently to receive email updates containing new notifications",
                verbose_name="email digest frequency",
            ),
        ),
    ]
