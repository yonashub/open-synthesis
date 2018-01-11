# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2018-01-11 02:50
from __future__ import unicode_literals

from django.db import migrations

def set_hypothesis_creator(apps, schema_editor):
    Hypothesis = apps.get_model('openach', 'Hypothesis')
    for h in Hypothesis.objects.filter(creator__isnull=True).select_related('board'):
        h.creator_id = h.board.creator_id
        h.save()

class Migration(migrations.Migration):

    dependencies = [
        ('openach', '0039_auto_20180111_0248'),
    ]

    operations = [
        migrations.RunPython(set_hypothesis_creator),
    ]
