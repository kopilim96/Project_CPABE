# -*- coding: utf-8 -*-
# Generated by Django 1.11.29 on 2024-08-30 16:10
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0005_auto_20240828_0107'),
    ]

    operations = [
        migrations.RenameField(
            model_name='specialist',
            old_name='name',
            new_name='specialist',
        ),
        migrations.AlterField(
            model_name='profile',
            name='specialization',
            field=models.CharField(choices=[('Cardiologist', 'Cardiologist'), ('Neurologist', 'Neurologist'), ('General', 'General'), ('Radiologist', 'Radiologist'), ('Urologist', 'Urologist')], max_length=50),
        ),
    ]
