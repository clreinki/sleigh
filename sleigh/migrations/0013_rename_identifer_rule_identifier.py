# Generated by Django 4.2.16 on 2025-01-03 20:20

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('sleigh', '0012_logentry'),
    ]

    operations = [
        migrations.RenameField(
            model_name='rule',
            old_name='identifer',
            new_name='identifier',
        ),
    ]
