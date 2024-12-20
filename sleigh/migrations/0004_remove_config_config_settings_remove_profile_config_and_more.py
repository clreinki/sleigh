# Generated by Django 4.2.16 on 2024-11-22 13:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sleigh', '0003_device_last_updated'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='config',
            name='config_settings',
        ),
        migrations.RemoveField(
            model_name='profile',
            name='config',
        ),
        migrations.AddField(
            model_name='config',
            name='allowed_path_regex',
            field=models.CharField(blank=True, max_length=512, null=True),
        ),
        migrations.AddField(
            model_name='config',
            name='assignments',
            field=models.JSONField(default=list),
        ),
        migrations.AddField(
            model_name='config',
            name='batch_size',
            field=models.IntegerField(default=100),
        ),
        migrations.AddField(
            model_name='config',
            name='block_usb_mount',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='config',
            name='blocked_path_regex',
            field=models.CharField(blank=True, max_length=512, null=True),
        ),
        migrations.AddField(
            model_name='config',
            name='client_mode',
            field=models.CharField(choices=[('LOCKDOWN', 'LOCKDOWN'), ('MONITOR', 'MONITOR')], default='MONITOR', max_length=12),
        ),
        migrations.AddField(
            model_name='config',
            name='enable_bundles',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='config',
            name='enable_transitive_rules',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='config',
            name='full_sync_interval',
            field=models.IntegerField(default=600),
        ),
        migrations.AddField(
            model_name='profile',
            name='assignments',
            field=models.JSONField(default=list),
        ),
        migrations.AddField(
            model_name='profile',
            name='description',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='profile',
            name='standalone',
            field=models.BooleanField(default=False),
        ),
    ]
