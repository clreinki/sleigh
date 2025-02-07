# Generated by Django 4.2.16 on 2025-01-24 16:22

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    replaces = [('sleigh', '0001_initial'), ('sleigh', '0002_device'), ('sleigh', '0003_device_last_updated'), ('sleigh', '0004_remove_config_config_settings_remove_profile_config_and_more'), ('sleigh', '0005_alter_config_assignments_alter_profile_assignments'), ('sleigh', '0006_alter_config_assignments_alter_profile_assignments'), ('sleigh', '0007_alter_config_assignments'), ('sleigh', '0008_device_config_device_profile'), ('sleigh', '0009_remove_config_assignments_remove_profile_assignments'), ('sleigh', '0010_rule_identifer'), ('sleigh', '0011_alter_rule_policy_alter_rule_rule_type'), ('sleigh', '0012_logentry'), ('sleigh', '0013_rename_identifer_rule_identifier'), ('sleigh', '0014_rename_custom_msg_rule_description'), ('sleigh', '0015_event_device_rules_synced_rule_custom_msg_and_more'), ('sleigh', '0016_alter_event_file_sha256'), ('sleigh', '0017_ignoredentry_event_ignored'), ('sleigh', '0018_alter_event_execution_time'), ('sleigh', '0019_event_timestamp'), ('sleigh', '0020_event_uniqueid'), ('sleigh', '0021_rename_file_bundle_id_ignoredentry_file_name')]

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Config',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64)),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
                ('allowed_path_regex', models.CharField(blank=True, max_length=512, null=True)),
                ('batch_size', models.IntegerField(default=100)),
                ('block_usb_mount', models.BooleanField(default=False)),
                ('blocked_path_regex', models.CharField(blank=True, max_length=512, null=True)),
                ('client_mode', models.CharField(choices=[('LOCKDOWN', 'LOCKDOWN'), ('MONITOR', 'MONITOR')], default='MONITOR', max_length=12)),
                ('enable_bundles', models.BooleanField(default=False)),
                ('enable_transitive_rules', models.BooleanField(default=False)),
                ('full_sync_interval', models.IntegerField(default=600)),
            ],
        ),
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64)),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
                ('standalone', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='LogEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now=True)),
                ('user', models.CharField(max_length=64)),
                ('action', models.CharField(max_length=256)),
            ],
        ),
        migrations.CreateModel(
            name='Device',
            fields=[
                ('serial_num', models.CharField(max_length=16, primary_key=True, serialize=False)),
                ('hostname', models.CharField(max_length=64)),
                ('os_version', models.CharField(max_length=16)),
                ('os_build', models.CharField(max_length=16)),
                ('model_identifier', models.CharField(max_length=16)),
                ('santa_version', models.CharField(max_length=16)),
                ('primary_user', models.CharField(max_length=64)),
                ('binary_rule_count', models.IntegerField(default=0)),
                ('certificate_rule_count', models.IntegerField(default=0)),
                ('compiler_rule_count', models.IntegerField(default=0)),
                ('transitive_rule_count', models.IntegerField(default=0)),
                ('teamid_rule_count', models.IntegerField(default=0)),
                ('signingid_rule_count', models.IntegerField(default=0)),
                ('cdhash_rule_count', models.IntegerField(default=0)),
                ('client_mode', models.CharField(max_length=16)),
                ('request_clean_sync', models.BooleanField(default=True)),
                ('last_updated', models.DateTimeField(auto_now=True)),
                ('config', models.ForeignKey(default=1, on_delete=django.db.models.deletion.SET_DEFAULT, to='sleigh.config')),
                ('profile', models.ForeignKey(default=1, on_delete=django.db.models.deletion.SET_DEFAULT, to='sleigh.profile')),
                ('rules_synced', models.IntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='Rule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.CharField(max_length=255)),
                ('policy', models.CharField(choices=[('ALLOWLIST', 'Allow'), ('BLOCKLIST', 'Block'), ('ALLOWLIST_COMPILER', 'Allow Compiler')], default=None, max_length=24)),
                ('rule_type', models.CharField(choices=[('TEAMID', 'TeamID'), ('SIGNINGID', 'SigningID'), ('BINARY', 'Binary'), ('CERTIFICATE', 'Certificate')], default=None, max_length=16)),
                ('created_by', models.CharField(blank=True, max_length=64, null=True)),
                ('date_created', models.DateField(default=django.utils.timezone.now)),
                ('profile', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='rules', to='sleigh.profile')),
                ('identifier', models.CharField(max_length=255)),
                ('custom_msg', models.CharField(blank=True, max_length=255, null=True)),
                ('custom_url', models.CharField(blank=True, max_length=255, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Event',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file_sha256', models.CharField(max_length=64)),
                ('file_path', models.TextField()),
                ('file_name', models.CharField(max_length=255)),
                ('executing_user', models.CharField(blank=True, max_length=255, null=True)),
                ('execution_time', models.BigIntegerField(blank=True, null=True)),
                ('loggedin_users', models.JSONField(blank=True, null=True)),
                ('current_sessions', models.JSONField(blank=True, null=True)),
                ('decision', models.CharField(max_length=50)),
                ('file_bundle_id', models.CharField(blank=True, max_length=255, null=True)),
                ('file_bundle_path', models.TextField(blank=True, null=True)),
                ('file_bundle_executable_rel_path', models.TextField(blank=True, null=True)),
                ('file_bundle_name', models.CharField(blank=True, max_length=255, null=True)),
                ('file_bundle_version', models.CharField(blank=True, max_length=50, null=True)),
                ('file_bundle_version_string', models.CharField(blank=True, max_length=50, null=True)),
                ('file_bundle_hash', models.CharField(blank=True, max_length=64, null=True)),
                ('file_bundle_hash_millis', models.FloatField(blank=True, null=True)),
                ('file_bundle_binary_count', models.IntegerField(blank=True, null=True)),
                ('pid', models.IntegerField(blank=True, null=True)),
                ('ppid', models.IntegerField(blank=True, null=True)),
                ('parent_name', models.CharField(blank=True, max_length=255, null=True)),
                ('quarantine_data_url', models.URLField(blank=True, null=True)),
                ('quarantine_referer_url', models.URLField(blank=True, null=True)),
                ('quarantine_timestamp', models.FloatField(blank=True, null=True)),
                ('quarantine_agent_bundle_id', models.CharField(blank=True, max_length=255, null=True)),
                ('signing_chain', models.JSONField(blank=True, null=True)),
                ('signing_id', models.CharField(blank=True, max_length=255, null=True)),
                ('team_id', models.CharField(blank=True, max_length=255, null=True)),
                ('cdhash', models.CharField(blank=True, max_length=64, null=True)),
                ('serial_num', models.CharField(max_length=16)),
                ('ignored', models.BooleanField(default=False)),
                ('timestamp', models.DateTimeField(auto_now=True)),
                ('uniqueid', models.CharField(blank=True, max_length=255, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='IgnoredEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file_name', models.CharField(max_length=255)),
            ],
        ),
    ]
