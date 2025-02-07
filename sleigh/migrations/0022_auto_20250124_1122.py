# Generated by Django 4.2.16 on 2025-01-24 16:04

from django.db import migrations

def initial_data(apps, schema_editor):
    Config = apps.get_model("sleigh", "Config")
    Profile = apps.get_model("sleigh", "Profile")
    User = apps.get_model("auth", "User")

    # Create Config object if it doesn't already exist
    Config.objects.get_or_create(
        pk=1,
        defaults={
            "name": "Default Config",
            "description": "Default config for all new devices",
            "enable_bundles": False,
            "enable_transitive_rules": False,
            "batch_size": 100,
            "full_sync_interval": 600,
            "client_mode": "MONITOR",
            "allowed_path_regex": None,
            "blocked_path_regex": None,
            "block_usb_mount": False,
        }
    )

    # Create Profile object if it doesn't already exist
    Profile.objects.get_or_create(
        pk=1,
        defaults={
            "name": "Default Profile",
            "description": "Default profile for all devices",
            "standalone": False,
        }
    )

    # Create User object if it doesn't already exist
    User.objects.get_or_create(
        pk=1,
        defaults={
            "username": "sleighadmin",
            "first_name": "Sleigh",
            "last_name": "Admin",
            "email": "you@email.com",
            "is_superuser": False,
            "is_staff": False,
            "is_active": True,
            "date_joined": "2024-11-20T13:47:56Z",
            "last_login": "2025-01-03T18:43:39Z",
            "password": "pbkdf2_sha256$600000$g79OBbhdyFrFuxEuB69QnA$UmRyD+cmUgXtzIT/7tXsSPWerLqJ2xc5ImylDFzxXqE=",
        }
    )


class Migration(migrations.Migration):

    dependencies = [
        ('sleigh', '0001_squashed_0021_rename_file_bundle_id_ignoredentry_file_name'),
    ]

    operations = [
        migrations.RunPython(initial_data),
    ]
