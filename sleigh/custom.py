from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
import json
import zlib

from .models import Config, Profile, Rule, Device, LogEntry, Event, IgnoredEntry

################### EXTRA FUNCTIONS ###################
def addlog(user, text):
    # Creates a changelog entry - addlog(request.user,f"")
    LogEntry.objects.create(
        user=user,
        action=text
    )

def get_dashboard_stats():
    seven_days_ago = timezone.now() - timedelta(days=7)
    past_day = timezone.now() - timedelta(days=1)

    stat1 = Device.objects.filter(last_updated__gte=seven_days_ago).count()

    main_profile = Profile.objects.get(id=1)
    stat2 = Rule.objects.filter(profile=main_profile).count()

    stat3 = IgnoredEntry.objects.all().count()

    stat4 = Event.objects.filter(timestamp__gte=seven_days_ago).count()

    stats = {'stat1': stat1, 'stat2': stat2, 'stat3': stat3, 'stat4': stat4}
    return stats

def get_client_info(serial):
    device = Device.objects.get(serial_num=serial)
    client_info = {'config': device.config.id, 'profile': device.profile.id}
    return client_info

def get_client_preflight(config_id):
    config = Config.objects.get(id=config_id)
    full_sync_interval = round(config.full_sync_interval * 0.6667)  # Fix weird bug in Santa client
    response_data = {
        "batch_size": config.batch_size,
        "client_mode": config.client_mode,
        "allowed_path_regex": config.allowed_path_regex,
        "blocked_path_regex": config.blocked_path_regex,
        "full_sync_interval": full_sync_interval,
        "sync_type": "clean",
        "bundles_enabled": config.enable_bundles,
        "enable_transitive_rules": config.enable_transitive_rules,
        "block_usb_mount": config.block_usb_mount
    }
    return response_data

def get_client_rules(profile_id):
    profile = Profile.objects.get(id=profile_id)
    # If assigned the default profile or a standalone profile
    if profile.id == 1 or profile.standalone:
        rules = profile.rules.all()
    # If including a partial profile, combine rulesets
    else:
        partial_rules = profile.rules.all()
        base_rules = Rule.objects.filter(profile__id=1)
        rules = partial_rules | base_rules
    
    # Assemble JSON response from queryset
    rule_list = []
    for rule in rules:
        rule_data = {
            "identifier": rule.identifier,
            "policy": rule.policy,
            "rule_type": rule.rule_type
        }
        if rule.custom_msg:
            rule_data['custom_msg'] = rule.custom_msg
        if rule.custom_url:
            rule_data['custom_url'] = rule.custom_url
        rule_list.append(rule_data)
    response_data = {
        "rules": rule_list,
    }
    return response_data

def delete_cache_keys(prefix):
    keys = cache.keys(f'{prefix}*')  # Fetch all keys starting with 'prefix'
    if keys:
        cache.delete_many(keys)  # Delete all matching keys