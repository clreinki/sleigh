from django.core.cache import cache
import json
import zlib

from .models import Config, Profile, Rule, Device, LogEntry, Event

################### EXTRA FUNCTIONS ###################
def addlog(user, text):
    LogEntry.objects.create(
        user=user,
        text=text
    )

def get_client_preflight(serial):
    device = Device.objects.select_related('config').get(serial_num=serial)
    full_sync_interval = device.config.full_sync_interval - 300  # Fix weird bug in Santa client that adds 300 sec
    response_data = {
        "batch_size": device.config.batch_size,
        "client_mode": device.config.client_mode,
        "allowed_path_regex": device.config.allowed_path_regex,
        "blocked_path_regex": device.config.blocked_path_regex,
        "full_sync_interval": full_sync_interval,
        "sync_type": "clean",
        "bundles_enabled": device.config.enable_bundles,
        "enable_transitive_rules": device.config.enable_transitive_rules,
        "block_usb_mount": device.config.block_usb_mount
    }
    return response_data

def get_client_rules(serial):
    device = Device.objects.get(serial_num=serial)
    # If assigned the default profile or a standalone profile
    if device.profile.id == 1 or device.profile.standalone:
        rules = device.profile.rules.all()
    # If including a partial profile, combine rulesets
    else:
        partial_rules = device.profile.rules.all()
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
