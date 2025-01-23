from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, F
import json
import zlib
from django.conf import settings
import httpx
import asyncio
from sentry_sdk import capture_exception

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
    try:
        device = Device.objects.get(serial_num=serial)
        client_info = {'config': device.config.id, 'profile': device.profile.id}
    except:
        client_info = {'config': 1, 'profile': 1}
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

def events_chart():
    # Get the current date and time
    today = timezone.now().date()
    # Calculate the date 30 days ago
    start_date = today - timedelta(days=30)

    # Query the database for event counts grouped by date
    events_by_day = (
        Event.objects.filter(timestamp__date__gte=start_date, ignored=False)
        .annotate(day=F('timestamp__date'))
        .values('day')
        .annotate(count=Count('id'))
        .order_by('day')
    )

    # Prepare data for the chart
    dates = [start_date + timedelta(days=i) for i in range(31)]
    event_counts = {event['day']: event['count'] for event in events_by_day}
    data = [event_counts.get(day, 0) for day in dates]

    context = {
        'dates': [date.strftime("%Y-%m-%d") for date in dates],
        'data': data,
    }
    return context

def macos_version_pie_chart(limit=5):
    # Query the database for macOS versions and their counts
    macos_versions = (
        Device.objects.values('os_version')
        .annotate(count=Count('serial_num'))
        .order_by('-count')
    )

    # Convert the QuerySet to a list of dictionaries
    macos_list = list(macos_versions)

    # Slice the top N versions
    top_versions = macos_list[:limit]

    # Calculate the "Others" count
    others_count = sum(entry['count'] for entry in macos_list[limit:])
    if others_count > 0:
        top_versions.append({'os_version': 'Others', 'count': others_count})

    # Prepare data for the chart
    labels = [entry['os_version'] for entry in top_versions]
    data = [entry['count'] for entry in top_versions]
    
    context = {
        'labels': labels,
        'data': data,
    }
    return context

def get_common_context():
    configs = cache.get_or_set("cache_allconfigs", Config.objects.all(), None)
    profiles = cache.get_or_set("cache_allprofiles", Profile.objects.all(), None)
    context = {'configs': configs, 'profiles': profiles}
    return context

async def send_to_elastic(event_data, serial):
    url = settings.ELASTIC_URL
    event_data['serial'] = serial

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, json=event_data, timeout=5)
            response.raise_for_status()  # Raise exception for HTTP errors
            capture_exception(f"Successfully sent event to Elasticsearch: {response.status_code}")
        except httpx.RequestError as e:
            capture_exception(f"Request error while sending event to Elasticsearch: {e}")
        except httpx.HTTPStatusError as e:
            capture_exception(f"HTTP error while sending event to Elasticsearch: {e.response.status_code} {e.response.text}")
