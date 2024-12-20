from django.db import models
from django.utils import timezone

class Config(models.Model):
    # Client configuration settings
    name = models.CharField(max_length=64)
    description = models.CharField(max_length=255, blank=True, null=True)
    enable_bundles = models.BooleanField(default=False)
    enable_transitive_rules = models.BooleanField(default=False)
    batch_size = models.IntegerField(default=100)
    full_sync_interval = models.IntegerField(default=600)
    MODE_CHOICES = (
        ('LOCKDOWN', 'LOCKDOWN'),
        ('MONITOR', 'MONITOR')
    )
    client_mode = models.CharField(max_length=12, choices=MODE_CHOICES, default='MONITOR')
    allowed_path_regex = models.CharField(max_length=512, blank=True, null=True)
    blocked_path_regex = models.CharField(max_length=512, blank=True, null=True)
    block_usb_mount = models.BooleanField(default=False)

    def __str__(self):
        return self.name

class Profile(models.Model):
    # Profiles are composed of client config settings and rules
    name = models.CharField(max_length=64)
    description = models.CharField(max_length=255, blank=True, null=True)
    standalone = models.BooleanField(default=False)

    def __str__(self):
        return self.name

class Rule(models.Model):
    custom_msg = models.CharField(max_length=255)
    identifer = models.CharField(max_length=255)
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name="rules")
    POLICY_CHOICES = (
        ('ALLOWLIST', 'Allow'),
        ('BLOCKLIST', 'Block'),
        ('ALLOWLIST_COMPILER', 'Allow Compiler'),
    )
    policy = models.CharField(max_length=24, choices=POLICY_CHOICES, default=None)
    RULETYPE_CHOICES = (
        ('TEAMID', 'TeamID'),
        ('SIGNINGID', 'SigningID'),
        ('BINARY', 'Binary'),
        ('CERTIFICATE', 'Certificate')
    )
    rule_type = models.CharField(max_length=16, choices=RULETYPE_CHOICES, default=None)
    created_by = models.CharField(max_length=64, blank=True, null=True)
    date_created = models.DateField(default=timezone.now)

    def __str__(self):
        return self.custom_msg

class Device(models.Model):
    serial_num = models.CharField(max_length=16, primary_key=True)
    hostname = models.CharField(max_length=64)
    os_version = models.CharField(max_length=16)
    os_build = models.CharField(max_length=16)
    model_identifier = models.CharField(max_length=16)
    santa_version = models.CharField(max_length=16)
    primary_user = models.CharField(max_length=64)
    binary_rule_count = models.IntegerField(default=0)
    certificate_rule_count = models.IntegerField(default=0)
    compiler_rule_count = models.IntegerField(default=0)
    transitive_rule_count = models.IntegerField(default=0)
    teamid_rule_count = models.IntegerField(default=0)
    signingid_rule_count = models.IntegerField(default=0)
    cdhash_rule_count = models.IntegerField(default=0)
    client_mode = models.CharField(max_length=16)
    request_clean_sync = models.BooleanField(default=True)
    last_updated = models.DateTimeField(auto_now=True)
    config = models.ForeignKey(Config, on_delete=models.SET_DEFAULT, default=1)
    profile = models.ForeignKey(Profile, on_delete=models.SET_DEFAULT, default=1)
