from django.contrib import admin
from .models import Profile, Config, Rule, Device, LogEntry, Event, IgnoredEntry

# Register your models here.
admin.site.register(Profile)
admin.site.register(Config)
admin.site.register(Rule)
admin.site.register(Device)
admin.site.register(LogEntry)
admin.site.register(Event)
admin.site.register(IgnoredEntry)