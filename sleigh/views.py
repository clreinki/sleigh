from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from django.contrib.auth.models import User
from django.contrib.auth.views import LoginView
from django.http import Http404, JsonResponse, HttpResponse, HttpResponseServerError
from django.core.cache import cache
import json
import logging

from .models import Config, Profile, Rule, Device, LogEntry
from .forms import RegisterForm, CustomLoginForm, CustomUserCreationForm, ConfigEditForm, ProfileEditForm, RuleAddForm
from .custom import addlog, get_client_preflight, get_client_rules

logger = logging.getLogger('django')

################### WEB UI VIEWS ###################

@login_required
def index(request):
    """The main app homepage - for creating new request"""
    configs = cache.get_or_set("cache_allconfigs", Config.objects.all(), None)
    profiles = cache.get_or_set("cache_allprofiles", Profile.objects.all(), None)
    context = {'configs': configs, 'profiles': profiles}
    return render(request, 'sleigh/dashboard.html', context)

###### Config Management ######
@login_required
def config(request, config_id=None):
    """Modify Config Settings"""
    profiles = cache.get_or_set("cache_allprofiles", Profile.objects.all(), None)
    form_errors = None  # Initialize error variable

    # Check if we're editing an existing Config or creating a new one
    if config_id:
        config = get_object_or_404(Config, id=config_id)
        name = config.name
    else:
        config = None  # Create a new instance if no ID is provided
        name = "Add New Config"

    if request.method == "POST":
        form = ConfigEditForm(data=request.POST, instance=config)
        if form.is_valid():
            saved_config = form.save()
            cache.delete("cache_allconfigs")
            return redirect('sleigh:config', config_id=saved_config.id)
        else:
            form_errors = form.errors
    else:
        form = ConfigEditForm(instance=config)
    configs = cache.get_or_set("cache_allconfigs", Config.objects.all(), None)
    context = {'configs': configs, 'profiles': profiles, 'name': name, 'myconfig': config, 'form': form, 'form_errors': form_errors}
    return render(request, 'sleigh/configs.html', context)

@login_required
def delete_config_view(request, config_id):
    if request.method == 'POST' and not config_id == 1:
        try:
            config = Config.objects.get(id=config_id)
            config.delete()
            cache.delete("cache_allconfigs")
            return redirect('sleigh:index')
        except Config.DoesNotExist:
            return HttpResponseServerError("An internal server error occurred.")
    return redirect('sleigh:index')

###### Profile Management ######
@login_required
def profile(request, profile_id=None):
    """Modify Config Settings"""
    configs = cache.get_or_set("cache_allconfigs", Config.objects.all(), None)
    form_errors = None  # Initialize error variable

    # Check if we're editing an existing Config or creating a new one
    if profile_id:
        profile = get_object_or_404(Profile, id=profile_id)
        name = profile.name
        rules = Rule.objects.filter(profile__exact=profile_id).order_by('-id')
    else:
        profile = None  # Create a new instance if no ID is provided
        name = "Add New Profile"
        rules = None

    if request.method == "POST":
        profile_form = ProfileEditForm(data=request.POST, instance=profile)
        if profile_form.is_valid():
            saved_profile = profile_form.save()
            cache.delete("cache_allprofiles")
            return redirect('sleigh:profile', profile_id=saved_profile.id)
        else:
            form_errors = profile_form.errors
    else:
        profile_form = ProfileEditForm(instance=profile)
    rule_form = RuleAddForm(profile=profile, user=request.user)
    profiles = cache.get_or_set("cache_allprofiles", Profile.objects.all(), None)
    context = {'configs': configs, 'profiles': profiles, 'name': name, 'myprofile': profile, 'profile_form': profile_form, 'rule_form': rule_form, 'form_errors': form_errors, 'rules': rules}
    return render(request, 'sleigh/profiles.html', context)

@login_required
def delete_profile_view(request, profile_id):
    if request.method == 'POST' and not profile_id == 1:
        try:
            profile = Profile.objects.get(id=profile_id)
            profile.delete()
            cache.delete("cache_allprofiles")
            return redirect('sleigh:index')
        except Config.DoesNotExist:
            return HttpResponseServerError("An internal server error occurred.")
    return redirect('sleigh:index')

@login_required
def addrule(request):
    if request.method == 'POST':
        form = RuleAddForm(data=request.POST)
        if form.is_valid():
            form.save()
            return redirect('sleigh:profile', profile_id=request.POST['profile'])
        else:
            return HttpResponseServerError("Invalid data submitted")
    else:
        return HttpResponseServerError("No data submitted")

@login_required
def delete_rule_view(request):
    if request.method == 'POST':
        rule_id = request.POST.get('rule_id')
        try:
            rule = Rule.objects.get(id=rule_id)
            rule.delete()
            return JsonResponse({'success': True, 'message': 'Rule deleted successfully!'})
        except Rule.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Rule not found.'}, status=404)
    return JsonResponse({'success': False, 'message': 'Invalid request.'}, status=400)

###### User Management ######
@login_required
def usermgmt(request):
    """Displays existing users"""
    configs = cache.get_or_set("cache_allconfigs", Config.objects.all(), None)
    profiles = cache.get_or_set("cache_allprofiles", Profile.objects.all(), None)
    users = User.objects.all()
    form = CustomUserCreationForm()
    context = {'configs': configs, 'profiles': profiles, 'users': users, 'create_form': form}
    return render(request, 'sleigh/usermgmt.html', context)

class CustomLoginView(LoginView):
    authentication_form = CustomLoginForm

@login_required
def create_user_processing(request):
    form = CustomUserCreationForm(request.POST)
    if form.is_valid():
        form.save()
        return redirect('sleigh:usermgmt')
    return render(request, 'sleigh/error.html')

@login_required
def delete_user_view(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        try:
            user = User.objects.get(id=user_id)
            user.delete()
            return JsonResponse({'success': True, 'message': 'User deleted successfully!'})
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'User not found.'}, status=404)
    return JsonResponse({'success': False, 'message': 'Invalid request.'}, status=400)

################### SANTA VIEWS ###################

@csrf_exempt
def preflight(request, serial):
    if request.method == 'POST':
        try:
            # Parse incoming JSON data
            data = json.loads(request.body)

            # Find or create the device by serial number
            device, created = Device.objects.update_or_create(
                serial_num=serial,
                defaults={
                    'hostname': data.get('hostname', ''),
                    'os_version': data.get('os_version', ''),
                    'os_build': data.get('os_build', ''),
                    'model_identifier': data.get('model_identifier', ''),
                    'santa_version': data.get('santa_version', ''),
                    'primary_user': data.get('primary_user', ''),
                    'binary_rule_count': data.get('binary_rule_count', 0),
                    'certificate_rule_count': data.get('certificate_rule_count', 0),
                    'compiler_rule_count': data.get('compiler_rule_count', 0),
                    'transitive_rule_count': data.get('transitive_rule_count', 0),
                    'teamid_rule_count': data.get('teamid_rule_count', 0),
                    'signingid_rule_count': data.get('signingid_rule_count', 0),
                    'cdhash_rule_count': data.get('cdhash_rule_count', 0),
                    'client_mode': data.get('client_mode', ''),
                    'request_clean_sync': data.get('request_clean_sync', True),
                },
            )

            # Log whether the device was created or updated
            if created:
                print(f"Device {serial} created.")
            else:
                print(f"Device {serial} updated.")

            # Determine response based on serial
            response = cache.get_or_set(serial + "-config", get_client_preflight(serial), None)

            # Return a success response
            return JsonResponse(response, status=200)

        except json.JSONDecodeError:
            # Return an error response if JSON is invalid
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            # Return a generic error response for other exceptions
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def eventupload(request, serial):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            events = data.get('events', [])
            
            for event_data in events:
                Event.objects.create(
                    file_sha256=event_data.get('file_sha256'),
                    file_path=event_data.get('file_path'),
                    file_name=event_data.get('file_name'),
                    executing_user=event_data.get('executing_user'),
                    execution_time=event_data.get('execution_time'),
                    loggedin_users=event_data.get('loggedin_users'),
                    current_sessions=event_data.get('current_sessions'),
                    decision=event_data.get('decision'),
                    file_bundle_id=event_data.get('file_bundle_id'),
                    file_bundle_path=event_data.get('file_bundle_path'),
                    file_bundle_executable_rel_path=event_data.get('file_bundle_executable_rel_path'),
                    file_bundle_name=event_data.get('file_bundle_name'),
                    file_bundle_version=event_data.get('file_bundle_version'),
                    file_bundle_version_string=event_data.get('file_bundle_version_string'),
                    file_bundle_hash=event_data.get('file_bundle_hash'),
                    file_bundle_hash_millis=event_data.get('file_bundle_hash_millis'),
                    file_bundle_binary_count=event_data.get('file_bundle_binary_count'),
                    pid=event_data.get('pid'),
                    ppid=event_data.get('ppid'),
                    parent_name=event_data.get('parent_name'),
                    quarantine_data_url=event_data.get('quarantine_data_url'),
                    quarantine_referer_url=event_data.get('quarantine_referer_url'),
                    quarantine_timestamp=event_data.get('quarantine_timestamp'),
                    quarantine_agent_bundle_id=event_data.get('quarantine_agent_bundle_id'),
                    signing_chain=event_data.get('signing_chain'),
                    signing_id=event_data.get('signing_id'),
                    team_id=event_data.get('team_id'),
                    cdhash=event_data.get('cdhash'),
                    serial_num=serial
                )

            return JsonResponse({'message': 'Events processed successfully'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def ruledownload(request, serial):
    # Determine response based on serial
    response = cache.get_or_set(serial + "-rules", get_client_rules(serial), None)

    # Return a success response
    return JsonResponse(response, status=200)

@csrf_exempt
def postflight(request, serial):
    data = json.loads(request.body)
    Device.objects.filter(serial_num=serial).update(rules_synced=data.get('rules_processed', 0))
    return HttpResponse(status=200)