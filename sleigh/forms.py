from django import forms
from django.core.exceptions import ValidationError
from django.db import models
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from django.forms import ModelForm
from django.utils.safestring import mark_safe
import datetime
from crispy_forms.helper import FormHelper

from .models import Config, Profile, Rule, Device, Event

class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)
    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email", "password1", "password2"]

    def clean(self):
       email = self.cleaned_data.get('email')
       if User.objects.filter(email=email).exists():
            raise forms.ValidationError("An account with this email already exists!")
       return self.cleaned_data


class ConfigEditForm(ModelForm):

    class Meta:
        model = Config
        fields = ["name", "description", "client_mode", "batch_size", "full_sync_interval", "allowed_path_regex", "blocked_path_regex","block_usb_mount"]
        widgets = {'description': forms.Textarea(attrs={'rows': 2}),'allowed_path_regex': forms.Textarea(attrs={'rows': 2}),'blocked_path_regex': forms.Textarea(attrs={'rows': 2})}

class ProfileEditForm(ModelForm):

    class Meta:
        model = Profile
        fields = ["name", "description", "standalone"]
        widgets = {'description': forms.Textarea(attrs={'rows': 2})}

class RuleAddForm(forms.ModelForm):
    class Meta:
        model = Rule
        fields = ['policy', 'rule_type', 'identifier', 'description', 'profile', 'created_by']
        widgets = {
            'profile': forms.HiddenInput(),
            'created_by': forms.HiddenInput(),
            'description': forms.Textarea(attrs={'rows': 2}),
            'rule_type': forms.RadioSelect(),
            'policy': forms.RadioSelect()
        }

    def __init__(self, *args, **kwargs):
        # Extract the profile instance or ID from kwargs
        profile = kwargs.pop('profile', None)
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        if profile:
            # Set the initial value of the hidden profile field
            self.fields['profile'].initial = profile.id
        if user:
            self.fields['created_by'].initial = user.username

class DeviceObjectForm(forms.Form):
    # Use a Device instance's ID as the checkbox value
    devices = forms.ModelMultipleChoiceField(
        queryset=Device.objects.all(),
        widget=forms.CheckboxSelectMultiple
    )

class IgnoreEventForm(forms.Form):
    # Use a Event instance's id as the checkbox value
    events = forms.ModelMultipleChoiceField(
        queryset=Event.objects.filter(ignored=False).order_by('-id'),
        widget=forms.CheckboxSelectMultiple
    )

class CustomLoginForm(AuthenticationForm):
    username = forms.CharField(
        label="",
        widget=forms.TextInput(attrs={'class': 'form-control form-control-user mb-4', 'placeholder': 'Username'})
    )
    password = forms.CharField(
        label="",
        widget=forms.PasswordInput(attrs={'class': 'form-control form-control-user mb-4', 'placeholder': 'Password'})
    )


class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter username',
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter email',
            }),
            'password1': forms.PasswordInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter password',
            }),
            'password2': forms.PasswordInput(attrs={
                'class': 'form-control',
                'placeholder': 'Confirm password',
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})