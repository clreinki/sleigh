"""Defines URL patterns for mainapp."""
from django.urls import path
from django.contrib import admin
from django.conf.urls import include

from . import views
from .views import PreflightView

admin.site.site_header = "Sleigh Portal Login"
admin.site.site_title = "Sleigh Admin Portal"
admin.site.index_title = "Sleigh Portal"

app_name = 'sleigh'
urlpatterns = [
    path('', views.index, name='index'),
    path('config/', views.config, name='config'),
    path('config/<int:config_id>/', views.config, name='config'),
    path('delete_config/<int:config_id>/', views.delete_config_view, name='delete_config'),
    path('profile/', views.profile, name='profile'),
    path('profile/<int:profile_id>/', views.profile, name='profile'),
    path('delete_profile/<int:profile_id>/', views.delete_profile_view, name='delete_profile'),
    path('addrule/', views.addrule, name='addrule'),
    path('usermgmt/', views.usermgmt, name='usermgmt'),
    path('v1/preflight/<str:serial>/', PreflightView.as_view(), name='preflight'),
    path('createuser/', views.create_user_processing, name='create_user_processing'),
    path('delete-user/<int:config_id>/', views.delete_user_view, name='delete_user'),
]