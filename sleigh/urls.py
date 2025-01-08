"""Defines URL patterns for mainapp."""
from django.urls import path
from django.contrib import admin
from django.conf.urls import include

from . import views

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
    path('delete-rule/', views.delete_rule_view, name='delete_rule'),
    path('usermgmt/', views.usermgmt, name='usermgmt'),
    path('createuser/', views.create_user_processing, name='create_user_processing'),
    path('delete-user/', views.delete_user_view, name='delete_user'),
    path('preflight/<str:serial>/', views.preflight, name='preflight'),
    #path('v1/eventupload/<str:serial>/', EventUploadView.as_view(), name='eventupload'),
    path('eventupload/<str:serial>/', views.eventupload, name='eventupload'),
    path('postflight/<str:serial>/', views.postflight, name='postflight'),
]