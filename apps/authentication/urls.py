# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path
from .views import login_user, register_user, reset_password, register_activate
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path("login/", login_user, name="login"),
    path("register/", register_user, name="register"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("password/", reset_password, name="password"),
    path("activate/<uidb64>/<token>/", register_activate, name='register_activate'),
]
