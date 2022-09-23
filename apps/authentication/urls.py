# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path
from .views import login_user, register_user, reset_password, register_activate, reset_password_done, \
    reset_password_sent, reset_password_confirm, logout_user

urlpatterns = [
    path("login/", login_user, name="login"),
    path("register/", register_user, name="register"),
    path("logout/", logout_user, name="logout"),
    path("password/", reset_password, name="password"),
    path("activate/<uidb64>/<token>/", register_activate, name='register_activate'),
    path("reset_password/sent/", reset_password_sent, name="reset_password_sent"),
    path("reset/<uidb64>/<token>/", reset_password_confirm, name="reset_password_confirm"),
    path("reset_password/done/", reset_password_done, name="reset_password_done")
]
