from django.urls import path, re_path
from .views import (
    index,
    edit_profile,
    view_profile,
    all_profiles,
    new_project,
    edit_project,
    view_project,
    debug,
    billing,
)

urlpatterns = [
    # The home page
    path("", index, name="home"),
    path("index/", index, name="index"),
    # profiles
    path("profile/<int:user_id>", view_profile, name="view_profile"),
    path("profiles/", all_profiles, name="all_profiles"),
    path("editprofile/<int:user_id>", edit_profile, name="edit_profile"),
    # projects
    path("newproject/", new_project, name="new_project"),
    path("editproject/<int:project_id>/<int:user_id>", edit_project, name="edit_project"),
    path("viewproject/<int:project_id>", view_project, name="view_project"),
    # admin
    path("debug/", debug, name="debug"),
    path("billing/", billing, name="billing")
    # others
    # re_path(r"^.*\.*", pages, name="pages"),
]
