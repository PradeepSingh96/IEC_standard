from django.urls import path

from . import views
from django.conf.urls import url
from django.contrib.auth import views as auth_views

urlpatterns = [
    path("", views.index, name='index'),
    path("login/", views.login, name="login"),
    path("register/", views.register, name="register"),
    path("send_email/", views.send_email, name="send_email"),
    path("change_password/<token>", views.change_password, name="change_password"),
    path("news/", views.news, name="news"),
    path("projects/", views.projects, name="projects"),
    path("tools/", views.tools, name="tools"),
    path("add_project/", views.add_project, name="add_project"),
    path("logout/", views.logout, name="logout"),

]
