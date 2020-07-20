from django.urls import path

from . import views
from django.conf.urls import url


urlpatterns = [
    path("", views.index, name='index'),
    path("login/", views.login, name="login"),
    path("register/", views.register, name="register"),
    path("send_email/", views.send_email, name="send_email")

]
