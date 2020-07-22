import datetime
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
# from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import User
from django.urls import reverse


class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, name, email, password=None):

        if not email:
            raise ValueError('Users Must Have an email address')
        user = self.model(name=name, email=email)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, name, email, password):

        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(name, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class User(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(max_length=200)
    email = models.EmailField(max_length=254, unique=True)
    password = models.CharField(max_length=254)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    objects = UserManager()


Tools_CHOICES = (
    ('Commercial_tools_with_PLC_hardware_support', 'Commercial tools with PLC hardware support'),
    ('Open_source_tools', 'Open source tools'),
    ('Academic_and_research_developments', 'Academic and research developments'),
)


class Tools(models.Model):
    title = models.CharField(max_length=1000)
    link = models.CharField(max_length=200)
    description = models.CharField(max_length=40000)
    image = models.FileField(upload_to='tools/', blank=False, null=False)
    modified_at = models.DateTimeField(auto_now=True)
    category = models.CharField(max_length=200, choices=Tools_CHOICES, default='Academic and research developments')

    def __str__(self):
        return self.title  # , self.link, self.description, self.image


class News(models.Model):
    title = models.CharField(max_length=1000)
    link = models.CharField(max_length=200)
    description = models.CharField(max_length=40000)
    image = models.FileField(upload_to='news/', blank=False, null=False)
    modified_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title  # , self.link, self.description, self.image


PROJECT_CHOICES = (
        ('Student_projects', 'Student projects'),
        ('Test_beds', 'Testbeds'),
)


class Projects(models.Model):
    title = models.CharField(max_length=1000)
    link = models.CharField(max_length=200)
    description = models.CharField(max_length=40000)
    image = models.FileField(upload_to='projects/', blank=False, null=False)
    approved = models.BooleanField(default=False)
    category = models.CharField(max_length=200, choices=PROJECT_CHOICES, default='None')
    modified_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title  # , self.link, self.description, self.image
