import datetime
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from passlib.hash import sha256_crypt
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import User

# class MyUserManager(BaseUserManager):
#     ''' Inherits BaseUserManager class'''
#
#     def create_superuser(self,name, email, password):
#         '''Creates and saves a superuser with the given email and password.'''
#         user = self.model(email=email, name=name)
#         user.set_password(password)
#         user.is_superuser = True
#         user.is_active = True
#         user.is_staff = True
#         user.save(using=self._db)
#         return user
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


class Tools(models.Model):
    Title = models.CharField(max_length=200)
    Description = models.CharField(max_length=40000)

