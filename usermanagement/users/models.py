import datetime
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

from passlib.hash import sha256_crypt



class UserManager(BaseUserManager):
    def create_user(self, name, email, password=None):
        
        if not email:
            raise ValueError('Users Must Have an email address')
        user = self.model(name=name, email=email, password=sha256_crypt.encrypt(password))
        user.save()
        return user

    def create_superuser(self, name, email, password):
        
        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(name, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class User(AbstractBaseUser):
    name = models.CharField(max_length=200)
    email = models.EmailField(max_length=254, unique=True)
    password = models.CharField(max_length=254)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']
    
    objects = UserManager()


    @staticmethod
    def login_with_email(email, password):
        password_match = False
        user = User.objects.filter(email=email).get()
        if user and sha256_crypt.verify(password, user.password):
            password_match = True
        return user, password_match
