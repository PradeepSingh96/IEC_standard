from django.shortcuts import redirect, render
from django.contrib import messages
from .models import User
from passlib.hash import sha256_crypt
from rest_framework_jwt.settings import api_settings
from django.contrib.auth.models import update_last_login
from django.core.mail import send_mail
from itsdangerous import URLSafeTimedSerializer
from datetime import timedelta

SECRET_KEY = 'nzu3f^zvxhxm2e+ei)p&^qr)ap#v5*!93(w!al-b3vp6z=qoz0'

JWT_PAYLOAD_HANDLER = api_settings.JWT_PAYLOAD_HANDLER
JWT_ENCODE_HANDLER = api_settings.JWT_ENCODE_HANDLER


def index(request):
    return render(request, 'index.html')


def register(request):
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        if password1 == password2:
            if User.objects.filter(email=email).exists():
                print('email already registered')
                messages.info(request, 'email already registered')
                return redirect('register')
            else:
                user = User.objects.create_user(name=name, password=password1, email=email)
                print("user created")
                return redirect('login')
        else:
            print('password not matching....')
            messages.info(request, 'password not matched')
            return redirect('register')

    else:
        return render(request, 'register.html')


def login(request):
    if request.method == 'POST':

        email = request.POST['email']
        password = request.POST['password']
        user_email = User.objects.filter(email=email)
        if len(user_email) == 0:
            messages.info(request, 'email is not registered')
            return redirect('login')
        user, password_match = User.login_with_email(email, password)
        if user and password_match:
            print('login Success')
            user = User.objects.get(email=email)
            payload = JWT_PAYLOAD_HANDLER(user)
            jwt_token = JWT_ENCODE_HANDLER(payload)
            print("jwt_token : ", jwt_token)
            update_last_login(None, user)
            return redirect('/')
        else:
            print("invalid cred")
            messages.info(request, 'invalid credentials')
            return redirect('login')

    else:
        return render(request, 'login.html')


def send_email(request):
    if request.method == 'POST':
        email = request.POST['email']
        user_email = User.objects.filter(email=email)
        if len(user_email) == 0:
            messages.info(request, 'email is not registered')
            return redirect('send_email')
        user = User.objects.filter(email=email).get()
        link = 'http://127.0.0.1:8000/change_password/' + generate_confirmation_token(user.email)
        subject = 'Reset Password'
        message = ("Hello " + user.name + ",\n\nPlease click on the following link to reset your password:\n")

        send_mail(subject, message + link, user_email.get().email, [email],
                  fail_silently=False,
                  )
        # messages.info(request, 'email sent successfully')
        return redirect('/')
    else:
        return render(request, 'send_email.html')


def change_password(request, **kwargs):
    if request.method == 'POST':
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        token = kwargs.get('token')
        email = confirm_token(token)
        link = 'http://127.0.0.1:8000/change_password/' + token
        if email:
            if password1 == password2:
                user = User.objects.filter(email=email).get()
                user.password = sha256_crypt.encrypt(password1)
                user.save()
                return redirect('login')
            else:
                print('password not matching....')
                messages.info(request, 'password not matched')
                return redirect(link)
        else:
            return redirect('change_password')
    else:
        return render(request, 'pass.html')


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(SECRET_KEY)
    return serializer.dumps(email)


def confirm_token(token, expiration=43200):
    serializer = URLSafeTimedSerializer(SECRET_KEY)
    try:
        email = serializer.loads(
            token,
            max_age=expiration
        )
    except:
        return False
    return email
