from django.shortcuts import redirect, render
from django.contrib import messages
from .models import User
from passlib.hash import sha256_crypt
from rest_framework_jwt.settings import api_settings
from django.contrib.auth.models import update_last_login
from django.core.mail import send_mail

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
        # import  pdb;pdb.set_trace()
        user_email = User.objects.filter(email=email)
        if len(user_email) == 0:
            messages.info(request, 'email is not registered')
            return redirect('send_email')

        send_mail(
            'Forgot email',
            'Hi, Your registration successfully',
            user_email.get().email,
            [email],
            fail_silently=False,
            )
        messages.info(request, 'email sent successfully')
        return redirect('/')
    else:
        return render(request, 'send_email.html')
