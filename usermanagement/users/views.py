from django.shortcuts import redirect, render
from django.contrib import messages
from .models import User
from rest_framework_jwt.settings import api_settings
from django.contrib.auth.models import update_last_login
from django.core.mail import send_mail
from itsdangerous import URLSafeTimedSerializer
from datetime import timedelta
from usermanagement.settings import SECRET_KEY, EMAIL_HOST_USER
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
User = get_user_model()


SECRET_KEY = SECRET_KEY

JWT_PAYLOAD_HANDLER = api_settings.JWT_PAYLOAD_HANDLER
JWT_ENCODE_HANDLER = api_settings.JWT_ENCODE_HANDLER


def index(request):
    return render(request, 'index.html')


# User Register
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


# user login
def login(request):

    if request.method == 'POST':

        email = request.POST['email']
        password = request.POST['password']
        user_email = User.objects.filter(email=email)
        if len(user_email) == 0:
            messages.info(request, 'email is not registered')
            return redirect('login')
        user = authenticate(email=email, password=password)
        if user is not None:
            print('login Success')
            update_last_login(None, user)
            return redirect('/')
        else:
            print("invalid cred")
            messages.info(request, 'invalid credentials')
            return redirect('login')

    else:
        return render(request, 'login.html')


# forget password email send
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


# update password
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
                user.set_password(password1)
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
