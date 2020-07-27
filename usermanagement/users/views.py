from django.shortcuts import redirect, render
from django.contrib import messages
from .models import User, News, Tools, Projects
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.models import update_last_login, auth
from django.core.mail import send_mail
from itsdangerous import URLSafeTimedSerializer
from datetime import timedelta
from django.conf.global_settings import SECRET_KEY
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required

User = get_user_model()


def index(request):

    if request.method == 'POST':
        import pdb;
        pdb.set_trace()
        email = request.POST['email']
        password = request.POST['password']
        user_email = User.objects.filter(email=email)
        if len(user_email) == 0:
            messages.info(request, 'email is not registered')
            return redirect('login')
        user = auth.authenticate(email=email, password=password)
        if user is not None:
            auth.login(request, user)
            # update_last_login(None, user)
            return redirect('/')
        else:
            messages.info(request, 'invalid credentials')
            return redirect('login')

    else:
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
                return redirect('/')
        else:
            print('password not matching....')
            messages.info(request, 'password not matched')
            return redirect('/')

    else:
        return render(request, 'register.html')


# user login
def login(request):
    if request.method == 'POST':
        # import pdb;pdb.set_trace()
        email = request.POST['email']
        password = request.POST['password']
        user_email = User.objects.filter(email=email)
        if len(user_email) == 0:
            messages.info(request, 'email is not registered')
            return redirect('/')
        user = auth.authenticate(email=email, password=password)
        if user is not None:
            auth.login(request, user)
            update_last_login(None, user)
            return redirect('/')
        else:
            messages.info(request, 'invalid credentials')
            return redirect('/')

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

        link = 'http://' + request.get_host() + '/change_password/' + generate_confirmation_token(user.email)

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

        link = 'http://' + request.get_host() + '/change_password/' + token

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
            print("email not found")
            messages.info(request, 'This link is expired, Please generate new Link')
            return redirect('send_email')
    else:
        return render(request, 'pass.html')


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(SECRET_KEY)
    return serializer.dumps(email)


def confirm_token(token, expiration=43200):
    serializer = URLSafeTimedSerializer(SECRET_KEY)
    try:
        email = serializer.loads(token, max_age=expiration)
    except:
        return False
    return email


# news
def news(request):
    if request.method == "GET":
        news = News.objects.all().order_by('-modified_at')
        return render(request, 'news.html', {'news': news})
    else:
        return render(request, 'news.html')


# Projects
def projects(request):
    if request.method == "GET":

        Student_projects = Projects.objects.filter(approved=True, category='Student_projects').all().order_by(
            '-modified_at')
        Test_beds = Projects.objects.filter(approved=True, category='Test_beds').all().order_by('-modified_at')

        return render(request, 'projects.html', {'Student_projects': Student_projects, 'Test_beds': Test_beds})
    else:
        return render(request, 'projects.html')


# Tools
def tools(request):
    if request.method == "GET":

        Commercial_tools_with_PLC_hardware_support = Tools.objects.filter(
            category='Commercial_tools_with_PLC_hardware_support').all().order_by('-modified_at')
        Open_source_tools = Tools.objects.filter(category='Open_source_tools').all().order_by('-modified_at')
        Academic_and_research_developments = Tools.objects.filter(
            category='Academic_and_research_developments').all().order_by('-modified_at')

        return render(request, 'tools.html',
                      {'Commercial_tools_with_PLC_hardware_support': Commercial_tools_with_PLC_hardware_support,
                       'Open_source_tools': Open_source_tools,
                       'Academic_and_research_developments': Academic_and_research_developments})
    else:
        return render(request, 'tools.html')


# Add Project
@login_required(login_url='login')
def add_project(request):
    if request.method == "POST" and request.FILES['myfile']:
        title = request.POST['title']
        link = request.POST['link']
        description = request.POST['description']
        category = request.POST['category']
        myfile = request.FILES['myfile']

        fs = FileSystemStorage(location='media/projects/')
        fs.save(myfile.name, myfile)
        uploaded_file_url = 'projects/' + myfile.name

        project = Projects(title=title, link=link, description=description, category=category, image=uploaded_file_url)
        project.save()
        return redirect('/')
    else:
        return render(request, '/')


# Logout
def logout(request):
    auth.logout(request)
    return redirect('/')


# imprint
def imprint(request):
    if request.method == "GET":
        return render(request, 'imprint.html')
    else:
        return render(request, 'imprint.html')


# publications
def publications(request):
    if request.method == "GET":
        return render(request, 'publication.html')
    else:
        return render(request, 'publication.html')


# resources
def resources(request):
    if request.method == "GET":
        return render(request, 'resources.html')
    else:
        return render(request, 'resources.html')
