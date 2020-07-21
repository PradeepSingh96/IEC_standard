from django.contrib import admin
from .models import User, Tools, News, Projects
# Register your models here.

admin.site.register(User)
admin.site.register(Tools)
admin.site.register(News)
admin.site.register(Projects)
