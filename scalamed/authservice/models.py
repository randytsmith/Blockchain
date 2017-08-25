from authservice.managers import UserManager
from django.contrib.auth.models import AbstractUser


# https://docs.djangoproject.com/en/1.11/topics/auth/
class User(AbstractUser):
    objects = UserManager()
