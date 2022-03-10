from http import client
from django.db import models
from django.contrib.auth.models import AbstractUser
import random

# Create your models here.
class User(AbstractUser):
    client_id = models.IntegerField(default=random.randint(100,1000))
    client_secret = models.IntegerField(default=random.randint(100,1000))
    full_name = models.CharField(max_length=255)
    npm = models.CharField(max_length=10)
