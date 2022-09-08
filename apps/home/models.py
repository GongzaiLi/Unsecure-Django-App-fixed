import os
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.contrib.auth.models import User


##
## Helper functions
##

# Overwrite existing files for bio files
# adapted from https://gist.github.com/fabiomontefuscolo/1584462
class OverwriteStorage(FileSystemStorage):
    def get_available_name(self, name, max_length=None):
        if self.exists(name):
            os.remove(os.path.join(settings.MEDIA_ROOT, name))
        return name


##
## Model classes
##


class UserProfile(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    bio_file = models.FileField(upload_to="bio", blank=True, null=True, storage=OverwriteStorage())
    picture_file = models.FileField(upload_to="profile_pics", blank=True, null=True)

    def __str__(self):
        return self.user.first_name + " " + self.user.last_name


class Project(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, unique=True)
    picture_file = models.FileField(upload_to="project_pics", blank=True, null=True)
    budget = models.FloatField(validators=[MinValueValidator(0)])
    completion = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(100)])
    members = models.ManyToManyField(UserProfile)

    def __str__(self):
        return self.name
