import os
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.contrib.auth.models import User


##
## Helper functions
##
def validate_image_file_extension(value):
    from django.core.exceptions import ValidationError
    ext = os.path.splitext(value.name)[1]  # [0] returns path+filename
    valid_extensions = ['.blp', '.bmp', '.dib', '.bufr', '.cur', '.pcx', '.dcx', '.dds', '.ps', '.eps', '.fit', '.fits',
                        '.fli', '.flc', '.ftc', '.ftu', '.gbr', '.gif', '.grib', '.h5', '.hdf', '.png', '.apng', '.jp2',
                        '.j2k', '.jpc', '.jpf', '.jpx', '.j2c', '.icns', '.ico', '.im', '.iim', '.tif', '.tiff',
                        '.jfif', '.jpe', '.jpg', '.jpeg', '.mpg', '.mpeg', '.mpo', '.msp', '.palm', '.pcd', '.pdf',
                        '.pxr', '.pbm', '.pgm', '.ppm', '.pnm', '.psd', '.bw', '.rgb', '.rgba', '.sgi', '.ras', '.tga',
                        '.icb', '.vda', '.vst', '.webp', '.wmf', '.emf', '.xbm', '.xpm']
    if not ext.lower() in valid_extensions:
        raise ValidationError(F'file type {ext} not allow!')

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
    picture_file = models.FileField(upload_to="profile_pics", blank=True, null=True, storage=OverwriteStorage(),
                                    validators=[validate_image_file_extension])

    def __str__(self):
        return self.user.first_name + " " + self.user.last_name


class Project(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, unique=True)
    picture_file = models.FileField(upload_to="project_pics", blank=True, null=True, storage=OverwriteStorage(),
                                    validators=[validate_image_file_extension])
    budget = models.FloatField(validators=[MinValueValidator(0)])
    completion = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(100)])
    members = models.ManyToManyField(UserProfile)

    def __str__(self):
        return self.name
