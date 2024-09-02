# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, User

class UserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError('The Username field must be set')
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault('is_admin', True)
        return self.create_user(username, password, **extra_fields)

class User(AbstractBaseUser):
    username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    common_name = models.CharField(max_length=255, null=True, blank=True)
    country = models.CharField(max_length=255, null=True, blank=True)
    state = models.CharField(max_length=255, null=True, blank=True)
    locality = models.CharField(max_length=255, null=True, blank=True)
    organization = models.CharField(max_length=255, null=True, blank=True)
    organizational_unit = models.CharField(max_length=255, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    ca_approve = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_ca = models.BooleanField(default=False)
    is_doctor = models.BooleanField(default=False)
    is_patient = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.username

    @property
    def is_staff(self):
        return self.is_admin

class UserKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    public_key = models.TextField()
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{}'s Key".format(self.user.username)

    
class Specialist(models.Model):
    specialist = models.CharField(max_length=100)
    userid = models.IntegerField()

    def __str__(self):
        return "{}".format(self.specialist)

class Doctor(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    specialist = models.ForeignKey(Specialist, on_delete=models.CASCADE)

    def __str__(self):
        return "{} ({})".format(self.user.username, self.specialist.name)

class Patient(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    specialist = models.ForeignKey(Specialist, on_delete=models.CASCADE)

    def __str__(self):
        return "{} ({})".format(self.user.username, self.specialist.name)

# insert into myapp_specialist (userid, specialist) values (3, 'Neurologist'); 
# insert into myapp_specialist (userid, specialist) values (4, 'Neurologist'); 
# insert into myapp_specialist (userid, specialist) values (6, 'Neurologist'); 
# insert into myapp_specialist (userid, specialist) values (7, 'General');
# insert into myapp_specialist (userid, specialist) values (8, 'Radiologist');

class Profile(models.Model):
    SPECIALIZATION_CHOICES = [
        ('Cardiologist', 'Cardiologist'),
        ('Neurologist', 'Neurologist'),
        ('General', 'General'),
        ('Radiologist', 'Radiologist'),
        ('Urologist', 'Urologist'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_doctor = models.BooleanField(default=False)
    specialization = models.CharField(max_length=50, choices=SPECIALIZATION_CHOICES)

    def __str__(self):
        return '{} - {"Doctor" if self.is_doctor else "Patient"}'.format(self.user.username)

