from typing import Iterable, Optional
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator   

from rest_framework_simplejwt.tokens import RefreshToken

from apps.shared.models import BaseModel

import random
import datetime


    # Foydalanuvchi statuslari
ORDINARY, MANAGER, ADMIN = ('ordinary', 'manager','admin')
    # foydalanuvchi authenticate statuslari
NEW, CODE_FERIFED, DONE, PHOTO_DONE = ('new', 'code_verifed', 'done', 'photo_done')


class User(AbstractUser, BaseModel):
    """
    Foydalanuvchi bosh modeli.
    Bu model, foydalanuvchining first va last_name, 
    password, email'lari bilan birga
     user statusi, user authenticate statusi va boshqa 
     qisimlarini o'z ichiga oladi
     """
    USER_STATUS_CHOICE = (
        (ORDINARY, ORDINARY),
        (MANAGER, MANAGER),
        (ADMIN, ADMIN)
    )
    AUTH_STATUS_CHOICE = (
        (NEW, NEW),
        (CODE_FERIFED, CODE_FERIFED),
        (DONE, DONE),
        (PHOTO_DONE, PHOTO_DONE)
    )

    user_status = models.CharField(max_length=25, choices=USER_STATUS_CHOICE, default=ORDINARY)
    auth_status = models.CharField(max_length=25, choices=AUTH_STATUS_CHOICE, default=NEW)
    email = models.EmailField(unique=True)
    photo = models.ImageField(upload_to='user_photo', null=True, blank=True, validators=[FileExtensionValidator(
        allowed_extensions=['img', 'jpg', 'jpeg', 'heic', 'heif']
    )])
    # password = models.CharField(max_length=25, unique=False)
    # confirm_password = models.CharField(max_length=25, unique=False)

    def __str__(self):
        return str(self.username)
    
    '============================'  
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"
    '============================'  
    
    def create_verify_code(self, email):
        code = "".join([str(random.randint(0, 100) % 10) for i in range(4)])
        UserConfirmation.objects.create(
            user_id=self.id,
            code=code
        )
        return code
    
    def check_username(self):
        if self.username:
            normalize_username = self.username.lower()
            self.username = normalize_username

    def check_email(self):
        if self.email:
            normalize_email = self.email.lower()
            self.email = normalize_email

    def hashing_password(self):
        if not self.password.startswith('pbkdf2_sha256'):
            self.set_password(self.password)
            # self.set_password(self.confirm_password)

    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh)
        }

    def save(self, *args, **kwargs):
        self.hashing_password()
        self.check_username()
        self.check_email()
        super(User, self).save(*args, **kwargs)


validity_time = 2

class UserConfirmation(BaseModel):
    """
    UserConfirmation modeli o'z ichiga, userga 
    yuborilishi kerak bo'lgan tasdiqlash kodi
    va kodning amal qilish muddati, userning ro'yxatdan o'tkani 
    tasdiqlangan yoki tasdiqlanmaganini bildurvchi
    xossalarni o'z ichiga oladi
    """
    AUTH_STATUS_CHOICE = (
        (NEW, NEW),
        (CODE_FERIFED, CODE_FERIFED),
        (DONE, DONE),
        (PHOTO_DONE, PHOTO_DONE)
    )
    auth_status = models.CharField(max_length=25, choices=AUTH_STATUS_CHOICE, default=CODE_FERIFED)
    code = models.CharField(max_length=4) 
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verify_codes')
    expiration_time = models.DateTimeField(null=True)
    is_comfirmed = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if self.code:
            self.expiration_time = datetime.datetime.now() + datetime.timedelta(minutes=validity_time)
        super(UserConfirmation, self).save(*args, **kwargs)