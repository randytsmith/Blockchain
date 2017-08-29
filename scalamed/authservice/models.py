from authservice.managers import UserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from uuid import uuid4

import jwt
from secrets import token_bytes
from datetime import datetime, timedelta


KEY_SIZE_BITS = 256


def generate_uuid():
    # TODO check that it is unique
    return str(uuid4())


def generate_secret():
    # TODO cryptographically secure secret
    return token_bytes(KEY_SIZE_BITS // 8).hex()


class User(AbstractBaseUser, PermissionsMixin):
    """
    Merger of AbstractUser/User from django.contrib.auth.models. Due to
    requiring email as the username.
    """

    class Role:
        PATIENT = 'PAT'
        DOCTOR = 'DOC'
        PHARMACIST = 'PHA'

    roles = [
        (Role.PATIENT, 'Patient'),
        (Role.DOCTOR, 'Doctor'),
        (Role.PHARMACIST, 'Pharmacist'),
    ]

    objects = UserManager()

    email = models.EmailField(
        'email address',
        blank=False,
        unique=True,
        error_messages={
            'unique': ("A user with that email address already exists."),
        },
    )

    is_staff = models.BooleanField(
        'staff status',
        default=False,
        help_text='Designates whether the user can log into this admin site.',
    )

    is_active = models.BooleanField(
        'active',
        default=True,
        help_text=(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )

    role = models.CharField(
        blank=False,
        choices=roles,
        default='PAT',
        help_text=(
            'Designates the role of the user and subsequently their authority '
            'to perform certain actions.'
        ),
        max_length=3,
    )

    uuid = models.CharField(
        blank=False,
        unique=True,
        error_messages={
            'unique': ("A user with that uuid already exists."),
        },
        max_length=36,
        default=generate_uuid
    )

    date_joined = models.DateTimeField('date joined', default=timezone.now)

    secret = models.CharField(
        blank=False,
        unique=True,
        max_length=(KEY_SIZE_BITS // 8) * 2,
        default=generate_secret
    )

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['password']

    class Meta:
        swappable = 'AUTH_USER_MODEL'
        verbose_name = 'user'
        verbose_name_plural = 'users'

    def clean(self):
        super().clean()
        self.email = type(self).objects.normalize_email(self.email)

    def generate_token_level_0(self):
        token = jwt.encode({
            'level': 0
        }, self.uuid + 'secret', algorithm='HS256')
        return token

    def generate_token_level_1(self):
        # TODO: refresh with a new token
        token = jwt.encode({
            'level': 1,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, self.uuid + 'secret', algorithm='HS256')
        return token

    def verify_token_level_0(self, token):
        result = jwt.decode(token, self.uuid + 'secret', algorithm='HS256')
        if result['level'] != 0:
            raise jwt.InvalidTokenError

    def verify_token_level_1(self, token):
        result = jwt.decode(token, self.uuid + 'secret', algorithm='HS256')
        if result['level'] != 1:
            raise jwt.InvalidTokenError
