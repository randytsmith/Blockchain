from authservice.managers import UserManager
from binascii import hexlify
from datetime import datetime, timedelta
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.conf import settings
from django.db import models
from django.utils import timezone
from hashlib import sha256
from jwt import PyJWT, InvalidTokenError, MissingRequiredClaimError
from secrets import token_bytes
from uuid import uuid4

import struct


jwt = PyJWT(options={'require_exp': True, 'require_iat': True, })

KEY_SIZE_BITS = 256

counter = 0


def generate_uuid():
    """Generate a UUID"""
    return str(uuid4())


def generate_secret():
    """Generate a cryptographically secure secret."""
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
        max_length=(KEY_SIZE_BITS // 8) * 2,  # storing as HEX: bytes*2
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

    def userkey(self):
        """
        Generate a unique key for each users JWT, derived from the master
        key, user data, and user secret. Use of this key should only be for
        ephemeral information: e.g. token_level_0, or token_level_1
        """
        assert(len(self.secret) == (KEY_SIZE_BITS // 8) * 2)
        assert(len(self.uuid) == 36)
        assert(settings.SECRET_KEY is not None)

        return sha256(
            "{}{}{}"
            .format(self.secret, self.uuid, settings.SECRET_KEY)
            .encode('utf8')
        ).hexdigest()

    def generate_token(self):
        global counter
        now = datetime.utcnow()
        ttl = timedelta(minutes=10)

        nonce = hexlify(token_bytes(16) + struct.pack(">Q", counter))
        claims = {

            # These claims are validated by PyJWT
            'exp': now + ttl,
            'iat': now,

            # These claims we have to validate ourselves
            'sub': self.email,
            'jti': nonce.decode('utf8'),
        }
        return jwt.encode(claims, settings.SECRET_KEY)

    def validate_token(self, token):
        try:
            token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])

            if 'sub' not in token:
                raise MissingRequiredClaimError('sub')

            if 'jti' not in token:
                raise MissingRequiredClaimError('jti')

            return True

        except InvalidTokenError as e:
            print(str(e))

        return False

    def generate_token_level_0(self):
        return jwt.encode({
            'level': 0,
            'exp': datetime.utcnow() + timedelta(days=30),
            'iat': datetime.utcnow(),
            'sub': self.uuid,
        }, self.userkey(), algorithm='HS256')

    def generate_token_level_1(self):
        return jwt.encode({
            'level': 1,
            'exp': datetime.utcnow() + timedelta(minutes=30),
            'iat': datetime.utcnow(),
            'sub': self.uuid,
        }, self.userkey(), algorithm='HS256')

    def verify_token_level_0(self, token):
        if not token:
            return False

        token = jwt.decode(token, self.userkey(), algorithm='HS256')
        if token['level'] != 0:
            raise jwt.InvalidTokenError(
                "token.level was {} expected {}"
                .format(token['level'], 0))
            return False
        return True

    def verify_token_level_1(self, token):
        if token is None:
            return False

        token = jwt.decode(token, self.userkey(), algorithm='HS256')
        if token['level'] != 1:
            raise jwt.InvalidTokenError(
                "token.level was {} expected {}"
                .format(token['level'], 1))
            return False
        return True
