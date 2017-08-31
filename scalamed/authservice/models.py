from authservice.managers import UserManager
from binascii import hexlify, unhexlify
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

KEY_SIZE_BITS = 256
counter = 0


class InvalidSubjectError(InvalidTokenError):
    pass


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

    # DO NOT USE THIS DIRECTLY; USE COUNTER()
    _counter = models.CharField(
        blank=False,
        unique=False,
        max_length=16,
        default='0000000000000000',
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

    def counter(self):
        """Returns the next count. Represented as a 64 bit unsigned integer."""
        ctr = struct.unpack('<Q', unhexlify(self._counter.encode('utf8')))[0]
        self._counter = hexlify(struct.pack('<Q', ctr + 1)).decode('utf8')
        return ctr

    def generate_token(
            self,
            exp=timedelta(minutes=30),
            iat=True,
            sub=True,
            jti=True,
            extra=None):

        global counter
        now = datetime.utcnow()

        claims = {}
        options = {}

        if isinstance(exp, timedelta):
            claims['exp'] = now + exp
            options['require_exp'] = True

        if iat:
            claims['iat'] = now
            options['require_iat'] = True

        jwt = PyJWT(options=options)

        if sub:
            claims['sub'] = self.uuid

        if jti:
            # TODO this needs to be better, counter should be user specific
            nonce = hexlify(
                token_bytes(16) +
                struct.pack(">Q", counter))
            counter += 1
            claims['jti'] = nonce.decode('utf8')

        if extra:
            assert(isinstance(extra, dict))
            for k, v in extra.items():
                assert(k not in claims)
            claims.update(extra)

        return jwt.encode(claims, self.userkey(), algorithm='HS256')

    def validate_token(
            self, token, iat=True, sub=True, jti=True, exp=True, extra=None):

        jwt = PyJWT(options={
            'require_exp': exp,
            'require_iat': iat
        })

        try:
            token = jwt.decode(token, self.userkey(), algorithms=['HS256'])

            if sub:
                if 'sub' not in token:
                    raise MissingRequiredClaimError('sub')
                if token['sub'] != self.uuid:
                    raise InvalidSubjectError()

            if jti and 'jti' not in token:
                raise MissingRequiredClaimError('jti')

            if extra:
                assert(isinstance(extra, dict))
                for k, v in extra.items():
                    if k not in token:
                        raise MissingRequiredClaimError(token)
                    if token[k] is not v:
                        raise InvalidTokenError()

            return True

        except InvalidTokenError as e:
            pass
        #print(str(e))

        return False
