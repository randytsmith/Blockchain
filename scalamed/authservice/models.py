from authservice.managers import UserManager
from binascii import hexlify, unhexlify
from datetime import timedelta
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.conf import settings
from django.db import models
from django.utils import timezone
from hashlib import sha256
from jwt import PyJWT, InvalidTokenError
from secrets import token_bytes
from uuid import uuid4
from scalamed.logging import log

import struct

KEY_SIZE_BITS = 256
counter = 0


class InvalidSubjectError(InvalidTokenError):
    pass


def generate_uuid():
    """Generate a random UUID"""
    return str(uuid4())


def generate_secret():
    """Generate a cryptographically secure secret."""
    return token_bytes(KEY_SIZE_BITS // 8).hex()


class User(AbstractBaseUser, PermissionsMixin):
    """
    Merger of AbstractUser/User from django.contrib.auth.models. Due to
    requiring email as the username, and some other modifications to the user
    class.
    """

    class Role:
        """
        The role of the user, one of:
            - ``Role.PATIENT``
            - ``Role.DOCTOR``
            - ``Role.PHARMACIST``
        """
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

    def __str__(self):
        return "User(uuid={}, email={}, role={})".format(
            self.uuid, self.email, self.role)

    def clean(self):
        super().clean()
        self.email = type(self).objects.normalize_email(self.email)

    def _userkey(self):
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
        self.save()
        return ctr

    # TODO this needs to be better, counter should be user specific and
    # survive us failing state. Like, we increase the counter by 10 when
    # we fail to ensure we don't resuse, etc...
    def __generate_nonce(self):
        global counter
        nonce = hexlify(token_bytes(16) + struct.pack(">Q", counter))
        counter += 1
        return nonce.decode('utf8')

    def generate_token(self, level, exp=timedelta(minutes=30)):
        """
        Generate a session token for the user, providing the level and exp.

        :param level: The token level
        :type level: int
        :param exp: The expiration delta of the token
        :type exp: datetime.timedelta
        :return: JWT encoded claims
        :rtype: str
        :Example:

        >>> user = User.objects.create(...)
        >>> token = user.generate_token(level=0)
        """
        assert(isinstance(exp, timedelta))
        assert(isinstance(level, int))

        now = timezone.now()

        claims = {
            'iat': now,
            'exp': now + exp,
            'sub': self.uuid,
            'jti': self.__generate_nonce(),
            'level': level,
        }

        jwt = PyJWT(options={
            'require_exp': True,
            'require_iat': True,
        })

        ValidTokens.objects.create(
            jti=claims['jti'], exp=claims['exp'], user=self)

        return jwt.encode(claims, self._userkey(), algorithm='HS256')

    def __validate_and_get_claims(self, session_token, level):
        assert(isinstance(level, int))

        jwt = PyJWT(options={
            'require_exp': True,
            'require_iat': True,
        })

        try:
            token = jwt.decode(
                session_token,
                self._userkey(),
                algorithms=['HS256'])
        except InvalidTokenError as e:
            log.warning(str(e))
            return False

        if 'sub' not in token:
            return False

        if token['sub'] != self.uuid:
            return False

        if 'jti' not in token:
            return False

        if token['level'] is not level:
            return False

        # Is the token in our database of valid tokens?
        try:
            ValidTokens.objects.get(jti=token['jti'], user=self)
        except ValidTokens.DoesNotExist:
            return False

        return token

    def validate_token(self, token, level):
        return self.__validate_and_get_claims(token, level) is not False

    def delete_token(self, session_token, level):
        """
        Validates a token and deletes.
        :todo: Throw exception if token invalid?
        """

        claims = self.__validate_and_get_claims(session_token, level)

        if not claims:
            return False

        try:
            tokenmeta = ValidTokens.objects.get(jti=claims['jti'], user=self)
            tokenmeta.delete()
            return True
        except ValidTokens.DoesNotExist:
            return False


# TODO this table needs to have some process clear out the expired tokens.
# Otherwise it will grow endlessly.
class ValidTokens(models.Model):
    """
    This model represents the nonces of the valid tokens in use by users. This
    helps to ensure that a nonce is unique, but also removes forging of a token,
    an attacker would have to guess the nonce in the token, and then sign it.
    """
    jti = models.CharField(
        blank=False,
        null=False,
        max_length=48,
        help_text='The JTI from a token.'
    )

    exp = models.DateTimeField(
        blank=False,
        null=False
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        unique_together = (("jti", "user"), )
