from authservice.managers import UserManager
from binascii import hexlify, unhexlify
from datetime import datetime, timedelta
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.conf import settings
from django.db import models
from django.utils import timezone
from enum import Enum, unique
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


@unique
class TokenType(Enum):
    """
    The type of token to generate.
    """
    LEVEL_ZERO = 0
    LEVEL_ONE = 1
    RESET_PASSWORD = 2

    def ttl(self):
        """
        Returns the time-to-live for a token.
        """
        return {
            self.LEVEL_ZERO: timedelta(hours=24),
            self.LEVEL_ONE: timedelta(minutes=30),
            self.RESET_PASSWORD: timedelta(hours=48),
        }[self]


class TokenManager():

    @staticmethod
    def generate(user, kind):
        """
        Generate a session token for the user, providing the level and exp.

        :param user: The user to generate the token for.
        :type user: models.User
        :param kind: The type of token to generate
        :type kind: models.TokenType
        :return: JWT encoded claims
        :rtype: str
        :Example:

        >>> user = User.objects.create(...)
        >>> token = TokenManager.generate(user, TokenType.LEVEL_ZERO)
        """
        assert(isinstance(kind, TokenType))
        assert(kind in list(TokenType))

        now = timezone.now()

        claims = {
            'iat': now,
            'exp': now + kind.ttl(),
            'sub': user.uuid,
            'jti': user.nonce(),
            'typ': int(kind.value),
        }

        jwt = PyJWT(options={
            'require_exp': True,
            'require_iat': True,
        })

        ValidTokens.objects.create(
            jti=claims['jti'], exp=claims['exp'], user=user)

        return jwt.encode(claims, user.private_key(), algorithm='HS256')

    @staticmethod
    def validate(user, encoded_token, kind):
        """
        Validate a token generated by TokenManager.generate(...).

        :param user: The user the token was generated for.
        :type user: authservice.models.User
        :param encoded_token: The token to verify.
        :type encoded_token: Base64 Encoded JWT Token
        :param kind: The expected type of the token
        :type kind: TokenType
        :return: JWT encoded claims or False
        :rtype: str or bool
        :Example:

        >>> user = User.objects.create(...)
        >>> token = TokenManager.generate(user, TokenType.LEVEL_ZERO)
        >>> TokenManager.validate(user, token, TokenType.LEVEL_ZERO)
        """
        assert(isinstance(user, User))
        assert(isinstance(kind, TokenType))
        assert(kind in list(TokenType))

        jwt = PyJWT(options={
            'require_exp': True,
            'require_iat': True,
        })

        try:
            claims = jwt.decode(
                encoded_token, user.private_key(), algorithms=['HS256'])
        except InvalidTokenError as e:
            log.warning(str(e))
            return False

        if ('sub' not in claims) or (claims['sub'] != user.uuid):
            return False

        if ('typ' not in claims) or (claims['typ'] is not int(kind.value)):
            return False

        if 'jti' not in claims:
            return False

        # Is the jti in our database of valid jti?
        try:
            entry = ValidTokens.objects.get(jti=claims['jti'], user=user)
        except ValidTokens.DoesNotExist:
            return False
        else:
            seconds = int(entry.exp.timestamp())
            if seconds != claims['exp']:
                return False

        return claims

    @staticmethod
    def delete(user, claims):
        """
        Delete a valid token entry.

        :param user: The user the token was generated for.
        :type user: authservice.models.User
        :param claims: The validated claims.
        :type claims: dict
        :return: Whether or not the claim was found and deleted
        :rtype: bool
        :Example:

        >>> user = User.objects.create(...)
        >>> token = TokenManager.generate(user, TokenType.LEVEL_ZERO)
        >>> ...
        >>> claims = TokenManager.validate(user, token, TokenType.LEVEL_ZERO)
        >>> TokenManager.delete(user, claims)
        """
        assert(isinstance(user, User))

        if 'jti' not in claims:
            return False

        try:
            entry = ValidTokens.objects.get(jti=claims['jti'], user=user)
        except ValidTokens.DoesNotExist:
            return False
        else:
            entry.delete()
            return True

        return False


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

    def private_key(self):
        """
        Generate a unique key for each users JWT, derived from the master
        key, user data, and user secret. Use of this key should only be for
        ephemeral information: e.g. token_level_0, or token_level_1

        !! DO NOT USE FOR LONG-TERM ENCRYPTION !!

        TODO We need to have an internal discussion about:
         - How key rollover works?
         - Cryptographic secureness of this schema?
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

    def nonce(self):
        """
        Create a unique nonce. The nonce is made up of:
         - 16 bytes randomness
         -  8 bytes counter

        The randomness makes the nonce difficult to predict, but also maintains
        a high level of probability that the nonce will be unique, if for some
        reason a count gets reused.

        The counter is there to ensure uniqueness for 2**64 nonces. This system
        has a low bandwidth of nonce-generation, and should therefore never need
        to roll the keys/secrets.
        """
        nonce = hexlify(token_bytes(16) + struct.pack(">Q", self.counter()))
        return nonce.decode('utf8')


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
