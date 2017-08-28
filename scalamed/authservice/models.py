from authservice.managers import UserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from uuid import uuid4


def generate_uuid():
    # TODO check that it is unique
    return uuid4()


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

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['password']

    class Meta:
        swappable = 'AUTH_USER_MODEL'
        verbose_name = 'user'
        verbose_name_plural = 'users'

    def clean(self):
        super().clean()
        self.email = self.objects.normalize_email(self.email)
