
from django.contrib.auth.models import UserManager as DjangoUserManager


class UserManager(DjangoUserManager):

    def _create_user(self, username, email, password, **extra_fields):
        """
        Create and save a user with the given email, and password.
        This function is a copy of create_user() in Django-1.11. The major
        difference is validation occuring before a user is created; and the fact
        that the username is the email address.
        """
        assert(username is None)
        if not email:
            raise ValueError('The given email must be set')
        if not password:
            raise ValueError('The given password must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.full_clean()
        user.save(using=self._db)
        return user
