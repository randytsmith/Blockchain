
from django.contrib.auth.models import UserManager as DjangoUserManager


class UserManager(DjangoUserManager):

    def _create_user(self, username, email, password, **extra_fields):
        """
        Create and save a user with the given username, email, and password.
        This function is a copy of create_user() in Django-1.11. The major
        difference is validation occuring before a user is created.
        """
        if not username:
            raise ValueError('The given username must be set')
        email = self.normalize_email(email)
        username = self.model.normalize_username(username)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.full_clean()
        user.save(using=self._db)
        return user
