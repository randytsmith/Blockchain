from authservice.models import User
from datetime import timedelta
from django.test import TestCase
from jwt.exceptions import ExpiredSignatureError
from unittest.mock import patch


class UserTestCase(TestCase):
    def setUp(self):
        pass

    def test_create_user(self):
        """Test create_user creates a user with working defaults."""

        user = User.objects.create_user(
            username=None,
            email="bob@example.com",
            password="password123")
        self.assertFalse(hasattr(user, 'username'))
        self.assertEqual(user.email, "bob@example.com")
        self.assertNotEqual(user.password, "password123")
        self.assertIsNotNone(user.uuid)
        self.assertEqual(len(user.uuid), 36)
        self.assertEqual(user.role, User.Role.PATIENT)

    def test_token_level_0_default(self):
        """Test the generation and validation of tokens"""

        user = User.objects.create_user(
            username=None,
            email="bob@example.com",
            password="password123")

        t0 = user.generate_token_level_0()
        user.verify_token_level_0(t0)

    @patch('authservice.models.timedelta')
    def test_token_level_1_expiry(self, timedelta_mock):
        """Test the generation and validation of tokens"""

        def foo(*args, **kwargs):
            return timedelta(seconds=-1)

        timedelta_mock.side_effect = foo
        user = User.objects.create_user(
            username=None,
            email="bob@example.com",
            password="password123")
        t0 = user.generate_token_level_1()

        with self.assertRaises(ExpiredSignatureError):
            user.verify_token_level_1(t0)
