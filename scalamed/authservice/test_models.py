from authservice.models import User, TokenManager, TokenType
from datetime import timedelta
from django.test import TestCase
from scalamed.logging import log
from unittest import mock


class UserTestCase(TestCase):
    def setUp(self):
        log.setLevel(10)

    def tearDown(self):
        log.setLevel(30)

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

        token = user.generate_token(level=0)
        self.assertTrue(user.validate_token(token, level=0))

    def test_token_level_1_default(self):
        """Test the generation and validation of tokens"""

        user = User.objects.create_user(
            username=None,
            email="bob@example.com",
            password="password123")

        token = user.generate_token(level=1)
        self.assertTrue(user.validate_token(token, level=1))

    # TODO patch kind.ttl()
    @mock.patch('authservice.models.TokenType.ttl')
    def test_token_expiry(self, mock_TokenType):

        def instantly_expire():
            return timedelta(seconds=-1)

        mock_TokenType.side_effect = instantly_expire

        user = User.objects.create_user(
            username=None,
            email="bob@example.com",
            password="password123")

        token = TokenManager.generate(user, TokenType.LEVEL_ZERO)
        claims = TokenManager.validate(user, token, TokenType.LEVEL_ZERO)
        self.assertFalse(claims)

    def test_token_subject(self):
        pass

    def test_counter(self):
        user = User.objects.create_user(
            username=None,
            email="bob@example.com",
            password="password123")

        self.assertEquals(user.counter(), 0)
        self.assertEquals(user.counter(), 1)
        self.assertEquals(user.counter(), 2)
        self.assertEquals(user.counter(), 3)

    def test_tokens(self):
        user = User.objects.create_user(
            username=None,
            email="bob@example.com",
            password="password123")

        t = user.generate_token(level=0)
        user.validate_token(t, level=0)
