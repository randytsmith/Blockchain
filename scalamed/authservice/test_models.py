from authservice.models import User, TokenManager, TokenType
from datetime import timedelta
from django.test import TestCase
from scalamed.logging import log
from unittest import mock


class UserTestCase(TestCase):
    def setUp(self):
        log.setLevel(100)

        self.user = User.objects.create_user(
            username=None,
            email="bob@example.com",
            password="password123")

    def tearDown(self):
        log.setLevel(30)

    def test_create_user(self):
        """Test create_user creates a user with working defaults."""

        user = self.user
        self.assertFalse(hasattr(user, 'username'))
        self.assertEqual(user.email, "bob@example.com")
        self.assertNotEqual(user.password, "password123")
        self.assertIsNotNone(user.uuid)
        self.assertEqual(len(user.uuid), 36)
        self.assertEqual(user.role, User.Role.PATIENT)

    def test_counter(self):
        user = self.user
        self.assertEquals(user.counter(), 0)
        self.assertEquals(user.counter(), 1)
        self.assertEquals(user.counter(), 2)
        self.assertEquals(user.counter(), 3)

    def test_TokenManager_generate(self):
        """Test the generation and validation of tokens"""
        user = self.user
        for kind in list(TokenType):
            token = TokenManager.generate(user, kind)
            self.assertTrue(TokenManager.validate(user, token, kind))

    @mock.patch('authservice.models.TokenType.ttl')
    def test_TokenManager_token_expires(self, mock_TokenType):

        def instantly_expire():
            return timedelta(seconds=-1)

        mock_TokenType.side_effect = instantly_expire

        user = self.user
        token = TokenManager.generate(user, TokenType.LEVEL_ZERO)
        claims = TokenManager.validate(user, token, TokenType.LEVEL_ZERO)
        self.assertFalse(claims)

    def test_TokenManager_generate_weird_kind(self):

        with self.assertRaises(ValueError):
            TokenManager.generate(self.user, TokenType(400))

        with self.assertRaises(Exception):
            TokenManager.generate(self.user, 400)
