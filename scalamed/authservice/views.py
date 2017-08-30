from authservice.serializers import UserSerializer
from authservice.models import User
from authservice.responsemessage import ResponseMessage
from binascii import hexlify
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from jwt import PyJWT, InvalidTokenError, MissingRequiredClaimError
from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser
from secrets import token_bytes
import struct


jwt = PyJWT(options={'require_exp': True, 'require_iat': True, })

counter = 0


def generate_token(email, counter):
    now = datetime.utcnow()
    ttl = timedelta(minutes=10)

    nonce = hexlify(token_bytes(16) + struct.pack(">Q", counter))
    claims = {

        # These claims are validated by PyJWT
        'exp': now + ttl,
        'iat': now,

        # These claims we have to validate ourselves
        'sub': email,
        'jti': nonce.decode('utf8'),
    }
    return jwt.encode(claims, settings.SECRET_KEY)


def validate_token(token):
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


@csrf_exempt
def user_list(request):
    """List all users, or create a new user."""

    if request.method == 'GET':
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return JsonResponse(serializer.data, safe=False)

    return ResponseMessage.EMPTY_404


@csrf_exempt
def register(request):
    """Register a new user into the system."""

    if request.method == 'PUT':
        try:
            data = JSONParser().parse(request)
        except ParseError as e:
            return ResponseMessage.INVALID_MESSAGE(str(e))

        x = set(data.keys()) - {'email', 'password'}
        if len(x):
            # TODO better words
            return ResponseMessage.INVALID_MESSAGE("Extra fields present")

        serializer = UserSerializer(data=data)

        if serializer.is_valid():
            user = User.objects.create_user(
                username=None,
                email=serializer.data['email'],
                password=serializer.data['password'])
            return JsonResponse({'email': user.email}, status=201)
        return ResponseMessage.INVALID_MESSAGE(str(serializer.errors))

    return ResponseMessage.EMPTY_404


@csrf_exempt
def login(request):
    """
    Login a new user, expecting their e-mail and password as the credentials.
    We return them a fresh token_level_0, token_level_1, and the UUID of the
    user.
    """

    if request.method == 'POST':
        try:
            data = JSONParser().parse(request)
        except ParseError as e:
            return ResponseMessage.INVALID_MESSAGE(str(e))

        email = data['email']
        password = data['password']

        user = authenticate(username=email, password=password)

        if user == None:
            return ResponseMessage.INVALID_CREDENTIALS

        l0 = user.generate_token_level_0()
        l1 = user.generate_token_level_1()

        return JsonResponse({
            'token_level_0': l0.decode('ascii'),
            'token_level_1': l1.decode('ascii'),
            'uuid': user.uuid,
        }, status=200)

    return ResponseMessage.EMPTY_404


@csrf_exempt
def check(request, actiontype=None):
    """
    Checks if the given token is valid, expecting their uuid, token_level_1, token_level_0.
    Optional: Checks if the given user is permitted to perform the action.
    We return them a fresh token_level_1 on success.
    """

    if request.method == 'POST':

        try:
            data = JSONParser().parse(request)
        except ParseError as e:
            return ResponseMessage.INVALID_MESSAGE(str(e))

        allowed_keys = {'token_level_0', 'token_level_1', 'uuid'}

        if set(data.keys()) != allowed_keys:
            return ResponseMessage.INVALID_CREDENTIALS

        l0 = data['token_level_0']
        l1 = data['token_level_1']
        uuid = data['uuid']

        # Verify the user id
        try:
            user = User.objects.get(uuid=uuid)
        except User.DoesNotExist:
            return ResponseMessage.INVALID_CREDENTIALS

        # Verify the tokens are valid.
        try:
            user.verify_token_level_0(l0)
            user.verify_token_level_1(l1)
        except jwt.InvalidTokenError:
            return ResponseMessage.INVALID_CREDENTIALS

        # Finally check the action type
        if actiontype:
            if actiontype == 'prescription':
                if user.role != User.Role.DOCTOR:
                    return ResponseMessage.INVALID_CREDENTIALS
            elif actiontype == 'fulfil':
                if user.role != User.Role.PHARMACIST:
                    return ResponseMessage.INVALID_CREDENTIALS

        # Refresh with the new token
        new_l1 = user.generate_token_level_1()

        return JsonResponse({
            'success': True,
            'token_level_1': new_l1.decode('ascii'),
        }, status=200)

    return ResponseMessage.EMPTY_404


@csrf_exempt
def get_secret(request):
    """
    Checks the user tokens, if valid returns the user secret for row encryption.
    Expecting token_level_0, token_level_1, uuid.
    Returns new token_level_0 and the secret.
    """

    if request.method == 'POST':

        try:
            data = JSONParser().parse(request)
        except ParseError as e:
            return ResponseMessage.INVALID_MESSAGE(str(e))

        allowed_keys = {'token_level_0', 'token_level_1', 'uuid'}

        if set(data.keys()) != allowed_keys:
            return ResponseMessage.INVALID_CREDENTIALS

        l0 = data['token_level_0']
        l1 = data['token_level_1']
        uuid = data['uuid']

        # Verify the user id
        try:
            user = User.objects.get(uuid=uuid)
        except User.DoesNotExist:
            return ResponseMessage.INVALID_CREDENTIALS

        # Verify the tokens are valid.
        try:
            user.verify_token_level_0(l0)
            user.verify_token_level_1(l1)
        except jwt.InvalidTokenError:
            return ResponseMessage.INVALID_CREDENTIALS

        # Refresh with the new token
        new_l1 = user.generate_token_level_1()

        return JsonResponse({
            'token_level_1': new_l1.decode('ascii'),
            'secret': user.secret,
        }, status=200)

    return ResponseMessage.EMPTY_404


@csrf_exempt
def forgot_password(request):
    """
    Request a reset password link to be sent to the users email.
    Expecting: email
    Returns: success
    """
    global counter

    if request.method == 'POST':

        try:
            data = JSONParser().parse(request)
        except ParseError as e:
            return ResponseMessage.INVALID_MESSAGE(str(e))

        allowed_keys = {'email'}

        if set(data.keys()) != allowed_keys:
            return ResponseMessage.INVALID_CREDENTIALS

        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            return ResponseMessage.INVALID_CREDENTIALS

        token = generate_token(user.email, counter)
        return JsonResponse({
            "token": token.decode('utf8')
        }, status=200)
    return ResponseMessage.EMPTY_404


@csrf_exempt
def reset_password(request):
    """
    Peforms the password reset.
    Expecting:
        GET: email, token
        DATA: password
    Returns: Success
    """

    if request.method == 'POST':
        try:
            data = JSONParser().parse(request)
        except ParseError as e:
            return ResponseMessage.INVALID_MESSAGE(str(e))

        allowed_keys = {'email', 'token'}

        if set(data.keys()) != allowed_keys:
            return ResponseMessage.INVALID_CREDENTIALS

        token = data['token']

        if not validate_token(token):
            return ResponseMessage.INVALID_CREDENTIALS

        try:
            User.objects.get(email=data['email'])

            # TODO match email from token to email in POST data

            return JsonResponse({
                'success': True
            }, status=201)

        except User.DoesNotExist:
            return ResponseMessage.INVALID_CREDENTIALS

        return ResponseMessage.INVALID_CREDENTIALS

    return ResponseMessage.EMPTY_404
