from authservice.serializers import UserSerializer
from authservice.models import User
from authservice.responsemessage import ResponseMessage
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser


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

        token = user.generate_token()
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

        # We only accept what we need
        allowed_keys = {'email', 'token'}
        if set(data.keys()) != allowed_keys:
            return ResponseMessage.INVALID_CREDENTIALS

        # Get the user from the email
        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            return ResponseMessage.INVALID_CREDENTIALS

        # Validate the token matches the user token
        if not user.validate_token(data['token']):
            return ResponseMessage.INVALID_CREDENTIALS

        return JsonResponse({
            'success': True
        }, status=201)

    return ResponseMessage.EMPTY_404
