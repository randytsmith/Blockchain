from authservice.serializers import UserSerializer
from authservice.models import User
from authservice.responsemessage import ResponseMessage
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser
from rest_framework.views import APIView
from scalamed.logging import log, logroute


@csrf_exempt
@logroute(decoder='json')
def user_list(request):
    """List all users, or create a new user."""
    if request.method == 'GET':
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return JsonResponse(serializer.data, safe=False)

    return ResponseMessage.EMPTY_404


@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(APIView):

    parser_classes = (JSONParser, )

    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def put(self, request):
        """Register a new user into the system."""

        data = request.data

        x = set(data.keys()) - {'email', 'password'}
        if len(x):
            log.error("Extra fields present.")
            return ResponseMessage.INVALID_MESSAGE("Extra fields present.")

        serializer = UserSerializer(data=data)

        if not serializer.is_valid():
            log.warning("{} => {}".format(
                "User data was deemed invalid by UserSerializer",
                str(serializer.errors),
                data))
            return ResponseMessage.INVALID_MESSAGE(str(serializer.errors))

        user = User.objects.create_user(
            username=None,
            email=serializer.data['email'],
            password=serializer.data['password'])
        log.info("User has been registered: {}".format(user))
        return JsonResponse(
            {
                'email': user.email,
                'uuid': user.uuid
            }, status=201)


@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):

    parser_classes = (JSONParser, )

    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def post(self, request):
        """
        Login a new user, expecting their e-mail and password as the
        credentials.  We return them a fresh token_level_0, token_level_1, and
        the UUID of the user.
        """
        x = set(request.data.keys()) - {'email', 'password'}
        if len(x):
            log.error("Extra fields present.")
            return ResponseMessage.INVALID_MESSAGE("Extra fields present.")

        email = request.data['email']
        password = request.data['password']

        user = authenticate(username=email, password=password)

        if user is None:
            return ResponseMessage.INVALID_CREDENTIALS

        l0 = user.generate_token(level=0)
        l1 = user.generate_token(level=1)

        return JsonResponse({
            'token_level_0': l0.decode('ascii'),
            'token_level_1': l1.decode('ascii'),
            'uuid': user.uuid,
        }, status=200)


@csrf_exempt
def logout(request):
    """
    Invalidate the current user session.
    """

    if request.method == 'POST':
        try:
            data = JSONParser().parse(request)
        except ParseError as e:
            log.debug("Failed to parse JSON: {}".format(str(e)))
            return ResponseMessage.INVALID_MESSAGE("")

        l0 = data['token_level_0']
        l1 = data['token_level_1']
        uuid = data['uuid']

        try:
            user = User.objects.get(uuid=uuid)
        except User.DoesNotExist:
            log.debug("User does not exist: uuid={}".format(uuid))
            return ResponseMessage.INVALID_CREDENTIALS

        # Verify the tokens are valid.
        if not user.validate_token(l0, level=0):
            return ResponseMessage.INVALID_CREDENTIALS

        if not user.validate_token(l1, level=1):
            return ResponseMessage.INVALID_CREDENTIALS

        user.delete_token(l0)
        user.delete_token(l1)

        return JsonResponse({'success': True}, status=200)

    return ResponseMessage.EMPTY_404


@csrf_exempt
@logroute(decoder='json')
def check(request, actiontype=None):
    """
    Checks if the given token is valid, expecting their uuid, token_level_1,
    token_level_0.  Optional: Checks if the given user is permitted to perform
    the action.  We return them a fresh token_level_1 on success.
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
        if not user.validate_token(l0, level=0):
            return ResponseMessage.INVALID_CREDENTIALS

        if not user.validate_token(l1, level=1):
            return ResponseMessage.INVALID_CREDENTIALS

        # Finally check the action type
        if actiontype:
            if actiontype == 'prescription':
                if user.role != User.Role.DOCTOR:
                    return ResponseMessage.INVALID_CREDENTIALS
            elif actiontype == 'fulfil':
                if user.role != User.Role.PHARMACIST:
                    return ResponseMessage.INVALID_CREDENTIALS

        if not user.delete_token(l1, level=1):
            log.warning("Could not delete token: {}".format(l1))

        # Refresh with the new token
        new_l1 = user.generate_token(level=1)

        return JsonResponse({
            'success': True,
            'token_level_1': new_l1.decode('ascii'),
        }, status=200)

    return ResponseMessage.EMPTY_404


@csrf_exempt
@logroute(decoder='json')
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
        if not user.validate_token(l0, level=0):
            return ResponseMessage.INVALID_CREDENTIALS

        if not user.validate_token(l1, level=1):
            return ResponseMessage.INVALID_CREDENTIALS

        # TODO invalidate token_1, make a renew function for this?

        # Refresh with the new token
        new_l1 = user.generate_token(level=1)

        return JsonResponse({
            'token_level_1': new_l1.decode('ascii'),
            'secret': user.secret,
        }, status=200)

    return ResponseMessage.EMPTY_404


@csrf_exempt
@logroute(decoder='json')
def forgot_password(request):
    """
    Request a reset password link to be sent to the users email.
    Expecting: email
    Returns: success
    """

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
@logroute(decoder='json')
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
