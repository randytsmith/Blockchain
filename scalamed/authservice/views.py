from authservice.serializers import UserSerializer
from authservice.models import User
from authservice.responsemessage import ResponseMessage
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from rest_framework.views import APIView
from scalamed.logging import log, logroute


def request_must_have(expected, required):
    if not isinstance(expected, set):
        expected = set(expected)

    if expected == required:
        return True

    messages = []

    extra = expected - required
    if extra:
        messages.append("Extra fields were found: {}".format(extra))

    missing = required - expected
    if missing:
        messages.append("Fields were missing: {}".format(missing))

    log.info("Errors in request: {}".format(messages))
    return False


def request_fields(fields):
    def decorator(functor):
        def caller(self, request, *args, **kwargs):
            if not request_must_have(request.data.keys(), fields):
                return ResponseMessage.INVALID_MESSAGE("Fields missing")
            else:
                return functor(self, request, *args, **kwargs)
        return caller
    return decorator


@csrf_exempt
@logroute(decoder='json')
def user_list(request):
    """List all users, or create a new user."""
    if request.method == 'GET':
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return JsonResponse(serializer.data, safe=False)

    return ResponseMessage.NOT_FOUND


@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(APIView):

    parser_classes = (JSONParser, )

    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    @request_fields({'email', 'password'})
    def put(self, request):
        """Register a new user into the system."""

        serializer = UserSerializer(data=request.data)

        if not serializer.is_valid():
            log.warning("{} => {}".format(
                "User data was deemed invalid by UserSerializer",
                str(serializer.errors),
                request.data))
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

    @request_fields({'email', 'password'})
    def post(self, request):
        """
        Login a new user, expecting their e-mail and password as the
        credentials.  We return them a fresh token_level_0, token_level_1, and
        the UUID of the user.
        """
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


@method_decorator(csrf_exempt, name='dispatch')
class LogoutView(APIView):

    parser_classes = (JSONParser, )

    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    @request_fields({'token_level_0', 'token_level_1', 'uuid'})
    def post(self, request):
        """Invalidate the current user session."""

        l0 = request.data['token_level_0']
        l1 = request.data['token_level_1']
        uuid = request.data['uuid']

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

        user.delete_token(l0, level=0)
        user.delete_token(l1, level=1)

        return JsonResponse({'success': True}, status=200)


@method_decorator(csrf_exempt, name='dispatch')
class CheckView(APIView):

    parser_classes = (JSONParser, )

    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    @request_fields({'token_level_0', 'token_level_1', 'uuid'})
    def post(self, request, actiontype=None):
        """
        Checks if the given token is valid, expecting their uuid, token_level_1,
        token_level_0.  Optional: Checks if the given user is permitted to
        perform the action.  We return them a fresh token_level_1 on success.
        """
        l0 = request.data['token_level_0']
        l1 = request.data['token_level_1']
        uuid = request.data['uuid']

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
                    return ResponseMessage.FORBIDDEN('User cannot prescribe')
            elif actiontype == 'fulfil':
                if user.role != User.Role.PHARMACIST:
                    return ResponseMessage.FORBIDDEN('User cannot fulfill')

        if not user.delete_token(l1, level=1):
            log.warning("Could not delete token: {}".format(l1))

        # Refresh with the new token
        new_l1 = user.generate_token(level=1)

        return JsonResponse({
            'success': True,
            'token_level_1': new_l1.decode('ascii'),
        }, status=200)


@method_decorator(csrf_exempt, name='dispatch')
class GetSecretView(APIView):

    parser_classes = (JSONParser, )

    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    @request_fields({'token_level_0', 'token_level_1', 'uuid'})
    def post(self, request):
        """
        Checks the user tokens, if valid returns the user secret for row
        encryption.  Expecting token_level_0, token_level_1, uuid.  Returns new
        token_level_0 and the secret.
        """
        l0 = request.data['token_level_0']
        l1 = request.data['token_level_1']
        uuid = request.data['uuid']

        # Verify the user id
        try:
            user = User.objects.get(uuid=uuid)
        except User.DoesNotExist as e:
            log.debug(
                "User does not exist, looked for uuid={}: {}"
                .format(uuid, str(e)))
            return ResponseMessage.INVALID_CREDENTIALS

        # Verify the tokens are valid.
        if not user.validate_token(l0, level=0):
            log.debug(
                "Invalid token_level_0 for user={} was detected: {}"
                .format(user, l0))
            return ResponseMessage.INVALID_CREDENTIALS

        if not user.validate_token(l1, level=1):
            log.debug(
                "Invalid token_level_1 for user={} was detected: {}"
                .format(user, l0))
            return ResponseMessage.INVALID_CREDENTIALS

        # Refresh with the new token
        new_l1 = user.generate_token(level=1)

        return JsonResponse({
            'token_level_1': new_l1.decode('ascii'),
            'secret': user.secret,
        }, status=200)


@method_decorator(csrf_exempt, name='dispatch')
class ForgotPasswordView(APIView):

    parser_classes = (JSONParser, )

    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    @request_fields({'email'})
    def post(self, request):
        """
        Request a reset password link to be sent to the users email.
        Expecting: email
        Returns: success
        """
        try:
            user = User.objects.get(email=request.data['email'])
        except User.DoesNotExist:
            return ResponseMessage.INVALID_CREDENTIALS

        token = user.generate_token()
        return JsonResponse({
            "token": token.decode('utf8')
        }, status=200)


@method_decorator(csrf_exempt, name='dispatch')
class ResetPasswordView(APIView):

    parser_classes = (JSONParser, )

    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    @request_fields({'email', 'token'})
    def post(self, request):
        """
        Peforms the password reset.
        Expecting:
            GET: email, token
            DATA: password
        Returns: Success
        """
        # Get the user from the email
        try:
            user = User.objects.get(email=request.data['email'])
        except User.DoesNotExist:
            return ResponseMessage.INVALID_CREDENTIALS

        # Validate the token matches the user token
        if not user.validate_token(request.data['token']):
            return ResponseMessage.INVALID_CREDENTIALS

        return JsonResponse({'success': True}, status=201)
