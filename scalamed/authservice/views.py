from authservice.serializers import UserSerializer
from authservice.models import User
from django.contrib.auth import authenticate
from django.http import (
    HttpResponseBadRequest,
    JsonResponse)
from django.views.decorators.csrf import csrf_exempt
from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser

import jwt


@csrf_exempt
def user_list(request):
    """List all users, or create a new user."""

    if request.method == 'GET':
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return JsonResponse(serializer.data, safe=False)

    return JsonResponse({}, status=404)


@csrf_exempt
def register(request):
    """Register a new user into the system."""

    if request.method == 'PUT':
        try:
            data = JSONParser().parse(request)
        except ParseError as e:
            return HttpResponseBadRequest(str(e))

        x = set(data.keys()) - {'email', 'password'}
        if len(x):
            # TODO better words
            return HttpResponseBadRequest('you had extra fields')

        # data['uuid'] = User.generate_uuid()

        serializer = UserSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status=201)
        return HttpResponseBadRequest(str(serializer.errors))

    return JsonResponse({}, status=404)


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
            return HttpResponseBadRequest(str(e))

        email = data['email']
        password = data['password']

        user = authenticate(username=email, password=password)

        if user == None:
            return HttpResponseBadRequest("incorrect buddy")

        l0 = jwt.encode({'level': 0}, 'secret', algorithm='HS256')
        l1 = jwt.encode({'level': 1}, 'secret', algorithm='HS256')

        return JsonResponse({
            'token_level_0': l0.decode('ascii'),
            'token_level_1': l1.decode('ascii'),
            'uuid': user.uuid,
        }, status=200)

    return JsonResponse({}, status=404)
