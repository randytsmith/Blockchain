from authservice.serializers import UserSerializer
from authservice.models import User
from django.http import (
    HttpResponseBadRequest,
    JsonResponse)
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

    return JsonResponse({}, status=404)


@csrf_exempt
def register(request):
    """Register a new user into the system."""

    if request.method == 'PUT':
        try:
            data = JSONParser().parse(request)
        except ParseError as e:
            return HttpResponseBadRequest(str(e))

        serializer = UserSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status=201)
        return HttpResponseBadRequest(str(serializer.errors))

    return JsonResponse({}, status=404)
