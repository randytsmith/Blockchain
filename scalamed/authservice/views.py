from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from authservice.serializers import UserSerializer
from authservice.models import User


@csrf_exempt
def user_list(request):
    """List all users, or create a new user."""

    if request.method == 'GET':
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return JsonResponse(serializer.data, safe=False)

    elif request.method == 'POST':
        data = JSONParser().parse(request)
        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status=201)
        return JsonResponse(serializer.errors, status=400)

    return JsonResponse({}, status=404)


@csrf_exempt
def register(request):
    """Register a new user into the system."""

    if request.method == 'PUT':
        return 0

    return JsonResponse({}, status=404)
