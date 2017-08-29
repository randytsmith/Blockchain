from django.http import JsonResponse


class ResponseMessage:
    """
    Utility file to handle simple error returns
    """
    INVALID_CREDENTIALS = JsonResponse({
        'success': False,
        'message': 'Invalid Credentials',
    }, status=400)
    EMPTY_404 = JsonResponse({}, status=404)

    def INVALID_MESSAGE(msg):
        return JsonResponse({
            'success': False,
            'message': msg
        }, status=400)
