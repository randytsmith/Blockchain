from authservice import views
from django.conf.urls import url

urlpatterns = [
    url(r'^users$', views.user_list),
]
