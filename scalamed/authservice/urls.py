from authservice import views
from django.conf.urls import url

urlpatterns = [
    url(r'^register$', views.register),
    url(r'^users$', views.user_list),
]
