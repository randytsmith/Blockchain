from authservice import views
from django.conf.urls import url

urlpatterns = [
    url(r'^register$', views.register),
    url(r'^login$', views.login),
    url(r'^users$', views.user_list),
    url(r'^check$', views.check),
    url(r'^check/(?P<actiontype>(prescription|fulfil))$', views.check),
    url(r'^getsecret$', views.get_secret),
    url(r'^forgotpw$', views.forgot_password),
    url(r'^resetpw$', views.reset_password),
]
