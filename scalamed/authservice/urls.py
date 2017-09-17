from authservice import views
from django.conf.urls import url


urlpatterns = [
    url(r'^register$', views.RegisterView.as_view()),
    url(r'^login$', views.LoginView.as_view()),
    url(r'^logout$', views.LogoutView.as_view()),
    url(r'^check$', views.CheckView.as_view()),
    url(r'^users$', views.user_list),
    url(r'^check/(?P<actiontype>(prescription|fulfil))$',
        views.CheckView.as_view()),
    url(r'^getsecret$', views.get_secret),
    url(r'^forgotpw$', views.forgot_password),
    url(r'^resetpw$', views.reset_password),
]
