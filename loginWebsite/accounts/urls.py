from django.urls import path

from .views import SignUpView, LoginPage, LogOut


urlpatterns = [
    path("signup/", SignUpView, name="signup"),
    path("login/", LoginPage, name='login'),
    path("logout/",LogOut,name="logout")
]