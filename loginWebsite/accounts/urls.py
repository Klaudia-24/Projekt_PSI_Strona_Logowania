from django.urls import path, re_path

from .views import SignUpView, LoginPage, LogOut, passwordResetLinkSent, passwordResetConfirm, resetPasswordDone, ResetPasswordByEmail


urlpatterns = [
    path("signup/", SignUpView, name="signup"),
    path("login/", LoginPage, name='login'),
    path("logout/",LogOut,name="logout"),
    path("passwordResetLinkSent/",passwordResetLinkSent,name="passwordResetLinkSent"),
    re_path(r'^resetPasswordConfirm/(?P<uidb64>[0-9A-Za-z]+)/(?P<token>.+)',passwordResetConfirm, name='passwordResetConfirm'),
    path("resetPasswordDone/",resetPasswordDone,name="resetPasswordDone"),
    path("ResetPasswordByEmail/",ResetPasswordByEmail,name="ResetPasswordByEmail")
]