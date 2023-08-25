from .models import Users
from django.contrib.auth.backends import BaseBackend
from django.core.exceptions import PermissionDenied

class UserAuthBackend(BaseBackend):
    def authenticate(self,request, username=None,password=None, **kwargs):
        try:
            user = Users.objects.get(username=username)
            if user.check_password(password):
                return user
            raise PermissionDenied()
        except Users.DoesNotExist:
            return None

    def get_user(self,user_id):
        try:
            return Users.objects.get(pk=user_id)
        except Users.DoesNotExist:
            return None