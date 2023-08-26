
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser,BaseUserManager,EmptyManager
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from sendgrid import Content
from datetime import timedelta
from django.utils.http import urlsafe_base64_encode
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail,To,Email
import argon2

SENDGRID_API_KEY="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"
DOMAIN = "127.0.0.1:8000"

class UserMenager(BaseUserManager):
    def create_user(self, password=None):
        user = self.model()

        user.set_password(password)
        user.save(using=self._db)
        user.counter=0
        return user

    def create_superuser(self, password):
        user = self.create_user(password=password)
        user.is_admin = True
        user.save(using=self._db)
        return user

class Users(AbstractUser):
    username=models.CharField(max_length=30, unique=True)
    email = models.CharField(max_length=100, unique=True)
    counter=models.IntegerField(default=0)
    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['email']
    is_active = models.BooleanField(default=True)
    password_change_date=models.DateTimeField(default=timezone.now()+timedelta(days=30))

    objects = UserMenager()
    def check_password(self, raw_password):
        ph = argon2.PasswordHasher()
        try:
            if ph.verify(self.password[6:],raw_password):
                if ph.check_needs_rehash(self.password[6:]):
                    self.set_password(raw_password)
                    self.save()
                return True
        except argon2.exceptions.VerificationError:
            return False
        return False

    def sendPasswordResetLink(self):
        uid = urlsafe_base64_encode(force_bytes(self.pk))
        token = default_token_generator.make_token(self)
        to_email = To(self.email)
        from_email = Email("psiproject@o2.pl")
        subject = "Password Recovery from website"
        content = Content("text/plain", f"You are receiving this email because of your reset password request.\n"
                                        f"Please go to this page and choose a new password:\n"
                                        f"http://{DOMAIN}/accounts/resetPasswordConfirm/{uid}/{token}")
        print(content.get())
        message = Mail(from_email, to_email, subject, content)
        sg = SendGridAPIClient(api_key=SENDGRID_API_KEY)
        sg.client.mail.send.post(request_body=message.get())

class Activity(models.Model):
    activityName=models.CharField(max_length=50)
    objects=models.Manager()

class BlockedUser(models.Model):
    user=models.ForeignKey(Users,on_delete=models.CASCADE)
    time=models.DateTimeField(default=timezone.now)

    objects=models.Manager()

class Logs(models.Model):
    user=models.ForeignKey(Users,on_delete=models.CASCADE, related_name='logs')
    time=models.DateTimeField(default=timezone.now)
    acivity=models.ForeignKey(Activity,on_delete=models.PROTECT)

class PasswordArchive(models.Model):
    user=models.ForeignKey(Users,on_delete=models.CASCADE)
    password = models.CharField(max_length=300)
    date = models.DateTimeField(default=timezone.now)
    USERNAME_FIELD='user'
    objects = models.Manager()
