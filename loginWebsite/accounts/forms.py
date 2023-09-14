from .models import Users, PasswordArchive
from django.forms import ModelForm, CharField, PasswordInput, ValidationError, Form
import re
import argon2

emailPattern = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
# passwordPattern = re.compile(r'[A-Za-z0-9@#$%^&+=]{8,}')
passwordPattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+?-]).{8,}$')

class SignUpForm(ModelForm):
    password2=CharField(widget=PasswordInput, label="Confirm password")
    class Meta:
        model = Users
        fields = ["username", "email", "password","password2"]
        widgets = {
            'password': PasswordInput(),
        }
    def save(self, commit=True):
        user = super(SignUpForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password"])
        passwordarchive = PasswordArchive()
        passwordarchive.user=user
        passwordarchive.password = user.password
        if commit:
            user.save()
            passwordarchive.save()
        return user
    def clean(self):
        super(SignUpForm,self).clean()
        username=self.cleaned_data.get("username")
        email=self.cleaned_data.get("email")
        try:
            user = Users.objects.get(username=username)
        except Users.DoesNotExist:
            pass
        else:
            raise ValidationError("Username already reserved")
        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            pass
        else:
            raise ValidationError("Email address already in use")
        if len(username)<3:
            raise ValidationError("User name too short.")
        if len(username)>30:
            raise ValidationError("User name too long.")

        if not re.fullmatch(emailPattern, email):
            raise ValidationError("Incorect email form.")

        psw1 = self.cleaned_data.get("password")
        psw2 = self.cleaned_data.get("password2")

        if not re.fullmatch(passwordPattern, psw1):
            raise ValidationError("Password needs at least 8 sings including: 1 lower case letter, 1 upper case letter, 1 digit and 1 special sing.")
        if psw1 != psw2:
            raise ValidationError("Passwords are different.")
        return self.cleaned_data

class LoginForm(Form):
    username=CharField(max_length=30,required=True, label='Username')
    password=CharField(max_length=100,required=True, label='Password', widget=PasswordInput)
    class Meta:
        model = Users
        fields = ["username", "password"]
    def clean(self):
        cleaned_data = super().clean()
        log=cleaned_data["username"]
        try:
            user = Users.objects.get(username=log)
        except Users.DoesNotExist:
            raise ValidationError("User doesn't exist.")
        return cleaned_data

class PasswordResetByEmailForm(Form):
    email=CharField(max_length=30, required=True, label='email')

    class Meta:
        model = Users
        fields = ['email']

    def clean(self):
        cleaned_data=super().clean()
        if not re.fullmatch(emailPattern, cleaned_data["email"]):
            raise ValidationError("Incorrect email form.")
        return cleaned_data

class PasswordResetInputForm(Form):
    password = CharField(widget=PasswordInput,label='password')
    password2 = CharField(widget=PasswordInput, label='confirm password')
    class Meta:
        model=Users
        fields=['password','password2']
    def clean(self):
        super(PasswordResetInputForm,self).clean()
        psw1 = self.cleaned_data.get("password")
        psw2 = self.cleaned_data.get("password2")
        if psw1 != psw2:
            raise ValidationError("Passwords are different.")
        if not re.fullmatch(passwordPattern, psw1):
            raise ValidationError("Password needs at least 8 sings including: 1 lower case letter, 1 upper case letter, 1 digit and 1 special sing.")
        return self.cleaned_data

class PasswordAlreadyUsedError(Exception):
    pass
class UserPasswordHistory(Form):
    password = CharField(widget=PasswordInput, label='password')
    password2 = CharField(widget=PasswordInput, label='confirm password')
    class Meta:
        model=PasswordArchive
        fields = ['password', 'password2']


    def __init__(self,user=None, *args,**kwargs):
        super().__init__(*args,**kwargs)
        self.user: Users = user

    def clean(self):
        cleaned_data = super(UserPasswordHistory, self).clean()
        entry = PasswordArchive(user=self.user,password=self.user.password)
        entry.save()
        try:
            query = PasswordArchive.objects.filter(user=self.user)
            if query.count() > 20:
                record = PasswordArchive.objects.earliest('date')
                record.delete()
        except PasswordArchive.DoesNotExist:
            pass
        else:
            ph = argon2.PasswordHasher()
            for element in query:
                try:
                    if ph.verify(element.password[6:],cleaned_data["password"]):
                        raise PasswordAlreadyUsedError
                except argon2.exceptions.VerifyMismatchError:
                    pass
        return cleaned_data