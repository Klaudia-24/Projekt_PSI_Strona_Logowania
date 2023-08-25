from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from .models import Users, PasswordArchive
from django.forms import ModelForm, CharField, PasswordInput, ValidationError, Form
import re
import argon2

emailPattern = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
passwordPattern = re.compile(r'[A-Za-z0-9@#$%^&+=]{8,}')

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
        print(user)
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
        if len(username)<3:
            raise ValidationError("User name too short.")
        if len(username)>30:
            raise ValidationError("User name too long.")

        if not re.fullmatch(emailPattern, email):
            raise ValidationError("Incorect email form.")

        psw1 = self.cleaned_data.get("password")
        psw2 = self.cleaned_data.get("password2")

        if not re.fullmatch(passwordPattern, psw1):
            raise ValidationError("Password needs at least 8 sings")
        if psw1 != psw2:
            raise ValidationError("Passwords are different.")
        return self.cleaned_data