from .forms import SignUpForm, LoginForm, PasswordResetByEmailForm, PasswordResetInputForm, UserPasswordHistory, \
    PasswordAlreadyUsedError
from django.shortcuts import render, redirect
from .models import Users, BlockedUser, Logs, Activity
from django.utils.http import urlsafe_base64_decode
from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
def SignUpView(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        form=SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('home')
        else:
            context = {
                'form': form,
            }
    else:
        context = {
            'form': SignUpForm(),
        }
    return render(request ,'registration/signup.html',context)

def LoginPage(request):
    if request.user.is_authenticated:
        return redirect('home')
    form = LoginForm()
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            try:
                user = Users.objects.get(username=form.cleaned_data["username"])
                blockedUser = BlockedUser.objects.get(user=user)
            except Users.DoesNotExist:
                messages.error(request, "User doesnt exist")
                return render(request,'registration/login.html', {'form': form})
            except BlockedUser.DoesNotExist:
                pass
            else:
                if blockedUser.time + timedelta(minutes=1) > timezone.now():
                    messages.error(request, "User is blocked temporarily, try again later")
                    return render(request, 'login.html', {'form': form})
                else:
                    blockedUser.delete()
            if user.password_change_date < timezone.now():
                messages.error(request, "Password expired use forgot password to reset password")
                return render(request, 'registration/login.html', {'form':form})
            user: Users = authenticate(request, username=form.cleaned_data["username"],
                                       password=form.cleaned_data["password"])
            if user is not None:
                user.counter = 0
                user.save()
                login(request, user)
                log = Logs(activity=Activity.objects.get(activityName="Logged In"), user=user)
                log.save()
                if user.password_change_date - timedelta(days=5) < timezone.now():
                    wynik = user.password_change_date - timezone.now()
                    messages.error(request,
                                   f"Zresetuj swoje hasło, bedzie wazne jeszcze przez {wynik.days} dni {wynik.seconds // 3600} godziny")
                return redirect('home')
            else:
                user: Users = Users.objects.get(username=form.cleaned_data["username"])
                user.counter += 1
                log = Logs(activity=Activity.objects.get(activityName="Loggin Failed"), user=user)
                log.save()
                if user.counter > 3:
                    user.counter = 0
                    blocked = BlockedUser(user=user)
                    blocked.save()
                    log = Logs(activity=Activity.objects.get(activityName="User Blocked"), user=user)
                    log.save()
                user.save()
                messages.error(request, "Incorrect password or username")
        else:
            return render(request, 'registration/login.html', {'form': form})
    return render(request, 'registration/login.html', {'form': form})

@login_required
def LogOut(request):
    log = Logs(activity=Activity.objects.get(activityName="Logged Out"), user=request.user)
    log.save()
    logout(request)
    return redirect('home')

def ResetPasswordByEmail(request):
    if request.user.is_authenticated:
        return redirect('loggedPasswordReset')
    if request.method == "POST":
        form=PasswordResetByEmailForm(request.POST)
        if form.is_valid():
            try:
                user=Users.objects.get(email=form.cleaned_data["email"])
                user.sendPasswordResetLink()
                log = Logs(activity=Activity.objects.get(activityName="Reset Link Request"), user=user)
                log.save()
            except Users.DoesNotExist:
                pass
            except Exception as e:
                messages.error(request, "Error while sending email.")
            else:
                return redirect('passwordResetLinkSent')
    return render(request,'registration/password_reset_form.html', {'form': PasswordResetByEmailForm()})

def passwordResetLinkSent(request):
    return render(request, 'registration/password_reset_done.html', {})

def passwordResetConfirm(request,uidb64=None,token=None,*args, **kwargs):
    if request.user.is_authenticated:
        user=request.user
        tokenFlag=True
    else:
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = Users.objects.get(pk=uid)
            tokenFlag=default_token_generator.check_token(user, token)
        except (TypeError, ValueError, OverflowError, Users.DoesNotExist):
            user = None
            tokenFlag=None
    form = None
    if request.method=='POST':
        form=PasswordResetInputForm(request.POST)
        form2=UserPasswordHistory(user,request.POST)
        if form.is_valid():
            try:
                if form2.is_valid():
                    if user is not None and tokenFlag:
                            user.set_password(form.cleaned_data['password'])
                            user.password_change_date=timezone.now()+timedelta(days=30)
                            user.save()
                            log = Logs(activity=Activity.objects.get(activityName="Password Reset"), user=user)
                            log.save()
                            return redirect('resetPasswordDone')
                    else:
                        if tokenFlag is not None:
                            messages.error(request, 'Your password has not been modified, token expired')
            except PasswordAlreadyUsedError:
                messages.error(request, 'Your password has already been used. Choose a different one.')
    return render(request,'registration/password_reset_confirm.html',  {'form': form if form is not None else PasswordResetInputForm(), 'validlink': True})

def resetPasswordDone(request):
    return render(request, 'registration/password_reset_complete.html', {})