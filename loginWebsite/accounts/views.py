from .forms import SignUpForm, LoginForm
from django.shortcuts import render, redirect
from .models import Users, BlockedUser, Logs, Activity
from django.contrib import messages
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
                log = Logs(acivity=Activity.objects.get(activityName="Logged In"), user=user)
                log.save()
                if user.password_change_date - timedelta(days=5) < timezone.now():
                    wynik = user.password_change_date - timezone.now()
                    messages.error(request,
                                   f"Zresetuj swoje hasło, bedzie wazne jeszcze przez {wynik.days} dni {wynik.seconds // 3600} godziny")
                return redirect('home')
            else:
                user: Users = Users.objects.get(username=form.cleaned_data["username"])
                user.counter += 1
                log = Logs(acivity=Activity.objects.get(activityName="Loggin Failed"), user=user)
                log.save()
                if user.counter > 3:
                    user.counter = 0
                    blocked = BlockedUser(user=user)
                    blocked.save()
                    log = Logs(acivity=Activity.objects.get(activityName="User Blocked"), user=user)
                    log.save()
                user.save()
                messages.error(request, "Incorrect password or username")
        else:
            return render(request, 'registration/login.html', {'form': form})
    return render(request, 'registration/login.html', {'form': form})

@login_required
def LogOut(request):
    log = Logs(acivity=Activity.objects.get(activityName="Logged Out"), user=request.user)
    log.save()
    logout(request)
    return redirect('home')