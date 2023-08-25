from .forms import SignUpForm
from django.shortcuts import render, redirect
def SignUpView(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        form=SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('index')
        else:
            context = {
                'form': form,
            }
    else:
        context = {
            'form': SignUpForm(),
        }
    return render(request ,'registration/signup.html',context)