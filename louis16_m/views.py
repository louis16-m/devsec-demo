from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib import messages

def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, 'Account created successfully! You can now log in.')
            return redirect('louis16_m:login')
    else:
        form = UserCreationForm()
    return render(request, 'louis16_m/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f'Welcome back, {user.username}!')
            return redirect('louis16_m:profile')
    else:
        form = AuthenticationForm()
    return render(request, 'louis16_m/login.html', {'form': form})

def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('louis16_m:login')

@login_required
def password_change_view(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Keep user logged in
            messages.success(request, 'Your password was successfully updated!')
            return redirect('louis16_m:password_change_done')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'louis16_m/password_change.html', {'form': form})

@login_required
def password_change_done_view(request):
    return render(request, 'louis16_m/password_change_done.html')

@login_required
def profile_view(request):
    return render(request, 'louis16_m/profile.html')