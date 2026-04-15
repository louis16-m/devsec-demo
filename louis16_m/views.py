from functools import wraps

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, User
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib import messages
from django.core.exceptions import PermissionDenied

ROLE_STANDARD = 'standard'
ROLE_PRIVILEGED = 'privileged'


def ensure_role_groups():
    standard_group, _ = Group.objects.get_or_create(name=ROLE_STANDARD)
    privileged_group, _ = Group.objects.get_or_create(name=ROLE_PRIVILEGED)
    return standard_group, privileged_group


def is_privileged(user):
    return user.is_authenticated and (
        user.is_staff or user.groups.filter(name=ROLE_PRIVILEGED).exists()
    )


def privileged_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('louis16_m:login')
        if not is_privileged(request.user):
            raise PermissionDenied
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            standard_group, _ = ensure_role_groups()
            user.groups.add(standard_group)
            messages.success(request, 'Account created successfully! You can now log in.')
            return redirect('louis16_m:login')
    else:
        form = UserCreationForm()
    return render(request, 'louis16_m/register.html', {'form': form})


def login_view(request):
    next_url = request.POST.get('next') or request.GET.get('next') or ''
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f'Welcome back, {user.username}!')
            return redirect(next_url or 'louis16_m:profile')
    else:
        form = AuthenticationForm()
    return render(request, 'louis16_m/login.html', {'form': form, 'next': next_url})


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


@privileged_required
def privileged_dashboard_view(request):
    return render(request, 'louis16_m/privileged_dashboard.html')


@login_required
def profile_view(request):
    has_privileged_access = is_privileged(request.user)
    return render(request, 'louis16_m/profile.html', {
        'target_user': request.user,
        'has_privileged_access': has_privileged_access,
        'is_own_profile': True,
    })


@login_required
def profile_detail_view(request, user_id):
    target_user = get_object_or_404(User, pk=user_id)
    if request.user != target_user and not is_privileged(request.user):
        raise PermissionDenied
    has_privileged_access = is_privileged(request.user)
    return render(request, 'louis16_m/profile.html', {
        'target_user': target_user,
        'has_privileged_access': has_privileged_access,
        'is_own_profile': request.user == target_user,
    })