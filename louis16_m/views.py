from functools import wraps
from datetime import timedelta

from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, User
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.utils import timezone

from .models import LoginAttempt

ROLE_STANDARD = 'standard'
ROLE_PRIVILEGED = 'privileged'
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_PERIOD = timedelta(minutes=15)


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


def get_client_ip(request):
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def get_login_attempt(username, ip_address):
    return LoginAttempt.objects.filter(username=username, ip_address=ip_address).first()


def create_login_attempt(username, ip_address):
    return LoginAttempt.objects.create(username=username, ip_address=ip_address)


def record_failed_login(username, ip_address):
    attempt = get_login_attempt(username, ip_address)
    if attempt is None:
        attempt = create_login_attempt(username, ip_address)
    attempt.failed_attempts += 1
    attempt.last_failed_at = timezone.now()
    if attempt.failed_attempts >= MAX_LOGIN_ATTEMPTS:
        attempt.lock(LOCKOUT_PERIOD)
    else:
        attempt.save()
    return attempt


def reset_login_attempt(username, ip_address):
    attempt = get_login_attempt(username, ip_address)
    if attempt is not None:
        attempt.reset()


def lockout_message(attempt):
    if attempt and attempt.is_locked():
        remaining = int((attempt.locked_until - timezone.now()).total_seconds() // 60) + 1
        return (
            'Too many failed login attempts. Your account is temporarily locked. '
            f'Please try again in {remaining} minute(s).'
        )
    return ''


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
    ip_address = get_client_ip(request)
    username = request.POST.get('username', '').strip()
    attempt = get_login_attempt(username, ip_address) if username else None

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if attempt and attempt.is_locked():
            form.add_error(None, lockout_message(attempt))
        elif form.is_valid():
            user = form.get_user()
            login(request, user)
            reset_login_attempt(username, ip_address)
            messages.success(request, f'Welcome back, {user.username}!')
            return redirect(next_url or 'louis16_m:profile')
        else:
            if username:
                record_failed_login(username, ip_address)
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


@login_required
def update_profile_ajax(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name', '').strip()
        request.user.first_name = first_name
        request.user.save()
        return JsonResponse({'status': 'success', 'first_name': first_name})
    return JsonResponse({'status': 'error'}, status=400)
