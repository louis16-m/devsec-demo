import json
import logging
import mimetypes
import os
from functools import wraps
from datetime import timedelta

from django import forms
from django.http import FileResponse, Http404, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import views as auth_views
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, User
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.utils.html import strip_tags
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils import timezone

from .models import LoginAttempt, UserProfile

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


audit_logger = logging.getLogger('louis16_m.audit')


def audit_log(event, request=None, user=None, extra=None):
    data = {
        'event': event,
        'ip_address': get_client_ip(request) if request else None,
        'path': request.path if request else None,
    }
    if user is not None:
        data.update({'user_id': user.id, 'username': user.username})
    if extra:
        data.update(extra)
    audit_logger.info(json.dumps({k: v for k, v in data.items() if v is not None}))


class ProfileUploadForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ('avatar', 'document')


def get_or_create_profile(user):
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile


def safe_redirect_target(request, target_url, fallback='louis16_m:profile'):
    if target_url and url_has_allowed_host_and_scheme(target_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return target_url
    return fallback


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
            audit_log('auth.registration', request, user, {'assigned_role': ROLE_STANDARD})
            audit_log('auth.role.assigned', request, user, {'assigned_role': ROLE_STANDARD})
            messages.success(request, 'Account created successfully! You can now log in.')
            return redirect('louis16_m:login')
    else:
        form = UserCreationForm()
    return render(request, 'louis16_m/register.html', {'form': form})


def login_view(request):
    raw_next = request.POST.get('next') or request.GET.get('next') or ''
    next_url = safe_redirect_target(request, raw_next)
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
            audit_log('auth.login.success', request, user, {
                'redirect_target': raw_next,
                'redirect_used': next_url or 'louis16_m:profile'
            })
            messages.success(request, f'Welcome back, {user.username}!')
            return redirect(next_url or 'louis16_m:profile')
        else:
            if username:
                record_failed_login(username, ip_address)
                audit_log('auth.login.failure', request, None, {'attempted_username': username})
    else:
        form = AuthenticationForm()
    return render(request, 'louis16_m/login.html', {'form': form, 'next': raw_next})


def logout_view(request):
    user = request.user if request.user.is_authenticated else None
    audit_log('auth.logout', request, user)
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('louis16_m:login')


class AuditPasswordResetView(auth_views.PasswordResetView):
    def form_valid(self, form):
        response = super().form_valid(form)
        user = None
        email = form.cleaned_data.get('email')
        if email:
            user = User.objects.filter(email=email).first()
        audit_log('auth.password_reset.requested', self.request, user, {
            'email': email,
            'user_exists': bool(user)
        })
        return response


class AuditPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    def form_valid(self, form):
        user = form.user
        response = super().form_valid(form)
        audit_log('auth.password_reset.completed', self.request, user)
        return response


@login_required
def password_change_view(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Keep user logged in
            audit_log('auth.password_change', request, user)
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
    profile = get_or_create_profile(request.user)
    if request.method == 'POST':
        form = ProfileUploadForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            audit_log('profile.upload.updated', request, request.user, {
                'avatar_uploaded': bool(profile.avatar),
                'document_uploaded': bool(profile.document),
            })
            messages.success(request, 'Your profile files were uploaded successfully.')
            return redirect('louis16_m:profile')
    else:
        form = ProfileUploadForm(instance=profile)

    has_privileged_access = is_privileged(request.user)
    return render(request, 'louis16_m/profile.html', {
        'target_user': request.user,
        'target_profile': profile,
        'upload_form': form,
        'has_privileged_access': has_privileged_access,
        'is_own_profile': True,
    })


@login_required
def profile_detail_view(request, user_id):
    target_user = get_object_or_404(User, pk=user_id)
    if request.user != target_user and not is_privileged(request.user):
        raise PermissionDenied
    profile = get_or_create_profile(target_user)
    has_privileged_access = is_privileged(request.user)
    return render(request, 'louis16_m/profile.html', {
        'target_user': target_user,
        'target_profile': profile,
        'upload_form': None,
        'has_privileged_access': has_privileged_access,
        'is_own_profile': request.user == target_user,
    })


@login_required
def serve_uploaded_file(request, user_id, file_type):
    if file_type not in {'avatar', 'document'}:
        raise Http404
    target_user = get_object_or_404(User, pk=user_id)
    if request.user != target_user and not is_privileged(request.user):
        raise PermissionDenied

    profile = get_or_create_profile(target_user)
    file_field = getattr(profile, file_type)
    if not file_field:
        raise Http404

    try:
        response = FileResponse(file_field.open('rb'), content_type=mimetypes.guess_type(file_field.name)[0] or 'application/octet-stream')
    except FileNotFoundError:
        raise Http404

    if file_type == 'document':
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_field.name)}"'
    else:
        response['Content-Disposition'] = 'inline'
    return response


@login_required
def update_profile_ajax(request):
    if request.method == 'POST':
        first_name = strip_tags(request.POST.get('first_name', '').strip())
        request.user.first_name = first_name
        request.user.save()
        return JsonResponse({'status': 'success', 'first_name': first_name})
    return JsonResponse({'status': 'error'}, status=400)