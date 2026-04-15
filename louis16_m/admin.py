from django.contrib import admin
from .models import LoginAttempt, UserProfile


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('username', 'ip_address', 'failed_attempts', 'locked_until')
    search_fields = ('username', 'ip_address')
    readonly_fields = ('first_failed_at', 'last_failed_at')


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'avatar', 'document')
    readonly_fields = ()
