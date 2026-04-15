from django.contrib import admin
from .models import LoginAttempt


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('username', 'ip_address', 'failed_attempts', 'locked_until')
    search_fields = ('username', 'ip_address')
    readonly_fields = ('first_failed_at', 'last_failed_at')
