from django.db import models
from django.utils import timezone


class LoginAttempt(models.Model):
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    failed_attempts = models.PositiveSmallIntegerField(default=0)
    first_failed_at = models.DateTimeField(auto_now_add=True)
    last_failed_at = models.DateTimeField(auto_now=True)
    locked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('username', 'ip_address')
        indexes = [
            models.Index(fields=['username', 'ip_address']),
        ]

    def __str__(self):
        return f"{self.username} @ {self.ip_address or 'unknown'}: {self.failed_attempts} failed"

    def is_locked(self):
        return self.locked_until is not None and self.locked_until > timezone.now()

    def lock(self, duration):
        self.failed_attempts = max(self.failed_attempts, 0)
        self.locked_until = timezone.now() + duration
        self.save()

    def reset(self):
        self.failed_attempts = 0
        self.locked_until = None
        self.save()
