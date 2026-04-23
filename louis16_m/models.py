import os
import uuid
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.core.files.images import get_image_dimensions

MAX_AVATAR_SIZE = 2 * 1024 * 1024
MAX_DOCUMENT_SIZE = 5 * 1024 * 1024
ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif"}
ALLOWED_IMAGE_MIMES = {"image/jpeg", "image/png", "image/gif"}
ALLOWED_DOCUMENT_EXTENSIONS = {".pdf"}
ALLOWED_DOCUMENT_MIMES = {"application/pdf"}


def _safe_file_name(filename):
    return f"{uuid.uuid4().hex}{os.path.splitext(filename)[1].lower()}"


def user_avatar_upload_path(instance, filename):
    return f"uploads/user_{instance.user_id}/avatars/{_safe_file_name(filename)}"


def user_document_upload_path(instance, filename):
    return f"uploads/user_{instance.user_id}/documents/{_safe_file_name(filename)}"


def _validate_file_extension(value, valid_extensions):
    ext = os.path.splitext(value.name)[1].lower()
    if ext not in valid_extensions:
        raise ValidationError(
            f'Unsupported file extension. Allowed: {", ".join(sorted(valid_extensions))}.'
        )


def validate_image_file(value):
    _validate_file_extension(value, ALLOWED_IMAGE_EXTENSIONS)

    if value.size > MAX_AVATAR_SIZE:
        raise ValidationError("File too large. Maximum size is 2MB.")

    if hasattr(value, "content_type") and value.content_type not in ALLOWED_IMAGE_MIMES:
        raise ValidationError("Invalid file type. Only JPEG, PNG, GIF allowed.")

    try:
        value.seek(0)
        width, height = get_image_dimensions(value)
    except Exception:
        raise ValidationError("Uploaded file is not a valid image.")

    if width > 1000 or height > 1000:
        raise ValidationError("Image too large. Maximum dimensions 1000x1000.")

    try:
        value.seek(0)
    except Exception:
        pass


def validate_document_file(value):
    _validate_file_extension(value, ALLOWED_DOCUMENT_EXTENSIONS)

    if value.size > MAX_DOCUMENT_SIZE:
        raise ValidationError("Document too large. Maximum size is 5MB.")

    if (
        hasattr(value, "content_type")
        and value.content_type not in ALLOWED_DOCUMENT_MIMES
    ):
        raise ValidationError("Invalid document type. Only PDF files are allowed.")

    try:
        value.seek(0)
        header = value.read(5)
        value.seek(0)
    except Exception:
        raise ValidationError("Unable to inspect uploaded document.")

    if header != b"%PDF-":
        raise ValidationError("Uploaded document is not a valid PDF file.")


class LoginAttempt(models.Model):
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    failed_attempts = models.PositiveSmallIntegerField(default=0)
    first_failed_at = models.DateTimeField(auto_now_add=True)
    last_failed_at = models.DateTimeField(auto_now=True)
    locked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ("username", "ip_address")
        indexes = [
            models.Index(fields=["username", "ip_address"]),
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


class UserProfile(models.Model):
    user = models.OneToOneField(
        "auth.User", on_delete=models.CASCADE, related_name="profile"
    )
    avatar = models.ImageField(
        upload_to=user_avatar_upload_path,
        validators=[validate_image_file],
        blank=True,
        null=True,
    )
    document = models.FileField(
        upload_to=user_document_upload_path,
        validators=[validate_document_file],
        blank=True,
        null=True,
    )

    def __str__(self):
        return f"{self.user.username}'s uploads"
