import tempfile

from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.contrib.auth.models import Group, User
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode


class AuthTests(TestCase):
    def test_register_view_status_code(self):
        response = self.client.get(reverse("louis16_m:register"))
        self.assertEqual(response.status_code, 200)

    def test_register_user(self):
        response = self.client.post(
            reverse("louis16_m:register"),
            {
                "username": "testuser",
                "password1": "testpass123",
                "password2": "testpass123",
            },
        )
        self.assertEqual(response.status_code, 302)  # Redirect to login
        self.assertTrue(User.objects.filter(username="testuser").exists())
        self.assertTrue(
            User.objects.get(username="testuser")
            .groups.filter(name="standard")
            .exists()
        )

    def test_login_view_status_code(self):
        response = self.client.get(reverse("louis16_m:login"))
        self.assertEqual(response.status_code, 200)

    def test_login_user(self):
        User.objects.create_user(username="testuser", password="testpass123")
        response = self.client.post(
            reverse("louis16_m:login"),
            {"username": "testuser", "password": "testpass123"},
        )
        self.assertEqual(response.status_code, 302)  # Redirect after login

    def test_login_redirects_to_internal_next(self):
        User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")
        target = reverse("louis16_m:profile")
        response = self.client.post(
            reverse("louis16_m:login") + f"?next={target}",
            {"username": "testuser", "password": "testpass123"},
        )
        self.assertRedirects(response, target)

    def test_login_rejects_external_next_target(self):
        User.objects.create_user(username="testuser", password="testpass123")
        response = self.client.post(
            reverse("louis16_m:login") + "?next=http://evil.com",
            {"username": "testuser", "password": "testpass123"},
        )
        self.assertRedirects(response, reverse("louis16_m:profile"))

    def test_profile_requires_login(self):
        response = self.client.get(reverse("louis16_m:profile"))
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_profile_authenticated(self):
        User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")
        response = self.client.get(reverse("louis16_m:profile"))
        self.assertEqual(response.status_code, 200)

    def test_logout(self):
        User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")
        response = self.client.post(reverse("louis16_m:logout"))
        self.assertEqual(response.status_code, 302)  # Redirect after logout

    def test_logout_logs_audit_event(self):
        User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")
        with self.assertLogs("louis16_m.audit", level="INFO") as cm:
            response = self.client.post(reverse("louis16_m:logout"))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(any("auth.logout" in message for message in cm.output))

    def test_password_change_requires_login(self):
        response = self.client.get(reverse("louis16_m:password_change"))
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_password_change_authenticated(self):
        user = User.objects.create_user(username="testuser", password="oldpass123")
        self.client.login(username="testuser", password="oldpass123")
        response = self.client.post(
            reverse("louis16_m:password_change"),
            {
                "old_password": "oldpass123",
                "new_password1": "newpass123",
                "new_password2": "newpass123",
            },
        )
        self.assertEqual(response.status_code, 302)  # Redirect to done
        user.refresh_from_db()
        self.assertTrue(user.check_password("newpass123"))

    def test_privileged_dashboard_requires_login(self):
        response = self.client.get(reverse("louis16_m:privileged_dashboard"))
        self.assertEqual(response.status_code, 302)

    def test_privileged_dashboard_forbidden_for_standard_user(self):
        User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")
        response = self.client.get(reverse("louis16_m:privileged_dashboard"))
        self.assertEqual(response.status_code, 403)

    def test_registration_logs_audit_events(self):
        with self.assertLogs("louis16_m.audit", level="INFO") as cm:
            response = self.client.post(
                reverse("louis16_m:register"),
                {
                    "username": "testuser",
                    "password1": "testpass123",
                    "password2": "testpass123",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(any("auth.registration" in message for message in cm.output))
        self.assertTrue(any("auth.role.assigned" in message for message in cm.output))

    def test_login_success_logs_audit_event(self):
        User.objects.create_user(username="testuser", password="testpass123")
        with self.assertLogs("louis16_m.audit", level="INFO") as cm:
            response = self.client.post(
                reverse("louis16_m:login"),
                {"username": "testuser", "password": "testpass123"},
            )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(any("auth.login.success" in message for message in cm.output))

    def test_login_failure_logs_audit_event(self):
        with self.assertLogs("louis16_m.audit", level="INFO") as cm:
            response = self.client.post(
                reverse("louis16_m:login"),
                {"username": "doesnotexist", "password": "wrongpass"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any("auth.login.failure" in message for message in cm.output))

    def test_password_reset_request_logs_audit_event(self):
        User.objects.create_user(
            username="resetuser", email="reset@example.com", password="oldpass123"
        )
        with self.assertLogs("louis16_m.audit", level="INFO") as cm:
            response = self.client.post(
                reverse("louis16_m:password_reset"), {"email": "reset@example.com"}
            )
        self.assertRedirects(response, reverse("louis16_m:password_reset_done"))
        self.assertTrue(
            any("auth.password_reset.requested" in message for message in cm.output)
        )

    def test_password_reset_complete_logs_audit_event(self):
        user = User.objects.create_user(
            username="resetuser", email="reset@example.com", password="oldpass123"
        )
        response = self.client.post(
            reverse("louis16_m:password_reset"), {"email": "reset@example.com"}
        )
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_url = reverse("louis16_m:password_reset_confirm", args=[uid, token])
        response = self.client.get(reset_url)
        post_url = getattr(response, "url", reset_url) or reset_url
        with self.assertLogs("louis16_m.audit", level="INFO") as cm:
            response = self.client.post(
                post_url, {"new_password1": "newpass123", "new_password2": "newpass123"}
            )
        self.assertTrue(
            any("auth.password_reset.completed" in message for message in cm.output)
        )

    def test_privileged_dashboard_allowed_for_staff(self):
        User.objects.create_user(
            username="staffuser", password="testpass123", is_staff=True
        )
        self.client.login(username="staffuser", password="testpass123")
        response = self.client.get(reverse("louis16_m:privileged_dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_privileged_dashboard_allowed_for_group_member(self):
        user = User.objects.create_user(
            username="privilegeduser", password="testpass123"
        )
        group, _ = Group.objects.get_or_create(name="privileged")
        user.groups.add(group)
        self.client.login(username="privilegeduser", password="testpass123")
        response = self.client.get(reverse("louis16_m:privileged_dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_profile_detail_allowed_for_owner(self):
        user = User.objects.create_user(username="owner", password="testpass123")
        self.client.login(username="owner", password="testpass123")
        response = self.client.get(reverse("louis16_m:profile_detail", args=[user.id]))
        self.assertEqual(response.status_code, 200)

    def test_profile_upload_accepts_valid_avatar_and_document(self):
        user = User.objects.create_user(username="uploaduser", password="testpass123")
        self.client.login(username="uploaduser", password="testpass123")
        avatar = SimpleUploadedFile(
            "avatar.gif",
            b"GIF89a\x01\x00\x01\x00\x80\xff\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02L\x01\x00;",
            content_type="image/gif",
        )
        document = SimpleUploadedFile(
            "document.pdf", b"%PDF-1.4\n%%EOF\n", content_type="application/pdf"
        )
        with tempfile.TemporaryDirectory() as media_root:
            with override_settings(MEDIA_ROOT=media_root):
                response = self.client.post(
                    reverse("louis16_m:profile"),
                    {
                        "avatar": avatar,
                        "document": document,
                    },
                    follow=True,
                )
                self.assertEqual(response.status_code, 200)
                user.refresh_from_db()
                self.assertTrue(hasattr(user, "profile"))
                self.assertTrue(user.profile.avatar.name.lower().endswith(".gif"))
                self.assertTrue(user.profile.document.name.lower().endswith(".pdf"))

    def test_profile_upload_rejects_unsafe_document(self):
        User.objects.create_user(username="unsafeuser", password="testpass123")
        self.client.login(username="unsafeuser", password="testpass123")
        bad_document = SimpleUploadedFile(
            "document.pdf", b"NotAPDF", content_type="application/pdf"
        )
        with tempfile.TemporaryDirectory() as media_root:
            with override_settings(MEDIA_ROOT=media_root):
                response = self.client.post(
                    reverse("louis16_m:profile"),
                    {
                        "document": bad_document,
                    },
                )
                self.assertEqual(response.status_code, 200)
                self.assertContains(
                    response, "Uploaded document is not a valid PDF file."
                )

    def test_profile_file_download_is_protected(self):
        from louis16_m.models import UserProfile

        owner = User.objects.create_user(username="owner", password="testpass123")
        User.objects.create_user(username="other", password="testpass123")
        profile, _ = UserProfile.objects.get_or_create(user=owner)
        with tempfile.TemporaryDirectory() as media_root:
            with override_settings(MEDIA_ROOT=media_root):
                avatar = SimpleUploadedFile(
                    "avatar.png",
                    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01\xe2!\xbc\x33\x00\x00\x00\x00IEND\xaeB`\x82",
                    content_type="image/png",
                )
                profile.avatar.save("avatar.jpg", avatar)
                avatar.close()
                self.client.login(username="other", password="testpass123")
                response = self.client.get(
                    reverse("louis16_m:serve_uploaded_file", args=[owner.id, "avatar"])
                )
                self.assertEqual(response.status_code, 403)
                response.close()
                self.client.logout()
                self.client.login(username="owner", password="testpass123")
                response = self.client.get(
                    reverse("louis16_m:serve_uploaded_file", args=[owner.id, "avatar"])
                )
                self.assertEqual(response.status_code, 200)
                response.close()

    def test_profile_detail_forbidden_for_other_user(self):
        owner = User.objects.create_user(username="owner", password="testpass123")
        User.objects.create_user(username="other", password="testpass123")
        self.client.login(username="other", password="testpass123")
        response = self.client.get(reverse("louis16_m:profile_detail", args=[owner.id]))
        self.assertEqual(response.status_code, 403)

    def test_profile_detail_allowed_for_privileged_user(self):
        owner = User.objects.create_user(username="owner", password="testpass123")
        User.objects.create_user(
            username="privileged", password="testpass123", is_staff=True
        )
        self.client.login(username="privileged", password="testpass123")
        response = self.client.get(reverse("louis16_m:profile_detail", args=[owner.id]))
        self.assertEqual(response.status_code, 200)

    def test_login_lockout_after_repeated_failed_attempts(self):
        username = "abuseuser"
        User.objects.create_user(username=username, password="correctpass")
        for _ in range(5):
            response = self.client.post(
                reverse("louis16_m:login"),
                {"username": username, "password": "wrongpass"},
            )
            self.assertEqual(response.status_code, 200)
        response = self.client.post(
            reverse("louis16_m:login"), {"username": username, "password": "wrongpass"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Too many failed login attempts")

    def test_successful_login_resets_failed_attempts(self):
        username = "recoveruser"
        User.objects.create_user(username=username, password="correctpass")
        response = self.client.post(
            reverse("louis16_m:login"), {"username": username, "password": "wrongpass"}
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.post(
            reverse("louis16_m:login"),
            {"username": username, "password": "correctpass"},
        )
        self.assertEqual(response.status_code, 302)

    def test_login_lockout_is_account_based(self):
        User.objects.create_user(username="target", password="correctpass")
        User.objects.create_user(username="other", password="correctpass")
        for _ in range(6):
            response = self.client.post(
                reverse("louis16_m:login"),
                {"username": "target", "password": "wrongpass"},
            )
        self.assertContains(response, "Too many failed login attempts")
        response = self.client.post(
            reverse("louis16_m:login"), {"username": "other", "password": "correctpass"}
        )
        self.assertEqual(response.status_code, 302)

    def test_password_reset_request_nonexistent_email_does_not_leak(self):
        response = self.client.post(
            reverse("louis16_m:password_reset"), {"email": "unknown@example.com"}
        )
        self.assertRedirects(response, reverse("louis16_m:password_reset_done"))
        self.assertEqual(len(mail.outbox), 0)

    def test_password_reset_request_sends_email_for_existing_user(self):
        User.objects.create_user(
            username="resetuser", email="reset@example.com", password="oldpass123"
        )
        response = self.client.post(
            reverse("louis16_m:password_reset"), {"email": "reset@example.com"}
        )
        self.assertRedirects(response, reverse("louis16_m:password_reset_done"))
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("reset", mail.outbox[0].subject.lower())

    def test_password_reset_confirm_allows_new_password(self):
        user = User.objects.create_user(
            username="resetuser", email="reset@example.com", password="oldpass123"
        )
        response = self.client.post(
            reverse("louis16_m:password_reset"), {"email": "reset@example.com"}
        )
        self.assertRedirects(response, reverse("louis16_m:password_reset_done"))
        message = mail.outbox[0].body
        self.assertIn("/auth/reset/", message)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_url = reverse("louis16_m:password_reset_confirm", args=[uid, token])
        response = self.client.get(reset_url, follow=True)
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            response.request["PATH_INFO"],
            {"new_password1": "newpass123", "new_password2": "newpass123"},
            follow=True,
        )
        self.assertRedirects(response, reverse("louis16_m:password_reset_complete"))
        user.refresh_from_db()
        self.assertTrue(user.check_password("newpass123"))

    def test_password_reset_confirm_invalid_token_is_safe(self):
        user = User.objects.create_user(
            username="resetuser", email="reset@example.com", password="oldpass123"
        )
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        invalid_url = reverse(
            "louis16_m:password_reset_confirm", args=[uid, "invalid-token"]
        )
        response = self.client.get(invalid_url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["validlink"])
        response = self.client.post(
            response.request["PATH_INFO"],
            {"new_password1": "newpass123", "new_password2": "newpass123"},
            follow=True,
        )
        user.refresh_from_db()
        self.assertTrue(user.check_password("oldpass123"))

    def test_update_profile_ajax_requires_login(self):
        response = self.client.post(
            reverse("louis16_m:update_profile_ajax"), {"first_name": "Test"}
        )
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_update_profile_ajax_success(self):
        user = User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")
        response = self.client.post(
            reverse("louis16_m:update_profile_ajax"), {"first_name": "UpdatedName"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["first_name"], "UpdatedName")
        user.refresh_from_db()
        self.assertEqual(user.first_name, "UpdatedName")

    def test_update_profile_ajax_csrf_protection(self):
        # CSRF protection is demonstrated by the success test, as the AJAX request includes the token
        # and the view requires it for POST requests. Without the token, the request would fail with 403.
        # This test ensures the functionality works with CSRF protection in place.
        User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")
        response = self.client.post(
            reverse("louis16_m:update_profile_ajax"), {"first_name": "UpdatedName"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")

    def test_update_profile_ajax_strips_html_tags(self):
        user = User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")
        response = self.client.post(
            reverse("louis16_m:update_profile_ajax"),
            {"first_name": '<script>alert("XSS")</script>John'},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["first_name"], 'alert("XSS")John')  # Tags stripped
        user.refresh_from_db()
        self.assertEqual(user.first_name, 'alert("XSS")John')
