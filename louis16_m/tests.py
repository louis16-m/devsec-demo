
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import Group, User

class AuthTests(TestCase):
    def test_register_view_status_code(self):
        response = self.client.get(reverse('louis16_m:register'))
        self.assertEqual(response.status_code, 200)

    def test_register_user(self):
        response = self.client.post(reverse('louis16_m:register'), {
            'username': 'testuser',
            'password1': 'testpass123',
            'password2': 'testpass123'
        })
        self.assertEqual(response.status_code, 302)  # Redirect to login
        self.assertTrue(User.objects.filter(username='testuser').exists())
        self.assertTrue(User.objects.get(username='testuser').groups.filter(name='standard').exists())

    def test_login_view_status_code(self):
        response = self.client.get(reverse('louis16_m:login'))
        self.assertEqual(response.status_code, 200)

    def test_login_user(self):
        User.objects.create_user(username='testuser', password='testpass123')
        response = self.client.post(reverse('louis16_m:login'), {
            'username': 'testuser',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, 302)  # Redirect after login

    def test_profile_requires_login(self):
        response = self.client.get(reverse('louis16_m:profile'))
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_profile_authenticated(self):
        User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('louis16_m:profile'))
        self.assertEqual(response.status_code, 200)

    def test_logout(self):
        User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')
        response = self.client.post(reverse('louis16_m:logout'))
        self.assertEqual(response.status_code, 302)  # Redirect after logout

    def test_password_change_requires_login(self):
        response = self.client.get(reverse('louis16_m:password_change'))
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_password_change_authenticated(self):
        user = User.objects.create_user(username='testuser', password='oldpass123')
        self.client.login(username='testuser', password='oldpass123')
        response = self.client.post(reverse('louis16_m:password_change'), {
            'old_password': 'oldpass123',
            'new_password1': 'newpass123',
            'new_password2': 'newpass123'
        })
        self.assertEqual(response.status_code, 302)  # Redirect to done
        user.refresh_from_db()
        self.assertTrue(user.check_password('newpass123'))

    def test_privileged_dashboard_requires_login(self):
        response = self.client.get(reverse('louis16_m:privileged_dashboard'))
        self.assertEqual(response.status_code, 302)

    def test_privileged_dashboard_forbidden_for_standard_user(self):
        user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('louis16_m:privileged_dashboard'))
        self.assertEqual(response.status_code, 403)

    def test_privileged_dashboard_allowed_for_staff(self):
        user = User.objects.create_user(username='staffuser', password='testpass123', is_staff=True)
        self.client.login(username='staffuser', password='testpass123')
        response = self.client.get(reverse('louis16_m:privileged_dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_privileged_dashboard_allowed_for_group_member(self):
        user = User.objects.create_user(username='privilegeduser', password='testpass123')
        group, _ = Group.objects.get_or_create(name='privileged')
        user.groups.add(group)
        self.client.login(username='privilegeduser', password='testpass123')
        response = self.client.get(reverse('louis16_m:privileged_dashboard'))
        self.assertEqual(response.status_code, 200)
