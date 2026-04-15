# devsec-demo
## Django based class demo about Security essentials required by dev

## Role-Based Access Control
This repository implements role-based access control for the UAS using Django-native groups and staff privileges.

Roles:
- anonymous visitors: may access registration and login only
- authenticated standard users: may access profile, password change, and other protected pages
- privileged users: staff or group members in `privileged`; may access the privileged dashboard

Unauthorized access is handled safely by either redirecting anonymous users to login or returning HTTP 403 for authenticated users without permission.

## Preventing IDOR in Profile Access
Profile access now uses explicit object-level access control when a route receives a user identifier.
The `profile/<int:user_id>/` route looks up the target user and verifies that the current user either owns that profile or is privileged.
If the user is authenticated but not authorized, the view raises HTTP 403 rather than leaking whether the profile exists.

## Secure Password Reset
Password reset uses Django's built-in `PasswordResetView` and related views, which provide secure token-based reset links and avoid custom token schemes.
The reset request page returns a generic success response regardless of whether the email exists, preventing account enumeration.
The workflow also uses the local email backend for development and tests, and the reset token validation respects Django's built-in security rules.

## Login Bruteforce Protection
Login is hardened with account- and IP-aware failed attempt tracking.
After 5 failed attempts, the login route temporarily locks the account for 15 minutes and returns a generic cooldown message.
Legitimate users can still log in normally if they use valid credentials before the threshold is reached, and the system resets the counter after a successful login.

## CSRF Protection in AJAX Workflows
Custom AJAX endpoints for state-changing operations must include CSRF tokens to prevent cross-site request forgery.
The `update_profile_ajax` view updates user profile data via POST and requires a valid CSRF token in the `X-CSRFToken` header.
The frontend JavaScript retrieves the CSRF token from the `csrftoken` cookie and includes it in AJAX requests.
This ensures that even AJAX-driven forms are protected against CSRF attacks, maintaining the security of the application while preserving user experience.