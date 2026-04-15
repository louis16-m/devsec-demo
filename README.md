# devsec-demo
## Django based class demo about Security essentials required by dev

## Role-Based Access Control
This repository implements role-based access control for the UAS using Django-native groups and staff privileges.

Roles:
- anonymous visitors: may access registration and login only
- authenticated standard users: may access profile, password change, and other protected pages
- privileged users: staff or group members in `privileged`; may access the privileged dashboard

Unauthorized access is handled safely by either redirecting anonymous users to login or returning HTTP 403 for authenticated users without permission.