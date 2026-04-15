from django.urls import path, reverse_lazy
from django.contrib.auth import views as auth_views
from . import views

app_name = 'louis16_m'

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('profile/<int:user_id>/', views.profile_detail_view, name='profile_detail'),
    path('profile/<int:user_id>/files/<str:file_type>/', views.serve_uploaded_file, name='serve_uploaded_file'),
    path('password_change/', views.password_change_view, name='password_change'),
    path('password_change/done/', views.password_change_done_view, name='password_change_done'),
    path('password_reset/', views.AuditPasswordResetView.as_view(
        template_name='louis16_m/password_reset_form.html',
        email_template_name='louis16_m/password_reset_email.html',
        subject_template_name='louis16_m/password_reset_subject.txt',
        success_url=reverse_lazy('louis16_m:password_reset_done')
    ), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='louis16_m/password_reset_done.html'
    ), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.AuditPasswordResetConfirmView.as_view(
        template_name='louis16_m/password_reset_confirm.html',
        success_url=reverse_lazy('louis16_m:password_reset_complete')
    ), name='password_reset_confirm'),
    path('reset/<uidb64>/<token>/set-password/', views.AuditPasswordResetConfirmView.as_view(
        template_name='louis16_m/password_reset_confirm.html',
        success_url=reverse_lazy('louis16_m:password_reset_complete')
    )),
    path('password_reset/complete/', auth_views.PasswordResetCompleteView.as_view(
        template_name='louis16_m/password_reset_complete.html'
    ), name='password_reset_complete'),
    path('privileged/', views.privileged_dashboard_view, name='privileged_dashboard'),
    path('update_profile_ajax/', views.update_profile_ajax, name='update_profile_ajax'),
]

