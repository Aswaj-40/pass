# from django.urls import path
# from . import views  # Import views from the same directory

# urlpatterns = [
#     path('login/', views.login_view, name='login'),  # Ensure this line exists
#       path('dashboard/', views.dashboard_view, name='dashboard'),
#        path("signup/", views.signup_view, name="signup"), 
# ]
from django.urls import path
from . import views

urlpatterns = [
    path("", views.login_view, name="login"),
    path("signup/", views.signup_view, name="signup"),  # ✅ Make sure this is correct
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path('forget-password/', views.forget_password, name='forget_password'),
     path("reset-password/<uidb64>/<token>/", views.reset_password, name="reset_password"),
    path('logout/', views.logout_view, name='logout'),
    path('password-manager/', views.password_manager, name='password_manager'),
    path('password-manager/edit/<int:password_id>/', views.edit_password, name='edit_password'),
    path('password-manager/delete/<int:password_id>/', views.delete_password, name='delete_password'),
    path('set-master-password/', views.set_master_password, name='set_master_password'),
    path('verify-master-password/', views.verify_master_password, name='verify_master_password'),
    path('update_master_password/', views.update_master_password, name='update_master_password'),
    path('password-manager/get/<int:password_id>/', views.get_password, name='get_password'),
    path('password-manager/copy/<int:password_id>/', views.copy_password, name='copy_password'),
    path('profile/', views.profile, name='profile'),
    path('settings/', views.settings_view, name='settings'),
    path('change-password/', views.change_password, name='change_password'),
    path('test-email/', views.test_email, name='test_email'),  # New test email URL
    path('generate-password/', views.generate_password, name='generate_password'),  # Added generate password URL
    path('security-settings/', views.security_settings, name='security_settings'),  # Added security settings URL
    path('password-health/', views.password_health, name='password_health'),
    path('get-password-health/', views.get_password_health, name='get_password_health'),
]
