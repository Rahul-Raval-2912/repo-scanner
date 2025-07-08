from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # Public pages
    path('', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('contact/', views.contact, name='contact'),
    
    # Authentication
    path('register/', views.register, name='register'),
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    
    # Password reset
    path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    
    # Dashboard and scanning
    path('dashboard/', views.dashboard, name='dashboard'),
    path('scan/', views.scan_form, name='scan_form'),
    path('scan/<uuid:scan_id>/', views.scan_result, name='scan_result'),
    path('history/', views.scan_history, name='scan_history'),
    
    # Reports and downloads
    path('scan/<uuid:scan_id>/download/<str:format_type>/', views.download_report, name='download_report'),
    
    # API endpoints
    path('api/scan/<uuid:scan_id>/status/', views.api_scan_status, name='api_scan_status'),
    path('api/finding/<int:finding_id>/false-positive/', views.mark_false_positive, name='mark_false_positive'),
]
