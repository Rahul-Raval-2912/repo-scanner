from django.contrib import admin
from .models import ScanSession, SecretFinding, UserProfile

@admin.register(ScanSession)
class ScanSessionAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'scan_type', 'status', 'secrets_found', 'created_at']
    list_filter = ['status', 'scan_type', 'created_at']
    search_fields = ['user__username', 'repository_url']
    readonly_fields = ['id', 'created_at', 'completed_at']

@admin.register(SecretFinding)
class SecretFindingAdmin(admin.ModelAdmin):
    list_display = ['scan_session', 'file_path', 'line_number', 'secret_type', 'severity']
    list_filter = ['secret_type', 'severity', 'is_false_positive']
    search_fields = ['file_path', 'matched_text']
    readonly_fields = ['created_at']

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'email_notifications', 'created_at']
    list_filter = ['email_notifications', 'created_at']
