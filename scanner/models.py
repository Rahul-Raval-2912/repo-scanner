from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid
from django.db.models import JSONField

class ScanSession(models.Model):
    SCAN_TYPES = [
        ('git_url', 'Git URL'),
        ('zip_upload', 'ZIP Upload'),
        ('git_deep', 'Git Deep Scan'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES)
    repository_url = models.URLField(blank=True, null=True)
    uploaded_file = models.FileField(upload_to='uploads/', blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(blank=True, null=True)
    total_files_scanned = models.IntegerField(default=0)
    secrets_found = models.IntegerField(default=0)
    commits_scanned = models.IntegerField(default=0)
    is_deep_scan = models.BooleanField(default=False)
    auto_remediation = JSONField(default=list, blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Scan {self.id} by {self.user.username}"

class SecretFinding(models.Model):
    SEVERITY_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    SECRET_TYPES = [
        ('aws_key', 'AWS Access Key'),
        ('aws_secret', 'AWS Secret Key'),
        ('gcp_key', 'GCP Service Account Key'),
        ('jwt_token', 'JWT Token'),
        ('db_url', 'Database URL'),
        ('email_password', 'Email/Password'),
        ('private_key', 'Private Key'),
        ('api_key', 'API Key'),
        ('oauth_token', 'OAuth Token'),
        ('ssh_key', 'SSH Key'),
    ]
    
    scan_session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='findings')
    file_path = models.CharField(max_length=500)
    line_number = models.IntegerField()
    secret_type = models.CharField(max_length=50, choices=SECRET_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    matched_text = models.TextField()
    context_before = models.TextField(blank=True)
    context_after = models.TextField(blank=True)
    commit_hash = models.CharField(max_length=40, blank=True, null=True)
    commit_message = models.TextField(blank=True, null=True)
    commit_author = models.CharField(max_length=255, blank=True, null=True)
    commit_date = models.DateTimeField(blank=True, null=True)
    is_false_positive = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-severity', 'file_path', 'line_number']
    
    def __str__(self):
        return f"{self.secret_type} in {self.file_path}:{self.line_number}"

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email_notifications = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return f"Profile for {self.user.username}"
