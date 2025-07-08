import os
import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

from .forms import CustomUserCreationForm, GitScanForm, ZipUploadForm, ContactForm
from .models import ScanSession, SecretFinding, UserProfile
from .utils.secret_detector import SecretDetector
from .utils.git_handler import GitHandler
from .utils.zip_handler import ZipHandler
from .utils.report_generator import ReportGenerator
from .utils.email_service import EmailService

def home(request):
    """Home page view."""
    return render(request, 'scanner/home.html')

def about(request):
    """About page view."""
    return render(request, 'scanner/about.html')

def contact(request):
    """Contact page view."""
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            # Send email
            email_service = EmailService()
            success = email_service.send_contact_form_email(
                name=form.cleaned_data['name'],
                email=form.cleaned_data['email'],
                subject=form.cleaned_data['subject'],
                message=form.cleaned_data['message']
            )
            
            if success:
                messages.success(request, 'Your message has been sent successfully!')
            else:
                messages.error(request, 'There was an error sending your message. Please try again.')
            
            return redirect('contact')
    else:
        form = ContactForm()
    
    return render(request, 'scanner/contact.html', {'form': form})

def register(request):
    """User registration view."""
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Create user profile
            UserProfile.objects.create(user=user)
            login(request, user)
            messages.success(request, 'Registration successful!')
            return redirect('dashboard')
    else:
        form = CustomUserCreationForm()
    
    return render(request, 'registration/register.html', {'form': form})

@login_required
def dashboard(request):
    """User dashboard view."""
    recent_scans = ScanSession.objects.filter(user=request.user)[:5]
    
    # Statistics
    total_scans = ScanSession.objects.filter(user=request.user).count()
    total_secrets = SecretFinding.objects.filter(scan_session__user=request.user).count()
    high_severity_secrets = SecretFinding.objects.filter(
        scan_session__user=request.user,
        severity='high'
    ).count()
    
    context = {
        'recent_scans': recent_scans,
        'total_scans': total_scans,
        'total_secrets': total_secrets,
        'high_severity_secrets': high_severity_secrets,
    }
    
    return render(request, 'scanner/dashboard.html', context)

@login_required
def scan_form(request):
    """Scan form view with both Git URL and ZIP upload options."""
    git_form = GitScanForm()
    zip_form = ZipUploadForm()
    
    if request.method == 'POST':
        scan_type = request.POST.get('scan_type')
        
        if scan_type == 'git_url':
            git_form = GitScanForm(request.POST)
            if git_form.is_valid():
                return process_git_scan(request, git_form.cleaned_data['repository_url'])
        
        elif scan_type == 'zip_upload':
            zip_form = ZipUploadForm(request.POST, request.FILES)
            if zip_form.is_valid():
                return process_zip_scan(request, request.FILES['zip_file'])
    
    context = {
        'git_form': git_form,
        'zip_form': zip_form,
    }
    
    return render(request, 'scanner/scan_form.html', context)

def process_git_scan(request, repository_url):
    """Process Git repository scan."""
    # Create scan session
    scan_session = ScanSession.objects.create(
        user=request.user,
        scan_type='git_url',
        repository_url=repository_url,
        status='processing'
    )
    
    try:
        # Clone repository
        git_handler = GitHandler()
        temp_dir, error = git_handler.clone_repository(repository_url)
        
        if error:
            scan_session.status = 'failed'
            scan_session.save()
            messages.error(request, f'Failed to clone repository: {error}')
            return redirect('scan_form')
        
        # Scan for secrets
        detector = SecretDetector()
        findings = detector.scan_directory(temp_dir)
        
        # Save findings to database
        save_findings_to_db(scan_session, findings)
        
        # Update scan session
        scan_session.status = 'completed'
        scan_session.completed_at = timezone.now()
        scan_session.total_files_scanned = count_scanned_files(temp_dir)
        scan_session.secrets_found = len(findings)
        scan_session.save()
        
        # Send email notifications
        send_scan_notifications(request.user, scan_session, findings)
        
        # Cleanup
        git_handler.cleanup_temp_dirs()
        
        messages.success(request, f'Scan completed! Found {len(findings)} potential secrets.')
        return redirect('scan_result', scan_id=scan_session.id)
        
    except Exception as e:
        scan_session.status = 'failed'
        scan_session.save()
        messages.error(request, f'Scan failed: {str(e)}')
        return redirect('scan_form')

def process_zip_scan(request, zip_file):
    """Process ZIP file scan."""
    # Create scan session
    scan_session = ScanSession.objects.create(
        user=request.user,
        scan_type='zip_upload',
        uploaded_file=zip_file,
        status='processing'
    )
    
    try:
        # Extract ZIP file
        zip_handler = ZipHandler()
        temp_dir, error = zip_handler.extract_zip(zip_file.temporary_file_path())
        
        if error:
            scan_session.status = 'failed'
            scan_session.save()
            messages.error(request, f'Failed to extract ZIP file: {error}')
            return redirect('scan_form')
        
        # Scan for secrets
        detector = SecretDetector()
        findings = detector.scan_directory(temp_dir)
        
        # Save findings to database
        save_findings_to_db(scan_session, findings)
        
        # Update scan session
        scan_session.status = 'completed'
        scan_session.completed_at = timezone.now()
        scan_session.total_files_scanned = count_scanned_files(temp_dir)
        scan_session.secrets_found = len(findings)
        scan_session.save()
        
        # Send email notifications
        send_scan_notifications(request.user, scan_session, findings)
        
        # Cleanup
        zip_handler.cleanup_temp_dirs()
        
        messages.success(request, f'Scan completed! Found {len(findings)} potential secrets.')
        return redirect('scan_result', scan_id=scan_session.id)
        
    except Exception as e:
        scan_session.status = 'failed'
        scan_session.save()
        messages.error(request, f'Scan failed: {str(e)}')
        return redirect('scan_form')

def save_findings_to_db(scan_session, findings):
    """Save scan findings to database."""
    for finding in findings:
        SecretFinding.objects.create(
            scan_session=scan_session,
            file_path=finding['file_path'],
            line_number=finding['line_number'],
            secret_type=finding['secret_type'],
            severity=finding['severity'],
            matched_text=finding['matched_text'][:500],  # Truncate if too long
            context_before=finding.get('context_before', ''),
            context_after=finding.get('context_after', ''),
        )

def count_scanned_files(directory):
    """Count the number of files that were scanned."""
    count = 0
    detector = SecretDetector()
    
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in detector.excluded_dirs]
        for file in files:
            if detector._should_scan_file(file):
                count += 1
    
    return count

def send_scan_notifications(user, scan_session, findings):
    """Send email notifications for scan completion."""
    try:
        user_profile = UserProfile.objects.get(user=user)
        if not user_profile.email_notifications:
            return
    except UserProfile.DoesNotExist:
        return
    
    email_service = EmailService()
    
    # Send completion email
    email_service.send_scan_completion_email(user, scan_session, findings)
    
    # Send high severity alert if needed
    high_severity_findings = [f for f in findings if f.get('severity') == 'high']
    if high_severity_findings:
        email_service.send_high_severity_alert(user, scan_session, high_severity_findings)

@login_required
def scan_result(request, scan_id):
    """Display scan results."""
    scan_session = get_object_or_404(ScanSession, id=scan_id, user=request.user)
    findings = SecretFinding.objects.filter(scan_session=scan_session)
    
    # Pagination
    paginator = Paginator(findings, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Statistics
    severity_counts = {
        'high': findings.filter(severity='high').count(),
        'medium': findings.filter(severity='medium').count(),
        'low': findings.filter(severity='low').count(),
    }
    
    context = {
        'scan_session': scan_session,
        'findings': page_obj,
        'severity_counts': severity_counts,
        'total_findings': findings.count(),
    }
    
    return render(request, 'scanner/scan_result.html', context)

@login_required
def scan_history(request):
    """Display user's scan history."""
    scans = ScanSession.objects.filter(user=request.user)
    
    # Pagination
    paginator = Paginator(scans, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'scans': page_obj,
    }
    
    return render(request, 'scanner/scan_history.html', context)

@login_required
def download_report(request, scan_id, format_type):
    """Download scan report in various formats."""
    scan_session = get_object_or_404(ScanSession, id=scan_id, user=request.user)
    findings = SecretFinding.objects.filter(scan_session=scan_session)
    
    # Convert findings to dict format
    findings_data = []
    for finding in findings:
        findings_data.append({
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'secret_type': finding.secret_type,
            'severity': finding.severity,
            'matched_text': finding.matched_text,
            'context_before': finding.context_before,
            'context_after': finding.context_after,
        })
    
    report_generator = ReportGenerator(scan_session, findings_data)
    
    if format_type == 'pdf':
        return report_generator.get_pdf_response()
    elif format_type == 'json':
        return report_generator.get_json_response()
    elif format_type == 'html':
        html_content = report_generator.generate_html_report()
        response = HttpResponse(html_content, content_type='text/html')
        response['Content-Disposition'] = f'attachment; filename="security_scan_{scan_id}.html"'
        return response
    else:
        messages.error(request, 'Invalid report format requested.')
        return redirect('scan_result', scan_id=scan_id)

@login_required
@require_http_methods(["POST"])
def mark_false_positive(request, finding_id):
    """Mark a finding as false positive."""
    finding = get_object_or_404(SecretFinding, id=finding_id, scan_session__user=request.user)
    finding.is_false_positive = not finding.is_false_positive
    finding.save()
    
    return JsonResponse({
        'success': True,
        'is_false_positive': finding.is_false_positive
    })

@login_required
def api_scan_status(request, scan_id):
    """API endpoint to check scan status."""
    scan_session = get_object_or_404(ScanSession, id=scan_id, user=request.user)
    
    return JsonResponse({
        'status': scan_session.status,
        'secrets_found': scan_session.secrets_found,
        'total_files_scanned': scan_session.total_files_scanned,
        'completed_at': scan_session.completed_at.isoformat() if scan_session.completed_at else None,
    })
