from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from typing import List, Dict, Optional
import logging
from functools import lru_cache

from scanner.models import ScanSession

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        self.from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@repoguardian.com')
        self._validate_config()
    
    def _validate_config(self):
        """Validate email configuration on initialization."""
        if not self.from_email:
            raise ImproperlyConfigured("DEFAULT_FROM_EMAIL setting is required")
        
        if not hasattr(settings, 'EMAIL_BACKEND'):
            logger.warning("EMAIL_BACKEND not configured, emails may not be sent")
    
    @lru_cache(maxsize=1)
    def _get_base_url(self) -> str:
        """Get base URL with caching."""
        hosts = getattr(settings, 'ALLOWED_HOSTS', [])
        if hosts and hosts[0] != '*':
            protocol = 'https' if getattr(settings, 'SECURE_SSL_REDIRECT', False) else 'http'
            return f"{protocol}://{hosts[0]}"
        return "http://localhost:8000"
    
    def _calculate_severity_summary(self, findings: List[Dict]) -> Dict[str, int]:
        """Calculate severity counts efficiently."""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        return severity_counts
    
    def send_scan_completion_email(self, user, scan_session, findings: List[Dict]) -> bool:
        """Send email notification when scan is completed."""
        if not user.email:
            logger.warning(f"User {user.id} has no email address")
            return False
        
        try:
            severity_counts = self._calculate_severity_summary(findings)
            critical_high_findings = [
                f for f in findings 
                if f.get('severity', '').lower() in ['critical', 'high']
            ][:5]
            
            context = {
                'user': user,
                'scan_session': scan_session,
                'findings_count': len(findings),
                'severity_counts': severity_counts,
                'critical_high_findings': critical_high_findings,
                'scan_url': f"{self._get_base_url()}/scan/{scan_session.id}/",
                'repository_name': getattr(scan_session, 'repository_name', 'Unknown'),
            }
            
            subject = self._generate_scan_subject(len(findings), severity_counts)
            
            return self._send_templated_email(
                subject=subject,
                template_base='scanner/emails/scan_complete',
                context=context,
                recipient=user.email,
                log_action=f"scan completion for scan {scan_session.id}"
            )
            
        except Exception as e:
            logger.error(f"Failed to send scan completion email to {user.email}: {e}", exc_info=True)
            return False
    
    def _generate_scan_subject(self, findings_count: int, severity_counts: Dict[str, int]) -> str:
        """Generate appropriate subject line based on findings."""
        if severity_counts['critical'] > 0:
            return f"🚨 CRITICAL: {findings_count} Issues Found (RepoGuardian)"
        elif severity_counts['high'] > 0:
            return f"⚠️ HIGH RISK: {findings_count} Issues Found (RepoGuardian)"
        elif findings_count > 0:
            return f"RepoGuardian Scan Complete - {findings_count} Issues Found"
        else:
            return "✅ RepoGuardian Scan Complete - No Issues Found"
    
    def send_high_severity_alert(self, user, scan_session, high_severity_findings: List[Dict]) -> bool:
        """Send immediate alert for critical/high severity findings."""
        if not high_severity_findings or not user.email:
            return True
        
        try:
            # Group findings by type for better presentation
            findings_by_type = {}
            for finding in high_severity_findings:
                finding_type = finding.get('type', 'Unknown')
                if finding_type not in findings_by_type:
                    findings_by_type[finding_type] = []
                findings_by_type[finding_type].append(finding)
            
            context = {
                'user': user,
                'scan_session': scan_session,
                'findings': high_severity_findings,
                'findings_by_type': findings_by_type,
                'findings_count': len(high_severity_findings),
                'scan_url': f"{self._get_base_url()}/scan/{scan_session.id}/",
                'repository_name': getattr(scan_session, 'repository_name', 'Unknown'),
            }
            
            severity_level = self._get_highest_severity(high_severity_findings)
            subject = f"🚨 {severity_level.upper()}: {len(high_severity_findings)} High-Risk Issues Found"
            
            return self._send_templated_email(
                subject=subject,
                template_base='scanner/emails/high_severity_alert',
                context=context,
                recipient=user.email,
                log_action=f"high severity alert for scan {scan_session.id}"
            )
            
        except Exception as e:
            logger.error(f"Failed to send high severity alert to {user.email}: {e}", exc_info=True)
            return False
    
    def _get_highest_severity(self, findings: List[Dict]) -> str:
        """Get the highest severity level from findings."""
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        highest = 'low'
        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            if severity_order.get(severity, 1) > severity_order.get(highest, 1):
                highest = severity
        return highest
    
    def send_contact_form_email(self, name: str, email: str, subject: str, message: str) -> bool:
        """Send contact form submission email."""
        if not all([name, email, subject, message]):
            logger.warning("Contact form submission missing required fields")
            return False
        
        try:
            admin_email = getattr(settings, 'ADMIN_EMAIL', self.from_email)
            
            context = {
                'name': name,
                'email': email,
                'subject': subject,
                'message': message,
                'timestamp': ScanSession.created_at if 'scan_session' in locals() else None,
            }
            
            return self._send_templated_email(
                subject=f"Contact Form: {subject}",
                template_base='scanner/emails/contact_form',
                context=context,
                recipient=admin_email,
                log_action=f"contact form submission from {email}",
                reply_to=email
            )
            
        except Exception as e:
            logger.error(f"Failed to send contact form email from {email}: {e}", exc_info=True)
            return False
    
    def _send_templated_email(self, subject: str, template_base: str, context: Dict, 
                            recipient: str, log_action: str, reply_to: Optional[str] = None) -> bool:
        """Send templated email with both text and HTML versions."""
        try:
            text_content = render_to_string(f'{template_base}.txt', context)
            html_content = render_to_string(f'{template_base}.html', context)
            
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=self.from_email,
                to=[recipient],
                reply_to=[reply_to] if reply_to else None
            )
            email.attach_alternative(html_content, "text/html")
            email.send()
            
            logger.info(f"Email sent successfully: {log_action}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send templated email for {log_action}: {e}", exc_info=True)
            return False
