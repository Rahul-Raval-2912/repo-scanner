from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        self.from_email = settings.DEFAULT_FROM_EMAIL
    
    def send_scan_completion_email(self, user, scan_session, findings: List[Dict]):
        """Send email notification when scan is completed."""
        try:
            # Calculate summary
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            for finding in findings:
                severity = finding.get('severity', 'low')
                severity_counts[severity] += 1
            
            # Prepare context
            context = {
                'user': user,
                'scan_session': scan_session,
                'findings_count': len(findings),
                'severity_counts': severity_counts,
                'high_severity_findings': [f for f in findings if f.get('severity') == 'high'][:5],  # Top 5
                'scan_url': f"{settings.ALLOWED_HOSTS[0]}/scan/{scan_session.id}/",
            }
            
            # Render email templates
            subject = f"RepoGuardian Scan Complete - {len(findings)} Issues Found"
            text_content = render_to_string('scanner/emails/scan_complete.txt', context)
            html_content = render_to_string('scanner/emails/scan_complete.html', context)
            
            # Create email
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=self.from_email,
                to=[user.email]
            )
            email.attach_alternative(html_content, "text/html")
            
            # Send email
            email.send()
            
            logger.info(f"Scan completion email sent to {user.email} for scan {scan_session.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send scan completion email: {e}")
            return False
    
    def send_high_severity_alert(self, user, scan_session, high_severity_findings: List[Dict]):
        """Send immediate alert for high severity findings."""
        if not high_severity_findings:
            return True
        
        try:
            context = {
                'user': user,
                'scan_session': scan_session,
                'findings': high_severity_findings,
                'findings_count': len(high_severity_findings),
                'scan_url': f"{settings.ALLOWED_HOSTS[0]}/scan/{scan_session.id}/",
            }
            
            subject = f"🚨 CRITICAL: {len(high_severity_findings)} High-Risk Secrets Found"
            text_content = render_to_string('scanner/emails/high_severity_alert.txt', context)
            html_content = render_to_string('scanner/emails/high_severity_alert.html', context)
            
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=self.from_email,
                to=[user.email]
            )
            email.attach_alternative(html_content, "text/html")
            email.send()
            
            logger.info(f"High severity alert sent to {user.email} for scan {scan_session.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send high severity alert: {e}")
            return False
    
    def send_contact_form_email(self, name: str, email: str, subject: str, message: str):
        """Send contact form submission email."""
        try:
            full_subject = f"Contact Form: {subject}"
            full_message = f"""
New contact form submission:

Name: {name}
Email: {email}
Subject: {subject}

Message:
{message}
            """
            
            send_mail(
                subject=full_subject,
                message=full_message,
                from_email=self.from_email,
                recipient_list=[settings.DEFAULT_FROM_EMAIL],
                fail_silently=False,
            )
            
            logger.info(f"Contact form email sent from {email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send contact form email: {e}")
            return False
