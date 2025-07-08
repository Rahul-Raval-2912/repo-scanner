import json
import os
from datetime import datetime
from typing import List, Dict
from django.template.loader import render_to_string
from django.http import HttpResponse
#from weasyprint import HTML, CSS
#from weasyprint.text.fonts import FontConfiguration
import tempfile

try:
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration
    WEASYPRINT_AVAILABLE = True
except Exception as e:
    WEASYPRINT_AVAILABLE = False
    HTML = CSS = FontConfiguration = None
    print("WeasyPrint is not available. PDF generation will be disabled.")

class ReportGenerator:
    def __init__(self, scan_session, findings: List[Dict]):
        self.scan_session = scan_session
        self.findings = findings
        self.severity_counts = self._calculate_severity_counts()
    
    def _calculate_severity_counts(self) -> Dict[str, int]:
        """Calculate counts for each severity level."""
        counts = {'high': 0, 'medium': 0, 'low': 0}
        for finding in self.findings:
            severity = finding.get('severity', 'low')
            counts[severity] += 1
        return counts
    
    def generate_html_report(self) -> str:
        """Generate HTML report content."""
        context = {
            'scan_session': self.scan_session,
            'findings': self.findings,
            'severity_counts': self.severity_counts,
            'total_findings': len(self.findings),
            'generated_at': datetime.now(),
        }
        
        return render_to_string('scanner/reports/html_report.html', context)
    
    def generate_pdf_report(self) -> bytes:
        """Generate PDF report and return as bytes."""
        html_content = self.generate_html_report()
        
        # Create temporary HTML file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            f.write(html_content)
            html_file_path = f.name
        
        try:
            # Generate PDF
            font_config = FontConfiguration()
            html_doc = HTML(filename=html_file_path)
            css = CSS(string='''
                @page {
                    margin: 1in;
                    @top-center {
                        content: "RepoGuardian Security Scan Report";
                        font-size: 12px;
                        color: #666;
                    }
                    @bottom-center {
                        content: "Page " counter(page) " of " counter(pages);
                        font-size: 10px;
                        color: #666;
                    }
                }
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }
                .severity-high { color: #dc3545; }
                .severity-medium { color: #fd7e14; }
                .severity-low { color: #28a745; }
                .finding-card {
                    border: 1px solid #ddd;
                    margin-bottom: 15px;
                    padding: 15px;
                    border-radius: 5px;
                }
                .code-block {
                    background-color: #f8f9fa;
                    padding: 10px;
                    border-radius: 3px;
                    font-family: monospace;
                    font-size: 12px;
                    white-space: pre-wrap;
                }
            ''', font_config=font_config)
            
            pdf_bytes = html_doc.write_pdf(stylesheets=[css], font_config=font_config)
            return pdf_bytes
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(html_file_path)
            except:
                pass
    
    def generate_json_report(self) -> str:
        """Generate JSON report."""
        report_data = {
            'scan_session': {
                'id': str(self.scan_session.id),
                'scan_type': self.scan_session.scan_type,
                'repository_url': self.scan_session.repository_url,
                'status': self.scan_session.status,
                'created_at': self.scan_session.created_at.isoformat(),
                'completed_at': self.scan_session.completed_at.isoformat() if self.scan_session.completed_at else None,
                'total_files_scanned': self.scan_session.total_files_scanned,
                'secrets_found': self.scan_session.secrets_found,
            },
            'summary': {
                'total_findings': len(self.findings),
                'severity_counts': self.severity_counts,
            },
            'findings': self.findings,
            'generated_at': datetime.now().isoformat(),
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def get_pdf_response(self, filename: str = None) -> HttpResponse:
        """Generate PDF response for download."""
        if not filename:
            filename = f"security_scan_{self.scan_session.id}.pdf"
        
        pdf_bytes = self.generate_pdf_report()
        
        response = HttpResponse(pdf_bytes, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    
    def get_json_response(self, filename: str = None) -> HttpResponse:
        """Generate JSON response for download."""
        if not filename:
            filename = f"security_scan_{self.scan_session.id}.json"
        
        json_content = self.generate_json_report()
        
        response = HttpResponse(json_content, content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
