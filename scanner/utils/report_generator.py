import json
import csv
import io
import os
from datetime import datetime
from typing import List, Dict, Optional
from django.template.loader import render_to_string
from django.http import HttpResponse
from django.utils import timezone
import tempfile
import zipfile
from collections import Counter, defaultdict

try:
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
    HTML = CSS = FontConfiguration = None
    print("WeasyPrint not available. PDF generation disabled.")

try:
    import xlsxwriter
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False
    xlsxwriter = None
    print("xlsxwriter not available. Excel export disabled.")

class ReportGenerator:
    def __init__(self, scan_session, findings: List[Dict]):
        self.scan_session = scan_session
        self.findings = findings
        self.severity_counts = self._calculate_severity_counts()
        self.findings_by_type = self._group_findings_by_type()
        self.findings_by_file = self._group_findings_by_file()
        self.statistics = self._calculate_statistics()
    
    def _calculate_severity_counts(self) -> Dict[str, int]:
        """Calculate counts for each severity level."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in self.findings:
            severity = finding.get('severity', 'low').lower()
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _group_findings_by_type(self) -> Dict[str, List[Dict]]:
        """Group findings by their type."""
        grouped = defaultdict(list)
        for finding in self.findings:
            finding_type = finding.get('type', 'Unknown')
            grouped[finding_type].append(finding)
        return dict(grouped)
    
    def _group_findings_by_file(self) -> Dict[str, List[Dict]]:
        """Group findings by file path."""
        grouped = defaultdict(list)
        for finding in self.findings:
            file_path = finding.get('file_path', 'Unknown')
            grouped[file_path].append(finding)
        return dict(grouped)
    
    def _calculate_statistics(self) -> Dict:
        """Calculate comprehensive statistics."""
        total_files_with_issues = len(self.findings_by_file)
        most_vulnerable_files = sorted(
            self.findings_by_file.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )[:10]
        
        type_distribution = Counter(f.get('type', 'Unknown') for f in self.findings)
        
        return {
            'total_findings': len(self.findings),
            'total_files_with_issues': total_files_with_issues,
            'most_vulnerable_files': most_vulnerable_files,
            'type_distribution': dict(type_distribution),
            'scan_duration': self._calculate_scan_duration(),
            'risk_score': self._calculate_risk_score(),
        }
    
    def _calculate_scan_duration(self) -> Optional[str]:
        """Calculate scan duration if available."""
        if self.scan_session.completed_at and self.scan_session.created_at:
            duration = self.scan_session.completed_at - self.scan_session.created_at
            return str(duration).split('.')[0]  # Remove microseconds
        return None
    
    def _calculate_risk_score(self) -> int:
        """Calculate overall risk score (0-100)."""
        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        total_score = sum(self.severity_counts[sev] * weight for sev, weight in weights.items())
        max_possible = len(self.findings) * 10 if self.findings else 1
        return min(100, int((total_score / max_possible) * 100))
    
    def generate_html_report(self) -> str:
        """Generate comprehensive HTML report."""
        context = {
            'scan_session': self.scan_session,
            'findings': self.findings,
            'severity_counts': self.severity_counts,
            'findings_by_type': self.findings_by_type,
            'findings_by_file': self.findings_by_file,
            'statistics': self.statistics,
            'generated_at': timezone.now(),
            'has_critical': self.severity_counts['critical'] > 0,
            'has_high': self.severity_counts['high'] > 0,
        }
        
        return render_to_string('scanner/reports/detailed_html_report.html', context)
    
    def generate_pdf_report(self) -> bytes:
        """Generate professional PDF report."""
        if not WEASYPRINT_AVAILABLE:
            raise Exception("WeasyPrint not available. Install with: pip install weasyprint")
        
        html_content = self.generate_html_report()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
            f.write(html_content)
            html_file_path = f.name
        
        try:
            html_doc = HTML(filename=html_file_path)
            css = CSS(string=self._get_pdf_styles())
            return html_doc.write_pdf(stylesheets=[css])
        finally:
            try:
                os.unlink(html_file_path)
            except:
                pass
    
    def _get_pdf_styles(self) -> str:
        """Get comprehensive PDF styles."""
        return '''
            @page {
                margin: 0.75in;
                size: A4;
                @top-center {
                    content: "RepoGuardian Security Report - " string(repo-name);
                    font-size: 10px;
                    color: #666;
                    border-bottom: 1px solid #ddd;
                    padding-bottom: 5px;
                }
                @bottom-center {
                    content: "Page " counter(page) " of " counter(pages) " | Generated: " string(generated-date);
                    font-size: 9px;
                    color: #666;
                    border-top: 1px solid #ddd;
                    padding-top: 5px;
                }
            }
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                line-height: 1.5;
                color: #333;
                font-size: 11px;
            }
            .header { text-align: center; margin-bottom: 30px; }
            .logo { font-size: 24px; color: #007bff; font-weight: bold; }
            .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }
            .summary-card { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
            .severity-critical { color: #8b0000; font-weight: bold; }
            .severity-high { color: #dc3545; font-weight: bold; }
            .severity-medium { color: #fd7e14; font-weight: bold; }
            .severity-low { color: #28a745; }
            .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; page-break-inside: avoid; }
            .finding.critical { border-left: 4px solid #8b0000; }
            .finding.high { border-left: 4px solid #dc3545; }
            .finding.medium { border-left: 4px solid #fd7e14; }
            .finding.low { border-left: 4px solid #28a745; }
            .code-block { background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 9px; }
            .risk-score { font-size: 18px; font-weight: bold; }
            .risk-high { color: #dc3545; }
            .risk-medium { color: #fd7e14; }
            .risk-low { color: #28a745; }
            table { width: 100%; border-collapse: collapse; margin: 10px 0; }
            th, td { padding: 8px; border: 1px solid #ddd; text-align: left; }
            th { background: #f8f9fa; font-weight: bold; }
        '''
    
    def generate_json_report(self) -> str:
        """Generate comprehensive JSON report."""
        report_data = {
            'metadata': {
                'report_version': '2.0',
                'generated_at': timezone.now().isoformat(),
                'generator': 'RepoGuardian v2.0',
            },
            'scan_session': {
                'id': str(self.scan_session.id),
                'scan_type': self.scan_session.scan_type,
                'repository_url': getattr(self.scan_session, 'repository_url', None),
                'status': self.scan_session.status,
                'created_at': self.scan_session.created_at.isoformat(),
                'completed_at': self.scan_session.completed_at.isoformat() if self.scan_session.completed_at else None,
                'total_files_scanned': getattr(self.scan_session, 'total_files_scanned', 0),
                'secrets_found': getattr(self.scan_session, 'secrets_found', 0),
            },
            'summary': {
                'total_findings': len(self.findings),
                'severity_counts': self.severity_counts,
                'risk_score': self.statistics['risk_score'],
                'scan_duration': self.statistics['scan_duration'],
            },
            'statistics': self.statistics,
            'findings_by_type': {k: len(v) for k, v in self.findings_by_type.items()},
            'findings_by_file': {k: len(v) for k, v in self.findings_by_file.items()},
            'findings': self.findings,
        }
        
        return json.dumps(report_data, indent=2, default=str, ensure_ascii=False)
    
    def generate_csv_report(self) -> str:
        """Generate CSV report."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow([
            'Finding ID', 'Type', 'Severity', 'File Path', 'Line Number',
            'Description', 'Code Snippet', 'Recommendation', 'Confidence'
        ])
        
        # Write findings
        for i, finding in enumerate(self.findings, 1):
            writer.writerow([
                f"F{i:04d}",
                finding.get('type', 'Unknown'),
                finding.get('severity', 'low').upper(),
                finding.get('file_path', 'Unknown'),
                finding.get('line_number', 'N/A'),
                finding.get('description', 'No description'),
                finding.get('code_snippet', '').replace('\n', ' '),
                finding.get('recommendation', 'Review and remediate'),
                finding.get('confidence', 'Medium')
            ])
        
        return output.getvalue()
    
    def generate_excel_report(self) -> bytes:
        """Generate Excel report with multiple sheets."""
        if not EXCEL_AVAILABLE:
            raise Exception("xlsxwriter not available. Install with: pip install xlsxwriter")
        
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {'in_memory': True})
        
        # Define formats
        header_format = workbook.add_format({'bold': True, 'bg_color': '#4472C4', 'font_color': 'white'})
        critical_format = workbook.add_format({'bg_color': '#8B0000', 'font_color': 'white'})
        high_format = workbook.add_format({'bg_color': '#DC3545', 'font_color': 'white'})
        medium_format = workbook.add_format({'bg_color': '#FD7E14', 'font_color': 'white'})
        low_format = workbook.add_format({'bg_color': '#28A745', 'font_color': 'white'})
        
        # Summary sheet
        summary_sheet = workbook.add_worksheet('Summary')
        self._write_excel_summary(summary_sheet, header_format)
        
        # Findings sheet
        findings_sheet = workbook.add_worksheet('Findings')
        self._write_excel_findings(findings_sheet, header_format, {
            'critical': critical_format, 'high': high_format,
            'medium': medium_format, 'low': low_format
        })
        
        # Statistics sheet
        stats_sheet = workbook.add_worksheet('Statistics')
        self._write_excel_statistics(stats_sheet, header_format)
        
        workbook.close()
        output.seek(0)
        return output.read()
    
    def _write_excel_summary(self, worksheet, header_format):
        """Write summary data to Excel sheet."""
        worksheet.write('A1', 'Scan Summary', header_format)
        worksheet.write('A3', 'Scan ID:')
        worksheet.write('B3', str(self.scan_session.id))
        worksheet.write('A4', 'Total Findings:')
        worksheet.write('B4', len(self.findings))
        worksheet.write('A5', 'Risk Score:')
        worksheet.write('B5', f"{self.statistics['risk_score']}/100")
        
        # Severity breakdown
        worksheet.write('A7', 'Severity Breakdown', header_format)
        row = 8
        for severity, count in self.severity_counts.items():
            worksheet.write(row, 0, severity.title())
            worksheet.write(row, 1, count)
            row += 1
    
    def _write_excel_findings(self, worksheet, header_format, severity_formats):
        """Write findings data to Excel sheet."""
        headers = ['ID', 'Type', 'Severity', 'File', 'Line', 'Description', 'Recommendation']
        for col, header in enumerate(headers):
            worksheet.write(0, col, header, header_format)
        
        for row, finding in enumerate(self.findings, 1):
            severity = finding.get('severity', 'low').lower()
            row_format = severity_formats.get(severity)
            
            worksheet.write(row, 0, f"F{row:04d}")
            worksheet.write(row, 1, finding.get('type', 'Unknown'))
            worksheet.write(row, 2, severity.upper(), row_format)
            worksheet.write(row, 3, finding.get('file_path', 'Unknown'))
            worksheet.write(row, 4, finding.get('line_number', 'N/A'))
            worksheet.write(row, 5, finding.get('description', 'No description'))
            worksheet.write(row, 6, finding.get('recommendation', 'Review and remediate'))
    
    def _write_excel_statistics(self, worksheet, header_format):
        """Write statistics to Excel sheet."""
        worksheet.write('A1', 'Detailed Statistics', header_format)
        
        # Most vulnerable files
        worksheet.write('A3', 'Most Vulnerable Files', header_format)
        worksheet.write('A4', 'File Path', header_format)
        worksheet.write('B4', 'Issues Count', header_format)
        
        for row, (file_path, findings) in enumerate(self.statistics['most_vulnerable_files'], 5):
            worksheet.write(row, 0, file_path)
            worksheet.write(row, 1, len(findings))
    
    def generate_comprehensive_zip(self) -> bytes:
        """Generate ZIP file with all report formats."""
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add JSON report
            zip_file.writestr('report.json', self.generate_json_report())
            
            # Add CSV report
            zip_file.writestr('findings.csv', self.generate_csv_report())
            
            # Add HTML report
            zip_file.writestr('report.html', self.generate_html_report())
            
            # Add PDF if available
            if WEASYPRINT_AVAILABLE:
                try:
                    zip_file.writestr('report.pdf', self.generate_pdf_report())
                except Exception as e:
                    print(f"PDF generation failed: {e}")
            
            # Add Excel if available
            if EXCEL_AVAILABLE:
                try:
                    zip_file.writestr('report.xlsx', self.generate_excel_report())
                except Exception as e:
                    print(f"Excel generation failed: {e}")
        
        zip_buffer.seek(0)
        return zip_buffer.read()
    
    def get_response(self, format_type: str, filename: str = None) -> HttpResponse:
        """Generate response for any format type."""
        if not filename:
            timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
            filename = f"repoguardian_scan_{self.scan_session.id}_{timestamp}"
        
        format_handlers = {
            'pdf': (self.generate_pdf_report, 'application/pdf', '.pdf'),
            'json': (self.generate_json_report, 'application/json', '.json'),
            'csv': (self.generate_csv_report, 'text/csv', '.csv'),
            'excel': (self.generate_excel_report, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', '.xlsx'),
            'zip': (self.generate_comprehensive_zip, 'application/zip', '.zip'),
        }
        
        if format_type not in format_handlers:
            raise ValueError(f"Unsupported format: {format_type}")
        
        generator, content_type, extension = format_handlers[format_type]
        
        try:
            content = generator()
            response = HttpResponse(content, content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{filename}{extension}"'
            response['Content-Length'] = len(content)
            return response
        except Exception as e:
            raise Exception(f"Failed to generate {format_type.upper()} report: {str(e)}")
