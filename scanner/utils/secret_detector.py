import re
import os
from typing import List, Dict, Tuple

class SecretDetector:
    def __init__(self):
        self.patterns = {
            'aws_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': 'high',
                'description': 'AWS Access Key ID'
            },
            'aws_secret': {
                'pattern': r'[A-Za-z0-9/+=]{40}',
                'severity': 'high',
                'description': 'AWS Secret Access Key',
                'context_required': ['aws', 'secret', 'key']
            },
            'gcp_key': {
                'pattern': r'"type":\s*"service_account"',
                'severity': 'high',
                'description': 'GCP Service Account Key'
            },
            'jwt_token': {
                'pattern': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
                'severity': 'medium',
                'description': 'JWT Token'
            },
            'db_url': {
                'pattern': r'(mongodb|mysql|postgresql|postgres)://[^\s]+',
                'severity': 'high',
                'description': 'Database Connection URL'
            },
            'email_password': {
                'pattern': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[^\s]+',
                'severity': 'medium',
                'description': 'Email with Password'
            },
            'private_key': {
                'pattern': r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
                'severity': 'high',
                'description': 'Private Key'
            },
            'api_key': {
                'pattern': r'[aA][pP][iI][_]?[kK][eE][yY][\'"\s]*[:=][\'"\s]*[A-Za-z0-9_-]{20,}',
                'severity': 'medium',
                'description': 'API Key'
            },
            'oauth_token': {
                'pattern': r'[oO][aA][uU][tT][hH][_]?[tT][oO][kK][eE][nN][\'"\s]*[:=][\'"\s]*[A-Za-z0-9_-]{20,}',
                'severity': 'medium',
                'description': 'OAuth Token'
            },
            'ssh_key': {
                'pattern': r'ssh-rsa [A-Za-z0-9+/]+[=]{0,3}',
                'severity': 'high',
                'description': 'SSH Public Key'
            }
        }
        
        self.file_extensions = {
            '.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.rs', '.cpp', '.c',
            '.h', '.hpp', '.cs', '.vb', '.sql', '.sh', '.bash', '.zsh', '.fish',
            '.yml', '.yaml', '.json', '.xml', '.ini', '.cfg', '.conf', '.env',
            '.properties', '.toml', '.md', '.txt', '.log'
        }
        
        self.excluded_dirs = {
            '.git', '__pycache__', 'node_modules', '.venv', 'venv', 'env',
            '.pytest_cache', '.mypy_cache', 'dist', 'build', '.idea', '.vscode'
        }

    def scan_directory(self, directory_path: str) -> List[Dict]:
        """Scan a directory for secrets and return findings."""
        findings = []
        
        for root, dirs, files in os.walk(directory_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, directory_path)
                
                # Skip binary files and files without relevant extensions
                if not self._should_scan_file(file):
                    continue
                
                try:
                    file_findings = self.scan_file(file_path, relative_path)
                    findings.extend(file_findings)
                except Exception as e:
                    print(f"Error scanning {file_path}: {e}")
                    continue
        
        return findings

    def scan_file(self, file_path: str, relative_path: str) -> List[Dict]:
        """Scan a single file for secrets."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            return findings
        
        for line_num, line in enumerate(lines, 1):
            line_findings = self.scan_line(line, relative_path, line_num, lines)
            findings.extend(line_findings)
        
        return findings

    def scan_line(self, line: str, file_path: str, line_num: int, all_lines: List[str]) -> List[Dict]:
        """Scan a single line for secrets."""
        findings = []
        
        for secret_type, config in self.patterns.items():
            pattern = config['pattern']
            matches = re.finditer(pattern, line, re.IGNORECASE)
            
            for match in matches:
                # Check if context is required
                if 'context_required' in config:
                    if not self._check_context(line.lower(), config['context_required']):
                        continue
                
                # Get context lines
                context_before = self._get_context_lines(all_lines, line_num - 1, -2, 0)
                context_after = self._get_context_lines(all_lines, line_num - 1, 1, 3)
                
                finding = {
                    'file_path': file_path,
                    'line_number': line_num,
                    'secret_type': secret_type,
                    'severity': config['severity'],
                    'matched_text': match.group(),
                    'context_before': context_before,
                    'context_after': context_after,
                    'description': config['description']
                }
                
                findings.append(finding)
        
        return findings

    def _should_scan_file(self, filename: str) -> bool:
        """Check if a file should be scanned based on its extension."""
        _, ext = os.path.splitext(filename.lower())
        return ext in self.file_extensions or filename.lower() in ['.env', 'dockerfile', 'makefile']

    def _check_context(self, line: str, required_words: List[str]) -> bool:
        """Check if the line contains required context words."""
        return any(word in line for word in required_words)

    def _get_context_lines(self, lines: List[str], current_line: int, start_offset: int, end_offset: int) -> str:
        """Get context lines around the current line."""
        start_idx = max(0, current_line + start_offset)
        end_idx = min(len(lines), current_line + end_offset)
        
        context_lines = []
        for i in range(start_idx, end_idx):
            if i != current_line:
                context_lines.append(lines[i].rstrip())
        
        return '\n'.join(context_lines)

    def get_severity_score(self, findings: List[Dict]) -> Dict[str, int]:
        """Calculate severity scores from findings."""
        scores = {'high': 0, 'medium': 0, 'low': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'low')
            scores[severity] += 1
        
        return scores
