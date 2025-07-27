import re
import os
from typing import List, Dict, Tuple

class SecretDetector:
    def __init__(self):
        self.auto_remediation = []

        self.skip_rules = [
    {
        'match_type': 'filename',
        'value': 'package-lock.json',
        'reason': 'Minified or auto-generated file',
        'suggestion': 'Add package-lock.json to .gitignore if not needed',
    },
    {
        'match_type': 'filename',
        'value': 'highlight.pack.min.js',
        'reason': 'Minified library file',
        'suggestion': 'Add highlight.pack.min.js to .gitignore if not needed',
    },
    {
        'match_type': 'path_contains',
        'value': '/venv/',
        'reason': 'Python virtual environment file',
        'suggestion': 'Exclude venv from Git and scans',
    },
    {
        'match_type': 'path_contains',
        'value': '/.venv/',
        'reason': 'Python virtual environment file',
        'suggestion': 'Exclude .venv from Git and scans',
    },
    {
        'match_type': 'path_contains',
        'value': '/env/',
        'reason': 'Python virtual environment file',
        'suggestion': 'Exclude env from Git and scans',
    },
]

        self.patterns = {
            'aws_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': 'high',
                'description': 'AWS Access Key ID',
                'false_positive_patterns': [r'AKIAIOSFODNN7EXAMPLE', r'AKIAI44QH8DHBEXAMPLE']
            },
            'aws_secret': {
                'pattern': r'(?i)(aws.{0,20}secret.{0,20}[=:\s]["\']?)([A-Za-z0-9/+=]{40})(["\']?)',
                'severity': 'high',
                'description': 'AWS Secret Access Key',
                'extract_group': 2,
                'false_positive_patterns': [
                    r'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                    r'your.{0,10}aws.{0,10}secret',
                    r'example.{0,10}secret',
                    r'<.*secret.*>',
                    r'\{.*secret.*\}'
                ]
            },
            'gcp_key': {
                'pattern': r'"type"\s*:\s*"service_account"',
                'severity': 'high',
                'description': 'GCP Service Account Key',
                'context_required': ['private_key', 'client_email']
            },
            'jwt_token': {
                'pattern': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
                'severity': 'medium',
                'description': 'JWT Token'
            },
            'db_url': {
                'pattern': r'(mongodb|mysql|postgresql|postgres)://[^\s]+',
                'severity': 'high',
                'description': 'Database Connection URL',
                'false_positive_patterns': [
                    r'://localhost',
                    r'://127\.0\.0\.1',
                    r'://0\.0\.0\.0',
                    r'://.*\.local',
                    r'://example\.',
                    r'://test\.',
                    r'://dummy\.',
                    r'://sample\.',
                    r'://.*example.*',
                    r'://.*test.*',
                    r'://.*dummy.*'
                ]
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
                'pattern': r'(?i)(api.{0,10}key.{0,10}[=:\s]["\']?)([A-Za-z0-9_-]{20,})(["\']?)',
                'severity': 'medium',
                'description': 'API Key',
                'extract_group': 2,
                'min_length': 20,
                'false_positive_patterns': [
                    r'your.{0,10}(api.{0,10})?key',
                    r'example.{0,10}key',
                    r'test.{0,10}key',
                    r'sample.{0,10}key',
                    r'dummy.{0,10}key',
                    r'placeholder.{0,10}key',
                    r'your_.*_key',
                    r'<.*key.*>',
                    r'\{.*key.*\}',
                    r'\[.*key.*\]'
                ]
            },
            'oauth_token': {
                'pattern': r'(?i)(oauth.{0,10}token.{0,10}[=:\s]["\']?)([A-Za-z0-9_-]{20,})(["\']?)',
                'severity': 'medium',
                'description': 'OAuth Token',
                'extract_group': 2,
                'min_length': 20,
                'false_positive_patterns': [
                    r'your.{0,10}oauth.{0,10}token',
                    r'example.{0,10}token',
                    r'<.*token.*>',
                    r'\{.*token.*\}'
                ]
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

    def scan_directory(self, directory_path: str, commit_info: Dict = None) -> List[Dict]:
        """Scan a directory for secrets and return findings."""
        findings = []
        
        for root, dirs, files in os.walk(directory_path):
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs]

            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, directory_path)

                if not self._should_scan_file(file_path):
                    continue

                try:
                    file_findings = self.scan_file(file_path, relative_path, commit_info)
                    findings.extend(file_findings)
                except Exception as e:
                    print(f"Error scanning {file_path}: {e}")

        
        return findings

    def scan_file(self, file_path: str, relative_path: str, commit_info: Dict = None) -> List[Dict]:
        """Scan a single file for secrets."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            return findings
        
        for line_num, line in enumerate(lines, 1):
            line_findings = self.scan_line(line, relative_path, line_num, lines, commit_info)
            findings.extend(line_findings)
        
        return findings

    def scan_line(self, line: str, file_path: str, line_num: int, all_lines: List[str], commit_info: Dict = None) -> List[Dict]:
        """Scan a single line for secrets."""
        findings = []
        
        for secret_type, config in self.patterns.items():
            pattern = config['pattern']
            matches = re.finditer(pattern, line, re.IGNORECASE)
            
            for match in matches:
                # Extract the actual secret (use specific group if defined)
                extract_group = config.get('extract_group', 0)
                matched_text = match.group(extract_group)
                
                # Check minimum length requirements
                min_length = config.get('min_length', 0)
                if len(matched_text) < min_length:
                    continue
                
                # Check for false positives
                if self._is_false_positive(matched_text, config.get('false_positive_patterns', [])):
                    continue
                
                # Check if context is required
                if 'context_required' in config:
                    context_text = ' '.join(all_lines[max(0, line_num-3):min(len(all_lines), line_num+2)])
                    if not self._check_context(context_text.lower(), config['context_required']):
                        continue
                
                # Additional context-based filtering for common false positives
                if self._is_documentation_or_example(file_path, line, all_lines, line_num):
                    continue
                
                # Get context lines
                context_before = self._get_context_lines(all_lines, line_num - 1, -2, 0)
                context_after = self._get_context_lines(all_lines, line_num - 1, 1, 3)
                
                finding = {
                    'file_path': file_path,
                    'line_number': line_num,
                    'secret_type': secret_type,
                    'severity': config['severity'],
                    'matched_text': matched_text,
                    'context_before': context_before,
                    'context_after': context_after,
                    'description': config['description']
                }
                
                # Add commit info if available (for deep scan)
                if commit_info:
                    finding.update({
                        'commit_hash': commit_info.get('hash'),
                        'commit_message': commit_info.get('message'),
                        'commit_author': commit_info.get('author'),
                        'commit_date': commit_info.get('date')
                    })
                
                findings.append(finding)
        
        return findings

    def _should_scan_file(self, filename: str) -> bool:
        """Check if a file should be scanned based on its extension."""
        _, ext = os.path.splitext(filename.lower())
        return ext in self.file_extensions or filename.lower() in ['.env', 'dockerfile', 'makefile']

    def _is_false_positive(self, text: str, false_positive_patterns: List[str]) -> bool:
        """Check if the matched text is a known false positive."""
        # Common false positive patterns
        common_false_positives = [
            r'^your_.*',
            r'^example.*',
            r'^test.*',
            r'^sample.*',
            r'^dummy.*',
            r'^placeholder.*',
            r'^<.*>$',
            r'^\{.*\}$',
            r'^\[.*\]$',
            r'.*example.*',
            r'.*placeholder.*',
            r'.*your.*key.*',
            r'.*your.*token.*',
            r'.*your.*secret.*'
        ]
        
        # Check common patterns first
        for pattern in common_false_positives:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        # Check specific patterns
        for pattern in false_positive_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def _is_documentation_or_example(self, file_path: str, line: str, all_lines: List[str], line_num: int) -> bool:
        """Check if the finding is in documentation or example code."""
        # Check file path indicators
        doc_indicators = ['readme', 'doc', 'example', 'sample', 'demo', 'test']
        if any(indicator in file_path.lower() for indicator in doc_indicators):
            return True
        
        # Check surrounding context for documentation patterns
        context_start = max(0, line_num - 5)
        context_end = min(len(all_lines), line_num + 5)
        context_lines = all_lines[context_start:context_end]
        context_text = ' '.join(context_lines).lower()
        
        doc_patterns = [
            r'example',
            r'sample',
            r'replace.*with',
            r'your.*here',
            r'todo',
            r'fixme',
            r'placeholder',
            r'dummy',
            r'#.*example',
            r'//.*example',
            r'<!--.*example',
            r'```',  # Code blocks in markdown
            r'`.*`'  # Inline code in markdown
        ]
        
        for pattern in doc_patterns:
            if re.search(pattern, context_text):
                return True
        
        return False
    
    def _check_context(self, text: str, required_words: List[str]) -> bool:
        """Check if the text contains required context words."""
        return any(word in text for word in required_words)

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

    def _should_scan_file(self, file_path: str) -> bool:
        
        filename = os.path.basename(file_path).lower()
        normalized_path = file_path.replace('\\', '/').lower()

        for rule in self.skip_rules:
            if rule['match_type'] == 'filename' and filename == rule['value']:
                self.auto_remediation.append({
                    'file': file_path,
                    'reason': rule['reason'],
                    'suggestion': rule['suggestion']
                })
                return False
            elif rule['match_type'] == 'path_contains' and rule['value'] in normalized_path:
                self.auto_remediation.append({
                    'file': file_path,
                    'reason': rule['reason'],
                    'suggestion': rule['suggestion']
                })
                return False

        _, ext = os.path.splitext(filename)
        return ext in self.file_extensions or filename in ['.env', 'dockerfile', 'makefile']
