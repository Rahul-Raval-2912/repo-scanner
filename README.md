# RepoGuardian 🛡️

A Django-based repository security scanner that detects secrets, vulnerabilities, and security issues in your codebase.

## Features

- **Secret Detection**: Scans for API keys, passwords, tokens, and other sensitive data
- **Real-time Scanning**: Automated security analysis of repositories
- **Email Notifications**: Instant alerts for critical security findings
- **Severity Classification**: Issues categorized as Critical, High, Medium, or Low
- **Web Dashboard**: User-friendly interface to view scan results
- **Multi-format Support**: Scans various file types and programming languages

## Quick Start

### Prerequisites

- Python 3.8+
- Django 4.0+
- Git

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd repo-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure settings:
```bash
cp settings.example.py settings.py
# Edit settings.py with your configuration
```

4. Run migrations:
```bash
python manage.py migrate
```

5. Start the server:
```bash
python manage.py runserver
```

## Configuration

### Email Settings
```python
DEFAULT_FROM_EMAIL = 'noreply@repoguardian.com'
ADMIN_EMAIL = 'admin@repoguardian.com'
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
```

### Security Settings
```python
ALLOWED_HOSTS = ['your-domain.com']
SECURE_SSL_REDIRECT = True  # For HTTPS
```

## Usage

1. **Start a Scan**: Upload or connect your repository
2. **Monitor Progress**: Track scan status in real-time
3. **Review Results**: Analyze findings by severity level
4. **Take Action**: Address critical issues immediately

## API Endpoints

- `POST /api/scan/` - Start new scan
- `GET /api/scan/{id}/` - Get scan results
- `GET /api/scan/{id}/status/` - Check scan status

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues and questions:
- Create an issue on GitHub
- Contact: support@repoguardian.com

---

**⚠️ Security Notice**: This tool is designed to help identify security issues. Always review findings manually and follow security best practices.