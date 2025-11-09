# CyberMailConnect

A robust Python library for secure email connection testing, validation, and security analysis. Built for security researchers, penetration testers, and bug bounty hunters.

## Overview

CyberMailConnect is a comprehensive toolkit designed to test and analyze email server configurations, validate security implementations, and identify potential vulnerabilities in mail systems. Originally developed for the CyberConnect Mail Bounty program.

## Features

- **Secure Connection Testing**: Test SMTP, IMAP, and POP3 connections with SSL/TLS validation
- **Security Analysis**: Identify weak configurations, outdated protocols, and security misconfigurations
- **Header Analysis**: Deep inspection of email headers for security vulnerabilities
- **SPF/DKIM/DMARC Validation**: Automated email authentication protocol verification
- **Rate Limiting Detection**: Identify and respect rate limiting mechanisms
- **Connection Pool Management**: Efficient handling of multiple concurrent connections
- **Detailed Logging**: Comprehensive logging for security auditing
- **CVE Database Integration**: Check for known vulnerabilities in mail server versions

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```python
from cybermailconnect import MailConnector, SecurityAnalyzer

# Initialize connector
connector = MailConnector(
    host="mail.example.com",
    port=587,
    use_tls=True
)

# Perform security analysis
analyzer = SecurityAnalyzer(connector)
results = analyzer.run_full_scan()

# Print findings
for finding in results.vulnerabilities:
    print(f"[{finding.severity}] {finding.description}")
```

## Use Cases

- **Bug Bounty Research**: Identify security issues in email infrastructure
- **Penetration Testing**: Assess mail server security during authorized engagements
- **Security Auditing**: Validate email security configurations
- **Compliance Testing**: Ensure email systems meet security standards

## Features in Detail

### Connection Security
- TLS/SSL version detection and validation
- Certificate chain verification
- Cipher suite analysis
- Protocol downgrade detection

### Authentication Testing
- Multiple authentication mechanism support (PLAIN, LOGIN, CRAM-MD5, etc.)
- OAuth2 integration
- Rate limiting and lockout detection
- Brute force protection validation

### Header Analysis
- Email spoofing detection
- SPF record validation
- DKIM signature verification
- DMARC policy analysis
- Received header path tracing

### Vulnerability Detection
- Open relay testing
- User enumeration protection
- Information disclosure checks
- Version fingerprinting
- Known CVE detection

## Configuration

Create a `config.yaml` file:

```yaml
target:
  host: mail.example.com
  ports: [25, 465, 587, 993, 995]

security:
  validate_certificates: true
  min_tls_version: "1.2"
  timeout: 30

scanning:
  max_threads: 5
  rate_limit: 10  # requests per second

logging:
  level: INFO
  output: scan_results.log
```

## Examples

See the `examples/` directory for detailed usage examples:

- `basic_connection.py` - Simple connection testing
- `security_scan.py` - Full security analysis
- `header_analysis.py` - Email header inspection
- `auth_testing.py` - Authentication mechanism testing

## Security Considerations

This tool is designed for **authorized security testing only**. Usage against systems without explicit permission is illegal and unethical. Always:

- Obtain written authorization before testing
- Respect rate limits and system resources
- Report findings responsibly
- Follow responsible disclosure practices

## Requirements

- Python 3.8+
- OpenSSL 1.1.1+
- See `requirements.txt` for Python dependencies

## Documentation

Full documentation available in the `docs/` directory:

- [API Reference](docs/api.md)
- [Security Best Practices](docs/security.md)
- [Vulnerability Database](docs/vulnerabilities.md)
- [Troubleshooting Guide](docs/troubleshooting.md)

## Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests for any enhancements.

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors assume no liability for misuse or damage caused by this program. Users are responsible for ensuring they have proper authorization before testing any systems.

## Author

Jakob - Security Researcher
Original development: 2022

## Acknowledgments

Developed as part of the CyberConnect Mail Security Research Program.
