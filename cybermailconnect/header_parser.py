"""
Email header parsing and analysis module.
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from email import message_from_string
from email.header import decode_header
import logging

logger = logging.getLogger(__name__)


@dataclass
class HeaderAnalysis:
    """Results of email header analysis."""
    received_path: List[str] = field(default_factory=list)
    authentication_results: Dict = field(default_factory=dict)
    potential_spoofing: bool = False
    suspicious_headers: List[str] = field(default_factory=list)
    sender_ip: Optional[str] = None
    return_path: Optional[str] = None
    message_id: Optional[str] = None


class HeaderParser:
    """
    Parse and analyze email headers for security issues.

    Identifies spoofing attempts, validates authentication headers,
    and traces email routing paths.
    """

    SUSPICIOUS_PATTERNS = [
        r'X-PHP-Script',
        r'X-Mailer.*PHPMailer',
        r'Content-Type.*multipart/mixed.*boundary=----',
    ]

    def __init__(self):
        """Initialize header parser."""
        self.analysis = HeaderAnalysis()

    def parse(self, raw_headers: str) -> HeaderAnalysis:
        """
        Parse email headers and perform security analysis.

        Args:
            raw_headers: Raw email headers as string

        Returns:
            HeaderAnalysis object with findings
        """
        msg = message_from_string(raw_headers)

        self._extract_received_path(msg)
        self._check_authentication(msg)
        self._detect_spoofing(msg)
        self._find_suspicious_headers(msg)
        self._extract_metadata(msg)

        return self.analysis

    def _extract_received_path(self, msg):
        """Extract the path of servers that handled the email."""
        received_headers = msg.get_all('Received', [])

        for header in received_headers:
            # Extract IP addresses from Received headers
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', header)
            if ip_match:
                ip = ip_match.group(1)
                self.analysis.received_path.append(ip)

                if not self.analysis.sender_ip:
                    self.analysis.sender_ip = ip

    def _check_authentication(self, msg):
        """Check SPF, DKIM, and DMARC authentication results."""
        auth_results = msg.get('Authentication-Results', '')

        if auth_results:
            # Parse authentication results
            if 'spf=pass' in auth_results.lower():
                self.analysis.authentication_results['SPF'] = 'PASS'
            elif 'spf=fail' in auth_results.lower():
                self.analysis.authentication_results['SPF'] = 'FAIL'

            if 'dkim=pass' in auth_results.lower():
                self.analysis.authentication_results['DKIM'] = 'PASS'
            elif 'dkim=fail' in auth_results.lower():
                self.analysis.authentication_results['DKIM'] = 'FAIL'

            if 'dmarc=pass' in auth_results.lower():
                self.analysis.authentication_results['DMARC'] = 'PASS'
            elif 'dmarc=fail' in auth_results.lower():
                self.analysis.authentication_results['DMARC'] = 'FAIL'

    def _detect_spoofing(self, msg):
        """Detect potential email spoofing."""
        from_header = msg.get('From', '')
        return_path = msg.get('Return-Path', '')

        # Check if From and Return-Path domains match
        if from_header and return_path:
            from_domain = self._extract_domain(from_header)
            return_domain = self._extract_domain(return_path)

            if from_domain != return_domain:
                self.analysis.potential_spoofing = True
                self.analysis.suspicious_headers.append(
                    f"From/Return-Path mismatch: {from_domain} vs {return_domain}"
                )

        # Check authentication failures
        if self.analysis.authentication_results.get('SPF') == 'FAIL':
            self.analysis.potential_spoofing = True

    def _find_suspicious_headers(self, msg):
        """Identify suspicious or uncommon headers."""
        for pattern in self.SUSPICIOUS_PATTERNS:
            for header, value in msg.items():
                if re.search(pattern, f"{header}: {value}", re.IGNORECASE):
                    self.analysis.suspicious_headers.append(f"{header}: {value}")

    def _extract_metadata(self, msg):
        """Extract important metadata from headers."""
        self.analysis.return_path = msg.get('Return-Path', '')
        self.analysis.message_id = msg.get('Message-ID', '')

    @staticmethod
    def _extract_domain(email_address: str) -> str:
        """Extract domain from email address."""
        match = re.search(r'@([a-zA-Z0-9.-]+)', email_address)
        return match.group(1) if match else ''

    def generate_report(self) -> str:
        """Generate human-readable analysis report."""
        report = []
        report.append("Email Header Analysis Report")
        report.append("=" * 50)

        if self.analysis.potential_spoofing:
            report.append("\n[!] POTENTIAL SPOOFING DETECTED")

        if self.analysis.authentication_results:
            report.append("\nAuthentication Results:")
            for method, result in self.analysis.authentication_results.items():
                status = "✓" if result == "PASS" else "✗"
                report.append(f"  {status} {method}: {result}")

        if self.analysis.received_path:
            report.append(f"\nEmail Path ({len(self.analysis.received_path)} hops):")
            for i, ip in enumerate(self.analysis.received_path[:5], 1):
                report.append(f"  {i}. {ip}")

        if self.analysis.suspicious_headers:
            report.append("\nSuspicious Headers:")
            for header in self.analysis.suspicious_headers:
                report.append(f"  - {header}")

        return "\n".join(report)
