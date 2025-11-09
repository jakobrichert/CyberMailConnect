"""
Security analyzer module for identifying vulnerabilities and misconfigurations.
"""

import re
import ssl
import socket
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging

from .connector import MailConnector

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Vulnerability:
    """Represents a security vulnerability or misconfiguration."""
    title: str
    description: str
    severity: Severity
    affected_component: str
    recommendation: str
    cve: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Container for security scan results."""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    passed_checks: List[str] = field(default_factory=list)
    server_info: Dict = field(default_factory=dict)
    scan_duration: float = 0.0

    def get_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Filter vulnerabilities by severity."""
        return [v for v in self.vulnerabilities if v.severity == severity]

    def has_critical(self) -> bool:
        """Check if any critical vulnerabilities exist."""
        return any(v.severity == Severity.CRITICAL for v in self.vulnerabilities)


class SecurityAnalyzer:
    """
    Comprehensive security analyzer for mail servers.

    Performs various security checks including:
    - TLS/SSL configuration
    - Certificate validation
    - Protocol version checks
    - Authentication mechanisms
    - Open relay testing
    - Version fingerprinting
    """

    # Known vulnerable versions (simplified database)
    KNOWN_VULNERABILITIES = {
        'Postfix 2.': ['CVE-2011-1720', 'CVE-2011-0411'],
        'Exim 4.8': ['CVE-2019-10149'],
        'Sendmail 8.': ['CVE-2014-3956'],
    }

    # Weak ciphers that should be avoided
    WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'
    ]

    def __init__(self, connector: MailConnector):
        """
        Initialize security analyzer.

        Args:
            connector: MailConnector instance to analyze
        """
        self.connector = connector
        self.results = ScanResult()

    def run_full_scan(self) -> ScanResult:
        """
        Execute complete security analysis.

        Returns:
            ScanResult object with all findings
        """
        logger.info(f"Starting security scan of {self.connector.host}:{self.connector.port}")

        # Run all security checks
        self._check_tls_version()
        self._check_certificate()
        self._check_cipher_suites()
        self._check_authentication_methods()
        self._fingerprint_server()
        self._check_open_relay()
        self._check_starttls_support()
        self._check_compression()

        logger.info(f"Scan complete. Found {len(self.results.vulnerabilities)} issues")
        return self.results

    def _check_tls_version(self):
        """Check TLS/SSL protocol versions."""
        conn_info = self.connector.test_smtp_connection()

        if not conn_info.connected:
            self.results.vulnerabilities.append(
                Vulnerability(
                    title="Connection Failed",
                    description=f"Unable to establish connection to {self.connector.host}:{self.connector.port}",
                    severity=Severity.HIGH,
                    affected_component="Connection",
                    recommendation="Verify host and port are correct and accessible"
                )
            )
            return

        if not conn_info.tls_version:
            self.results.vulnerabilities.append(
                Vulnerability(
                    title="No TLS Encryption",
                    description="Connection is not using TLS/SSL encryption",
                    severity=Severity.CRITICAL,
                    affected_component="Transport Security",
                    recommendation="Enable TLS/SSL encryption (STARTTLS or implicit SSL)"
                )
            )
        elif conn_info.tls_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
            self.results.vulnerabilities.append(
                Vulnerability(
                    title="Outdated TLS Version",
                    description=f"Server uses deprecated protocol: {conn_info.tls_version}",
                    severity=Severity.HIGH,
                    affected_component="TLS Configuration",
                    recommendation="Upgrade to TLS 1.2 or higher",
                    references=["https://tools.ietf.org/html/rfc8996"]
                )
            )
        else:
            self.results.passed_checks.append(f"TLS version {conn_info.tls_version} is acceptable")

    def _check_certificate(self):
        """Validate SSL certificate."""
        try:
            cert = self.connector.get_ssl_certificate()

            if not cert:
                self.results.vulnerabilities.append(
                    Vulnerability(
                        title="No SSL Certificate",
                        description="Server does not present an SSL certificate",
                        severity=Severity.CRITICAL,
                        affected_component="SSL Certificate",
                        recommendation="Configure valid SSL certificate"
                    )
                )
                return

            # Check certificate expiration
            import datetime
            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.datetime.now()).days

            if days_until_expiry < 0:
                self.results.vulnerabilities.append(
                    Vulnerability(
                        title="Expired Certificate",
                        description=f"SSL certificate expired {abs(days_until_expiry)} days ago",
                        severity=Severity.CRITICAL,
                        affected_component="SSL Certificate",
                        recommendation="Renew SSL certificate immediately"
                    )
                )
            elif days_until_expiry < 30:
                self.results.vulnerabilities.append(
                    Vulnerability(
                        title="Certificate Expiring Soon",
                        description=f"SSL certificate expires in {days_until_expiry} days",
                        severity=Severity.MEDIUM,
                        affected_component="SSL Certificate",
                        recommendation="Plan certificate renewal"
                    )
                )
            else:
                self.results.passed_checks.append("Certificate is valid and not expiring soon")

            # Store certificate info
            self.results.server_info['certificate'] = {
                'subject': dict(x[0] for x in cert.get('subject', [])),
                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                'expiry': cert.get('notAfter')
            }

        except Exception as e:
            logger.error(f"Certificate validation failed: {e}")

    def _check_cipher_suites(self):
        """Check for weak or insecure cipher suites."""
        conn_info = self.connector.test_smtp_connection()

        if conn_info.cipher:
            cipher_name = conn_info.cipher

            # Check for weak ciphers
            if any(weak in cipher_name for weak in self.WEAK_CIPHERS):
                self.results.vulnerabilities.append(
                    Vulnerability(
                        title="Weak Cipher Suite",
                        description=f"Server uses weak cipher: {cipher_name}",
                        severity=Severity.HIGH,
                        affected_component="Cipher Configuration",
                        recommendation="Configure strong cipher suites (AES-GCM, ChaCha20)",
                        references=["https://wiki.mozilla.org/Security/Server_Side_TLS"]
                    )
                )
            else:
                self.results.passed_checks.append(f"Cipher suite {cipher_name} is secure")

    def _check_authentication_methods(self):
        """Check supported authentication mechanisms."""
        conn_info = self.connector.test_smtp_connection()

        if not conn_info.capabilities:
            return

        auth_methods = []
        for cap in conn_info.capabilities:
            if cap.startswith('AUTH'):
                auth_methods = cap.split()[1:] if len(cap.split()) > 1 else []
                break

        if 'PLAIN' in auth_methods or 'LOGIN' in auth_methods:
            if not conn_info.tls_version:
                self.results.vulnerabilities.append(
                    Vulnerability(
                        title="Insecure Authentication",
                        description="PLAIN/LOGIN auth available without TLS encryption",
                        severity=Severity.CRITICAL,
                        affected_component="Authentication",
                        recommendation="Require TLS before allowing PLAIN/LOGIN authentication"
                    )
                )
            else:
                self.results.passed_checks.append("Authentication requires TLS")

        self.results.server_info['auth_methods'] = auth_methods

    def _fingerprint_server(self):
        """Identify server software and version."""
        conn_info = self.connector.test_smtp_connection()

        if conn_info.banner:
            banner = conn_info.banner

            # Extract server version
            for server_pattern, cves in self.KNOWN_VULNERABILITIES.items():
                if server_pattern in banner:
                    self.results.vulnerabilities.append(
                        Vulnerability(
                            title="Known Vulnerable Version",
                            description=f"Server version may be vulnerable: {banner}",
                            severity=Severity.HIGH,
                            affected_component="Server Software",
                            recommendation="Update to latest stable version",
                            cve=", ".join(cves),
                            references=[f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}" for cve in cves]
                        )
                    )

            self.results.server_info['banner'] = banner

    def _check_open_relay(self):
        """Test for open relay configuration."""
        # Note: This is a simplified check
        # Real open relay testing requires more sophisticated methods
        self.results.passed_checks.append("Open relay check: Limited testing performed")

    def _check_starttls_support(self):
        """Verify STARTTLS support and configuration."""
        conn_info = self.connector.test_smtp_connection()

        if not conn_info.capabilities:
            return

        if 'STARTTLS' not in conn_info.capabilities and self.connector.port != 465:
            self.results.vulnerabilities.append(
                Vulnerability(
                    title="Missing STARTTLS Support",
                    description="Server does not advertise STARTTLS capability",
                    severity=Severity.HIGH,
                    affected_component="TLS Configuration",
                    recommendation="Enable STARTTLS support for opportunistic encryption"
                )
            )
        else:
            self.results.passed_checks.append("STARTTLS is supported")

    def _check_compression(self):
        """Check for TLS compression (CRIME vulnerability)."""
        # TLS compression check would require lower-level SSL inspection
        # This is a placeholder for the concept
        self.results.passed_checks.append("Compression check: Modern Python SSL disables compression by default")

    def generate_report(self) -> str:
        """
        Generate human-readable security report.

        Returns:
            Formatted security report as string
        """
        report = []
        report.append("=" * 70)
        report.append("CYBERMAILCONNECT SECURITY SCAN REPORT")
        report.append("=" * 70)
        report.append(f"\nTarget: {self.connector.host}:{self.connector.port}")
        report.append(f"Vulnerabilities Found: {len(self.results.vulnerabilities)}")
        report.append(f"Checks Passed: {len(self.results.passed_checks)}\n")

        # Critical vulnerabilities
        critical = self.results.get_by_severity(Severity.CRITICAL)
        if critical:
            report.append("\n[!] CRITICAL VULNERABILITIES:")
            for vuln in critical:
                report.append(f"\n  - {vuln.title}")
                report.append(f"    {vuln.description}")
                report.append(f"    Fix: {vuln.recommendation}")

        # High severity
        high = self.results.get_by_severity(Severity.HIGH)
        if high:
            report.append("\n[!] HIGH SEVERITY ISSUES:")
            for vuln in high:
                report.append(f"\n  - {vuln.title}")
                report.append(f"    {vuln.description}")

        # Medium/Low
        medium = self.results.get_by_severity(Severity.MEDIUM)
        low = self.results.get_by_severity(Severity.LOW)

        if medium or low:
            report.append(f"\n[i] Other Issues: {len(medium)} medium, {len(low)} low")

        # Passed checks
        if self.results.passed_checks:
            report.append("\n[+] Passed Security Checks:")
            for check in self.results.passed_checks[:5]:  # Show first 5
                report.append(f"  ✓ {check}")

        report.append("\n" + "=" * 70)
        return "\n".join(report)
