"""
Mail connector module for establishing and managing secure email connections.
"""

import ssl
import socket
import smtplib
import imaplib
import poplib
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ConnectionInfo:
    """Store connection information and results."""
    host: str
    port: int
    protocol: str
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    certificate: Optional[Dict] = None
    connected: bool = False
    banner: Optional[str] = None
    capabilities: List[str] = None


class MailConnector:
    """
    Main connector class for establishing secure email server connections.

    Supports SMTP, IMAP, and POP3 protocols with comprehensive TLS/SSL support.
    """

    SMTP_PORTS = [25, 465, 587, 2525]
    IMAP_PORTS = [143, 993]
    POP3_PORTS = [110, 995]

    def __init__(
        self,
        host: str,
        port: int = 587,
        use_tls: bool = True,
        verify_cert: bool = True,
        timeout: int = 30,
        min_tls_version: str = "TLSv1_2"
    ):
        """
        Initialize mail connector.

        Args:
            host: Mail server hostname
            port: Port number
            use_tls: Enable TLS/SSL
            verify_cert: Verify SSL certificates
            timeout: Connection timeout in seconds
            min_tls_version: Minimum TLS version (TLSv1_2, TLSv1_3)
        """
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.verify_cert = verify_cert
        self.timeout = timeout
        self.min_tls_version = min_tls_version
        self.connection_info = None

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with security settings."""
        context = ssl.create_default_context()

        if not self.verify_cert:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # Set minimum TLS version
        if self.min_tls_version == "TLSv1_3":
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        elif self.min_tls_version == "TLSv1_2":
            context.minimum_version = ssl.TLSVersion.TLSv1_2

        return context

    def test_smtp_connection(self) -> ConnectionInfo:
        """
        Test SMTP connection and gather server information.

        Returns:
            ConnectionInfo object with connection details
        """
        conn_info = ConnectionInfo(
            host=self.host,
            port=self.port,
            protocol="SMTP"
        )

        try:
            # Determine if using implicit SSL (port 465)
            if self.port == 465:
                smtp = smtplib.SMTP_SSL(
                    self.host,
                    self.port,
                    timeout=self.timeout,
                    context=self._create_ssl_context()
                )
            else:
                smtp = smtplib.SMTP(self.host, self.port, timeout=self.timeout)

                if self.use_tls:
                    smtp.starttls(context=self._create_ssl_context())

            # Get server banner
            conn_info.banner = smtp.ehlo_resp.decode('utf-8') if smtp.ehlo_resp else None

            # Get capabilities
            smtp.ehlo()
            conn_info.capabilities = list(smtp.esmtp_features.keys())

            # Get TLS info if encrypted
            if self.use_tls or self.port == 465:
                sock = smtp.sock
                if isinstance(sock, ssl.SSLSocket):
                    conn_info.tls_version = sock.version()
                    conn_info.cipher = sock.cipher()[0] if sock.cipher() else None

            conn_info.connected = True
            smtp.quit()

            logger.info(f"Successfully connected to {self.host}:{self.port}")

        except Exception as e:
            logger.error(f"SMTP connection failed: {e}")
            conn_info.connected = False

        self.connection_info = conn_info
        return conn_info

    def test_imap_connection(self) -> ConnectionInfo:
        """
        Test IMAP connection and gather server information.

        Returns:
            ConnectionInfo object with connection details
        """
        conn_info = ConnectionInfo(
            host=self.host,
            port=self.port,
            protocol="IMAP"
        )

        try:
            # Use IMAP4_SSL for port 993, otherwise IMAP4
            if self.port == 993 or self.use_tls:
                imap = imaplib.IMAP4_SSL(
                    self.host,
                    self.port,
                    ssl_context=self._create_ssl_context()
                )
            else:
                imap = imaplib.IMAP4(self.host, self.port)

            # Get capabilities
            _, capability_data = imap.capability()
            conn_info.capabilities = capability_data[0].decode().split()

            # Get TLS info
            if hasattr(imap, 'sock') and isinstance(imap.sock, ssl.SSLSocket):
                conn_info.tls_version = imap.sock.version()
                conn_info.cipher = imap.sock.cipher()[0] if imap.sock.cipher() else None

            conn_info.connected = True
            imap.logout()

            logger.info(f"Successfully connected to IMAP {self.host}:{self.port}")

        except Exception as e:
            logger.error(f"IMAP connection failed: {e}")
            conn_info.connected = False

        self.connection_info = conn_info
        return conn_info

    def test_pop3_connection(self) -> ConnectionInfo:
        """
        Test POP3 connection and gather server information.

        Returns:
            ConnectionInfo object with connection details
        """
        conn_info = ConnectionInfo(
            host=self.host,
            port=self.port,
            protocol="POP3"
        )

        try:
            # Use POP3_SSL for port 995
            if self.port == 995 or self.use_tls:
                pop = poplib.POP3_SSL(
                    self.host,
                    self.port,
                    context=self._create_ssl_context()
                )
            else:
                pop = poplib.POP3(self.host, self.port)

            # Get welcome message
            conn_info.banner = pop.getwelcome().decode('utf-8')

            # Get capabilities if supported
            try:
                capabilities = pop.capa()
                conn_info.capabilities = [cap.decode() for cap in capabilities.values()]
            except:
                pass

            # Get TLS info
            if hasattr(pop, 'sock') and isinstance(pop.sock, ssl.SSLSocket):
                conn_info.tls_version = pop.sock.version()
                conn_info.cipher = pop.sock.cipher()[0] if pop.sock.cipher() else None

            conn_info.connected = True
            pop.quit()

            logger.info(f"Successfully connected to POP3 {self.host}:{self.port}")

        except Exception as e:
            logger.error(f"POP3 connection failed: {e}")
            conn_info.connected = False

        self.connection_info = conn_info
        return conn_info

    def scan_ports(self) -> List[ConnectionInfo]:
        """
        Scan common mail ports and test connections.

        Returns:
            List of ConnectionInfo objects for all accessible ports
        """
        results = []
        all_ports = self.SMTP_PORTS + self.IMAP_PORTS + self.POP3_PORTS

        for port in all_ports:
            # Quick port check
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            try:
                result = sock.connect_ex((self.host, port))
                sock.close()

                if result == 0:
                    # Port is open, test specific protocol
                    old_port = self.port
                    self.port = port

                    if port in self.SMTP_PORTS:
                        conn_info = self.test_smtp_connection()
                    elif port in self.IMAP_PORTS:
                        conn_info = self.test_imap_connection()
                    elif port in self.POP3_PORTS:
                        conn_info = self.test_pop3_connection()

                    results.append(conn_info)
                    self.port = old_port

            except Exception as e:
                logger.debug(f"Port {port} scan failed: {e}")
                sock.close()

        return results

    def get_ssl_certificate(self) -> Optional[Dict]:
        """
        Retrieve SSL certificate information.

        Returns:
            Dictionary containing certificate details
        """
        try:
            context = ssl.create_default_context()

            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    return cert

        except Exception as e:
            logger.error(f"Failed to retrieve certificate: {e}")
            return None
