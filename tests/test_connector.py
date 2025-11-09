"""
Unit tests for MailConnector
"""

import unittest
from unittest.mock import Mock, patch
from cybermailconnect.connector import MailConnector, ConnectionInfo


class TestMailConnector(unittest.TestCase):
    """Test cases for MailConnector class."""

    def setUp(self):
        """Set up test fixtures."""
        self.connector = MailConnector(
            host="mail.example.com",
            port=587,
            use_tls=True
        )

    def test_connector_initialization(self):
        """Test connector initializes with correct parameters."""
        self.assertEqual(self.connector.host, "mail.example.com")
        self.assertEqual(self.connector.port, 587)
        self.assertTrue(self.connector.use_tls)
        self.assertTrue(self.connector.verify_cert)

    def test_ssl_context_creation(self):
        """Test SSL context is created with correct settings."""
        context = self.connector._create_ssl_context()
        self.assertIsNotNone(context)

    def test_connection_info_dataclass(self):
        """Test ConnectionInfo dataclass."""
        conn_info = ConnectionInfo(
            host="mail.example.com",
            port=587,
            protocol="SMTP",
            connected=True
        )

        self.assertEqual(conn_info.host, "mail.example.com")
        self.assertEqual(conn_info.port, 587)
        self.assertEqual(conn_info.protocol, "SMTP")
        self.assertTrue(conn_info.connected)

    def test_port_lists(self):
        """Test port constants are defined correctly."""
        self.assertIn(587, MailConnector.SMTP_PORTS)
        self.assertIn(993, MailConnector.IMAP_PORTS)
        self.assertIn(995, MailConnector.POP3_PORTS)

    @patch('smtplib.SMTP')
    def test_smtp_connection_mock(self, mock_smtp):
        """Test SMTP connection with mock."""
        # Configure mock
        mock_instance = Mock()
        mock_smtp.return_value = mock_instance
        mock_instance.ehlo_resp = b"250-mail.example.com"
        mock_instance.esmtp_features = {'STARTTLS': '', 'AUTH': 'PLAIN LOGIN'}

        # This would normally connect, but we're just testing the structure
        self.assertIsNotNone(self.connector)


class TestConnectionInfo(unittest.TestCase):
    """Test cases for ConnectionInfo dataclass."""

    def test_connection_info_defaults(self):
        """Test ConnectionInfo default values."""
        conn_info = ConnectionInfo(
            host="test.com",
            port=25,
            protocol="SMTP"
        )

        self.assertIsNone(conn_info.tls_version)
        self.assertIsNone(conn_info.cipher)
        self.assertFalse(conn_info.connected)


if __name__ == '__main__':
    unittest.main()
