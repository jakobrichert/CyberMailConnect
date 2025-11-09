"""
Authentication management module for email connections.
"""

import base64
import hmac
import hashlib
from typing import Optional, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class AuthMethod(Enum):
    """Supported authentication methods."""
    PLAIN = "PLAIN"
    LOGIN = "LOGIN"
    CRAM_MD5 = "CRAM-MD5"
    OAUTH2 = "OAUTH2"
    XOAUTH2 = "XOAUTH2"


class AuthManager:
    """
    Manage email authentication mechanisms.

    Supports multiple authentication methods including:
    - PLAIN
    - LOGIN
    - CRAM-MD5
    - OAuth2/XOAUTH2
    """

    def __init__(self, username: str, password: str = None, oauth_token: str = None):
        """
        Initialize authentication manager.

        Args:
            username: Email username
            password: Email password (for traditional auth)
            oauth_token: OAuth2 token (for OAuth auth)
        """
        self.username = username
        self.password = password
        self.oauth_token = oauth_token

    def encode_plain(self) -> str:
        """
        Encode credentials for PLAIN authentication.

        Returns:
            Base64-encoded credentials
        """
        if not self.password:
            raise ValueError("Password required for PLAIN authentication")

        # PLAIN format: \0username\0password
        auth_string = f"\0{self.username}\0{self.password}"
        return base64.b64encode(auth_string.encode()).decode()

    def encode_login(self) -> Tuple[str, str]:
        """
        Encode credentials for LOGIN authentication.

        Returns:
            Tuple of (base64_username, base64_password)
        """
        if not self.password:
            raise ValueError("Password required for LOGIN authentication")

        username_b64 = base64.b64encode(self.username.encode()).decode()
        password_b64 = base64.b64encode(self.password.encode()).decode()

        return username_b64, password_b64

    def encode_cram_md5(self, challenge: str) -> str:
        """
        Encode credentials for CRAM-MD5 authentication.

        Args:
            challenge: Server challenge string

        Returns:
            CRAM-MD5 response
        """
        if not self.password:
            raise ValueError("Password required for CRAM-MD5 authentication")

        # Decode challenge from base64
        challenge_bytes = base64.b64decode(challenge)

        # Compute HMAC-MD5
        digest = hmac.new(
            self.password.encode(),
            challenge_bytes,
            hashlib.md5
        ).hexdigest()

        # Format response: username<space>digest
        response = f"{self.username} {digest}"

        return base64.b64encode(response.encode()).decode()

    def encode_oauth2(self) -> str:
        """
        Encode credentials for OAuth2/XOAUTH2 authentication.

        Returns:
            Base64-encoded OAuth2 auth string
        """
        if not self.oauth_token:
            raise ValueError("OAuth token required for OAuth2 authentication")

        # XOAUTH2 format: user=username\1auth=Bearer token\1\1
        auth_string = f"user={self.username}\1auth=Bearer {self.oauth_token}\1\1"

        return base64.b64encode(auth_string.encode()).decode()

    def authenticate(self, method: AuthMethod, challenge: str = None) -> str:
        """
        Generate authentication response for specified method.

        Args:
            method: Authentication method to use
            challenge: Server challenge (required for CRAM-MD5)

        Returns:
            Encoded authentication string
        """
        if method == AuthMethod.PLAIN:
            return self.encode_plain()
        elif method == AuthMethod.LOGIN:
            username_b64, password_b64 = self.encode_login()
            return username_b64  # LOGIN sends username first
        elif method == AuthMethod.CRAM_MD5:
            if not challenge:
                raise ValueError("Challenge required for CRAM-MD5")
            return self.encode_cram_md5(challenge)
        elif method in [AuthMethod.OAUTH2, AuthMethod.XOAUTH2]:
            return self.encode_oauth2()
        else:
            raise ValueError(f"Unsupported authentication method: {method}")

    @staticmethod
    def detect_supported_methods(capabilities: list) -> list:
        """
        Detect supported authentication methods from server capabilities.

        Args:
            capabilities: List of server capabilities

        Returns:
            List of supported AuthMethod enums
        """
        supported = []

        # Find AUTH capability
        auth_cap = None
        for cap in capabilities:
            if cap.startswith('AUTH'):
                auth_cap = cap
                break

        if not auth_cap:
            return supported

        # Parse authentication methods
        methods = auth_cap.split()[1:] if len(auth_cap.split()) > 1 else []

        for method in methods:
            try:
                supported.append(AuthMethod(method))
            except ValueError:
                logger.warning(f"Unknown authentication method: {method}")

        return supported

    def test_authentication(self, smtp_connection, method: AuthMethod) -> bool:
        """
        Test authentication with SMTP server.

        Args:
            smtp_connection: Active SMTP connection
            method: Authentication method to test

        Returns:
            True if authentication successful
        """
        try:
            if method == AuthMethod.PLAIN:
                auth_string = self.encode_plain()
                smtp_connection.docmd("AUTH PLAIN", auth_string)
                return True

            elif method == AuthMethod.LOGIN:
                smtp_connection.docmd("AUTH LOGIN")
                username_b64, password_b64 = self.encode_login()
                smtp_connection.docmd(username_b64)
                smtp_connection.docmd(password_b64)
                return True

            elif method == AuthMethod.CRAM_MD5:
                # SMTP connection handles CRAM-MD5 internally
                smtp_connection.login(self.username, self.password)
                return True

            else:
                logger.warning(f"Test not implemented for {method}")
                return False

        except Exception as e:
            logger.error(f"Authentication test failed: {e}")
            return False
