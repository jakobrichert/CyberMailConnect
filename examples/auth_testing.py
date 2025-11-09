#!/usr/bin/env python3
"""
Authentication Testing Example

Demonstrates authentication mechanism detection and testing.
For authorized testing only!
"""

from cybermailconnect import MailConnector, AuthManager
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

def main():
    """Test authentication mechanisms."""
    print("=" * 70)
    print("CyberMailConnect - Authentication Testing")
    print("=" * 70)
    print("\n[!] WARNING: Only use on systems you are authorized to test!")
    print()

    # Get target information
    host = input("Enter mail server hostname: ").strip()
    port = int(input("Enter port (default 587): ").strip() or "587")

    # Initialize connector
    connector = MailConnector(
        host=host,
        port=port,
        use_tls=True
    )

    print(f"\n[*] Connecting to {host}:{port}...")

    # Test connection and get capabilities
    conn_info = connector.test_smtp_connection()

    if not conn_info.connected:
        print("[-] Failed to connect to server")
        return

    print(f"[+] Connected successfully")
    print(f"    TLS Version: {conn_info.tls_version}")

    # Detect supported authentication methods
    supported_methods = AuthManager.detect_supported_methods(conn_info.capabilities)

    if not supported_methods:
        print("\n[-] No authentication methods detected")
        return

    print(f"\n[+] Supported authentication methods:")
    for method in supported_methods:
        print(f"    - {method.value}")

    # Security analysis
    print("\n" + "=" * 70)
    print("SECURITY ANALYSIS")
    print("=" * 70)

    # Check for insecure authentication
    from cybermailconnect.auth import AuthMethod

    if AuthMethod.PLAIN in supported_methods or AuthMethod.LOGIN in supported_methods:
        if conn_info.tls_version:
            print("\n[+] PLAIN/LOGIN auth available (protected by TLS)")
        else:
            print("\n[!] WARNING: PLAIN/LOGIN auth without TLS encryption!")
            print("    Credentials could be intercepted!")

    if AuthMethod.CRAM_MD5 in supported_methods:
        print("\n[~] CRAM-MD5 is supported (better than PLAIN, but outdated)")

    if AuthMethod.OAUTH2 in supported_methods or AuthMethod.XOAUTH2 in supported_methods:
        print("\n[+] OAuth2 authentication supported (recommended)")

    # Demonstrate authentication encoding (without actually authenticating)
    print("\n" + "=" * 70)
    print("AUTHENTICATION ENCODING EXAMPLES")
    print("=" * 70)

    # Example credentials (not real)
    auth_manager = AuthManager(
        username="user@example.com",
        password="example_password"
    )

    print("\n[*] PLAIN encoding example:")
    print(f"    Base64: {auth_manager.encode_plain()}")

    print("\n[*] LOGIN encoding example:")
    username_b64, password_b64 = auth_manager.encode_login()
    print(f"    Username: {username_b64}")
    print(f"    Password: {password_b64}")

    print("\n[!] Note: These are example encodings only.")
    print("    Never log or display real credentials!")

if __name__ == "__main__":
    main()
