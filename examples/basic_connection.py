#!/usr/bin/env python3
"""
Basic Connection Test Example

Demonstrates how to test basic email server connectivity.
"""

from cybermailconnect import MailConnector
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

def main():
    """Test basic SMTP connection."""
    print("=" * 60)
    print("CyberMailConnect - Basic Connection Test")
    print("=" * 60)

    # Initialize connector
    connector = MailConnector(
        host="smtp.gmail.com",
        port=587,
        use_tls=True,
        verify_cert=True
    )

    print(f"\nTesting connection to {connector.host}:{connector.port}...")

    # Test SMTP connection
    result = connector.test_smtp_connection()

    if result.connected:
        print("\n[+] Connection successful!")
        print(f"    Protocol: {result.protocol}")
        print(f"    TLS Version: {result.tls_version}")
        print(f"    Cipher: {result.cipher}")
        print(f"    Capabilities: {', '.join(result.capabilities[:5])}...")
    else:
        print("\n[-] Connection failed")

    # Scan all common ports
    print("\n" + "=" * 60)
    print("Scanning all common mail ports...")
    print("=" * 60)

    results = connector.scan_ports()

    print(f"\nFound {len(results)} accessible ports:\n")
    for result in results:
        status = "[+]" if result.connected else "[-]"
        print(f"{status} {result.protocol} Port {result.port}")
        if result.tls_version:
            print(f"    TLS: {result.tls_version} ({result.cipher})")

if __name__ == "__main__":
    main()
