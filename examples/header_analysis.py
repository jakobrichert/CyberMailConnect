#!/usr/bin/env python3
"""
Header Analysis Example

Demonstrates email header parsing and security analysis.
"""

from cybermailconnect import HeaderParser

# Example email headers
SAMPLE_HEADERS = """
From: sender@example.com
To: recipient@test.com
Subject: Test Email
Message-ID: <12345@example.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
Return-Path: <bounce@different-domain.com>
Received: from mail.example.com ([192.168.1.100]) by mx.test.com
Received: from sender-server.net ([10.0.0.5]) by mail.example.com
Authentication-Results: mx.test.com;
    spf=pass smtp.mailfrom=example.com;
    dkim=pass header.d=example.com;
    dmarc=pass header.from=example.com
X-Mailer: Custom Mailer 1.0
Content-Type: text/plain
"""

def main():
    """Analyze email headers for security issues."""
    print("=" * 60)
    print("CyberMailConnect - Header Analysis")
    print("=" * 60)

    # Initialize parser
    parser = HeaderParser()

    print("\n[*] Analyzing email headers...\n")

    # Parse headers
    analysis = parser.parse(SAMPLE_HEADERS)

    # Display results
    print(parser.generate_report())

    # Detailed analysis
    print("\n" + "=" * 60)
    print("DETAILED ANALYSIS")
    print("=" * 60)

    if analysis.sender_ip:
        print(f"\nOriginating IP: {analysis.sender_ip}")

    if analysis.return_path:
        print(f"Return-Path: {analysis.return_path}")

    if analysis.message_id:
        print(f"Message-ID: {analysis.message_id}")

    if analysis.potential_spoofing:
        print("\n[!] WARNING: Potential email spoofing detected!")
        print("    The From and Return-Path domains do not match.")
        print("    This could indicate a spoofing attempt.")

    # Authentication results
    if analysis.authentication_results:
        print("\n[+] Email Authentication:")
        for method, result in analysis.authentication_results.items():
            symbol = "✓" if result == "PASS" else "✗"
            print(f"    {symbol} {method}: {result}")
    else:
        print("\n[-] No authentication results found in headers")

    # Email path
    if analysis.received_path:
        print(f"\n[+] Email routing path ({len(analysis.received_path)} hops):")
        for i, ip in enumerate(analysis.received_path, 1):
            print(f"    {i}. {ip}")

    # Load headers from file (optional)
    print("\n" + "=" * 60)
    print("\nTo analyze headers from a file:")
    print("  1. Save email headers to a .txt file")
    print("  2. Modify this script to read from the file")
    print("  3. Run the analysis")

if __name__ == "__main__":
    main()
