#!/usr/bin/env python3
"""
Security Scan Example

Demonstrates comprehensive security analysis of email servers.
"""

from cybermailconnect import MailConnector, SecurityAnalyzer
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

def main():
    """Perform comprehensive security scan."""
    print("=" * 70)
    print("CyberMailConnect - Security Scan")
    print("=" * 70)

    # Get target from user
    host = input("\nEnter mail server hostname (e.g., mail.example.com): ").strip()
    port = int(input("Enter port (default 587): ").strip() or "587")

    # Initialize connector
    connector = MailConnector(
        host=host,
        port=port,
        use_tls=True,
        verify_cert=True,
        min_tls_version="TLSv1_2"
    )

    # Initialize security analyzer
    analyzer = SecurityAnalyzer(connector)

    print(f"\n[*] Starting security scan of {host}:{port}...")
    print("[*] This may take a moment...\n")

    # Run full security scan
    results = analyzer.run_full_scan()

    # Display results
    print("\n" + analyzer.generate_report())

    # Show detailed vulnerabilities
    if results.vulnerabilities:
        print("\n" + "=" * 70)
        print("DETAILED VULNERABILITY INFORMATION")
        print("=" * 70)

        for i, vuln in enumerate(results.vulnerabilities, 1):
            print(f"\n{i}. {vuln.title} [{vuln.severity.value}]")
            print(f"   Component: {vuln.affected_component}")
            print(f"   Description: {vuln.description}")
            print(f"   Recommendation: {vuln.recommendation}")

            if vuln.cve:
                print(f"   CVE: {vuln.cve}")

            if vuln.references:
                print(f"   References:")
                for ref in vuln.references:
                    print(f"     - {ref}")

    # Save report to file
    report_file = f"security_report_{host.replace('.', '_')}.txt"
    with open(report_file, 'w') as f:
        f.write(analyzer.generate_report())

    print(f"\n[+] Report saved to: {report_file}")

if __name__ == "__main__":
    main()
