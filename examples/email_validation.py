#!/usr/bin/env python3
"""
Email Authentication Validation Example

Demonstrates SPF, DKIM, and DMARC record validation.
"""

from cybermailconnect import SPFValidator, DKIMValidator, DMARCValidator
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

def main():
    """Validate email authentication records."""
    print("=" * 70)
    print("CyberMailConnect - Email Authentication Validation")
    print("=" * 70)

    # Get domain to check
    domain = input("\nEnter domain to validate (e.g., example.com): ").strip()

    # SPF Validation
    print("\n" + "=" * 70)
    print("SPF (Sender Policy Framework) Validation")
    print("=" * 70)

    spf_validator = SPFValidator()
    spf_result = spf_validator.validate_domain(domain)

    print(f"\nDomain: {domain}")
    print(f"Status: {'✓ VALID' if spf_result.valid else '✗ INVALID'}")
    print(f"Details: {spf_result.details}")

    if spf_result.record:
        print(f"Record: {spf_result.record}")

    if spf_result.errors:
        print("\nErrors/Warnings:")
        for error in spf_result.errors:
            print(f"  - {error}")

    # DMARC Validation
    print("\n" + "=" * 70)
    print("DMARC (Domain-based Message Authentication) Validation")
    print("=" * 70)

    dmarc_validator = DMARCValidator()
    dmarc_result = dmarc_validator.validate_domain(domain)

    print(f"\nDomain: {domain}")
    print(f"Status: {'✓ VALID' if dmarc_result.valid else '✗ INVALID'}")
    print(f"Details: {dmarc_result.details}")

    if dmarc_result.record:
        print(f"Record: {dmarc_result.record}")

    if dmarc_result.errors:
        print("\nErrors/Warnings:")
        for error in dmarc_result.errors:
            print(f"  - {error}")

    # DKIM Validation
    print("\n" + "=" * 70)
    print("DKIM (DomainKeys Identified Mail) Validation")
    print("=" * 70)

    # Common DKIM selectors to try
    common_selectors = ['default', 'selector1', 'selector2', 'google', 'k1', 's1']

    print(f"\nTrying common DKIM selectors for {domain}...")

    dkim_validator = DKIMValidator()
    found_selectors = []

    for selector in common_selectors:
        dkim_result = dkim_validator.validate_selector(domain, selector)

        if dkim_result.valid or dkim_result.record:
            found_selectors.append(selector)
            print(f"\n[+] Found DKIM selector: {selector}")
            print(f"    Status: {'✓ VALID' if dkim_result.valid else '✗ INVALID'}")

            if dkim_result.errors:
                print("    Warnings:")
                for error in dkim_result.errors:
                    print(f"      - {error}")

    if not found_selectors:
        print("\n[-] No DKIM records found with common selectors")
        print("    Note: DKIM selectors are configuration-specific")

    # Summary
    print("\n" + "=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)

    print(f"\nDomain: {domain}")
    print(f"  SPF:   {'✓ Configured' if spf_result.valid or spf_result.record else '✗ Not found'}")
    print(f"  DKIM:  {'✓ Configured' if found_selectors else '✗ Not found'}")
    print(f"  DMARC: {'✓ Configured' if dmarc_result.valid or dmarc_result.record else '✗ Not found'}")

    # Recommendations
    print("\n" + "=" * 70)
    print("RECOMMENDATIONS")
    print("=" * 70)

    if not spf_result.valid:
        print("\n[!] SPF: Configure SPF record to prevent email spoofing")

    if not found_selectors:
        print("\n[!] DKIM: Implement DKIM signing for email authentication")

    if not dmarc_result.valid:
        print("\n[!] DMARC: Set up DMARC policy for email protection")
    elif dmarc_result.errors and any('none' in str(e).lower() for e in dmarc_result.errors):
        print("\n[~] DMARC: Consider upgrading policy from 'none' to 'quarantine' or 'reject'")

    if spf_result.valid and found_selectors and dmarc_result.valid:
        print("\n[+] Excellent! All email authentication mechanisms are configured")

if __name__ == "__main__":
    main()
