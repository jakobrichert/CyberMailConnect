"""
Email authentication validators (SPF, DKIM, DMARC).
"""

import dns.resolver
import re
from typing import Optional, Dict, List
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of email authentication validation."""
    valid: bool
    details: str
    record: Optional[str] = None
    errors: List[str] = None


class SPFValidator:
    """
    SPF (Sender Policy Framework) record validator.

    Validates SPF records and checks sender authorization.
    """

    def __init__(self):
        """Initialize SPF validator."""
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    def validate_domain(self, domain: str) -> ValidationResult:
        """
        Validate SPF record for a domain.

        Args:
            domain: Domain name to check

        Returns:
            ValidationResult with validation status
        """
        try:
            # Query TXT records
            txt_records = self.resolver.resolve(domain, 'TXT')

            spf_record = None
            for record in txt_records:
                txt = record.to_text().strip('"')
                if txt.startswith('v=spf1'):
                    spf_record = txt
                    break

            if not spf_record:
                return ValidationResult(
                    valid=False,
                    details="No SPF record found",
                    errors=["Missing SPF record"]
                )

            # Basic SPF syntax validation
            errors = self._validate_spf_syntax(spf_record)

            return ValidationResult(
                valid=len(errors) == 0,
                details=f"SPF record: {spf_record}",
                record=spf_record,
                errors=errors
            )

        except dns.resolver.NXDOMAIN:
            return ValidationResult(
                valid=False,
                details=f"Domain {domain} does not exist",
                errors=["Domain not found"]
            )
        except Exception as e:
            logger.error(f"SPF validation failed: {e}")
            return ValidationResult(
                valid=False,
                details=f"Validation error: {str(e)}",
                errors=[str(e)]
            )

    def _validate_spf_syntax(self, spf_record: str) -> List[str]:
        """Validate SPF record syntax."""
        errors = []

        # Check for multiple SPF records (should only have one)
        if spf_record.count('v=spf1') > 1:
            errors.append("Multiple SPF version declarations")

        # Check for too many DNS lookups (max 10)
        lookup_mechanisms = ['include:', 'a:', 'mx:', 'ptr:', 'exists:']
        lookup_count = sum(spf_record.count(mech) for mech in lookup_mechanisms)

        if lookup_count > 10:
            errors.append(f"Too many DNS lookups ({lookup_count} > 10)")

        # Check for dangerous mechanisms
        if 'ptr:' in spf_record:
            errors.append("PTR mechanism is deprecated and should not be used")

        # Check for proper termination
        if not any(term in spf_record for term in ['~all', '-all', '?all', '+all']):
            errors.append("SPF record should end with an 'all' mechanism")

        if '+all' in spf_record:
            errors.append("'+all' allows any server to send email (insecure)")

        return errors


class DKIMValidator:
    """
    DKIM (DomainKeys Identified Mail) validator.

    Validates DKIM public key records.
    """

    def __init__(self):
        """Initialize DKIM validator."""
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5

    def validate_selector(self, domain: str, selector: str) -> ValidationResult:
        """
        Validate DKIM record for a specific selector.

        Args:
            domain: Domain name
            selector: DKIM selector

        Returns:
            ValidationResult with validation status
        """
        try:
            # Query DKIM record: selector._domainkey.domain
            dkim_domain = f"{selector}._domainkey.{domain}"
            txt_records = self.resolver.resolve(dkim_domain, 'TXT')

            dkim_record = None
            for record in txt_records:
                txt = record.to_text().strip('"').replace('" "', '')
                if 'p=' in txt:  # Public key present
                    dkim_record = txt
                    break

            if not dkim_record:
                return ValidationResult(
                    valid=False,
                    details=f"No DKIM record found for selector '{selector}'",
                    errors=["Missing DKIM record"]
                )

            # Validate DKIM record structure
            errors = self._validate_dkim_syntax(dkim_record)

            return ValidationResult(
                valid=len(errors) == 0,
                details=f"DKIM record found for selector '{selector}'",
                record=dkim_record,
                errors=errors
            )

        except dns.resolver.NXDOMAIN:
            return ValidationResult(
                valid=False,
                details=f"DKIM selector '{selector}' not found for domain {domain}",
                errors=["Selector not found"]
            )
        except Exception as e:
            logger.error(f"DKIM validation failed: {e}")
            return ValidationResult(
                valid=False,
                details=f"Validation error: {str(e)}",
                errors=[str(e)]
            )

    def _validate_dkim_syntax(self, dkim_record: str) -> List[str]:
        """Validate DKIM record syntax."""
        errors = []

        # Check for public key
        if 'p=' not in dkim_record:
            errors.append("Missing public key (p=)")

        # Check if key is revoked
        if re.search(r'p=\s*;', dkim_record) or re.search(r'p=\s*$', dkim_record):
            errors.append("DKIM key has been revoked")

        # Check key type
        if 'k=' in dkim_record:
            key_type = re.search(r'k=([^;]+)', dkim_record)
            if key_type and key_type.group(1) not in ['rsa', 'ed25519']:
                errors.append(f"Unknown key type: {key_type.group(1)}")

        return errors


class DMARCValidator:
    """
    DMARC (Domain-based Message Authentication) validator.

    Validates DMARC policies and configuration.
    """

    def __init__(self):
        """Initialize DMARC validator."""
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5

    def validate_domain(self, domain: str) -> ValidationResult:
        """
        Validate DMARC record for a domain.

        Args:
            domain: Domain name to check

        Returns:
            ValidationResult with validation status
        """
        try:
            # Query DMARC record: _dmarc.domain
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = self.resolver.resolve(dmarc_domain, 'TXT')

            dmarc_record = None
            for record in txt_records:
                txt = record.to_text().strip('"')
                if txt.startswith('v=DMARC1'):
                    dmarc_record = txt
                    break

            if not dmarc_record:
                return ValidationResult(
                    valid=False,
                    details="No DMARC record found",
                    errors=["Missing DMARC record"]
                )

            # Validate DMARC syntax and policy
            errors = self._validate_dmarc_syntax(dmarc_record)
            policy_info = self._parse_dmarc_policy(dmarc_record)

            details = f"DMARC record: {dmarc_record}\n"
            details += f"Policy: {policy_info.get('p', 'none')}"

            return ValidationResult(
                valid=len(errors) == 0,
                details=details,
                record=dmarc_record,
                errors=errors if errors else None
            )

        except dns.resolver.NXDOMAIN:
            return ValidationResult(
                valid=False,
                details=f"DMARC record not found for {domain}",
                errors=["DMARC record not found"]
            )
        except Exception as e:
            logger.error(f"DMARC validation failed: {e}")
            return ValidationResult(
                valid=False,
                details=f"Validation error: {str(e)}",
                errors=[str(e)]
            )

    def _validate_dmarc_syntax(self, dmarc_record: str) -> List[str]:
        """Validate DMARC record syntax."""
        errors = []

        # Check version
        if not dmarc_record.startswith('v=DMARC1'):
            errors.append("Invalid DMARC version")

        # Check for required policy
        if 'p=' not in dmarc_record:
            errors.append("Missing required policy tag (p=)")

        # Validate policy values
        policy_match = re.search(r'p=(none|quarantine|reject)', dmarc_record)
        if not policy_match:
            errors.append("Invalid policy value")
        elif policy_match.group(1) == 'none':
            errors.append("Policy set to 'none' - monitoring only, no enforcement")

        # Check for reporting URIs
        if 'rua=' not in dmarc_record:
            errors.append("No aggregate reporting URI (rua=) configured")

        return errors

    def _parse_dmarc_policy(self, dmarc_record: str) -> Dict:
        """Parse DMARC record into components."""
        policy = {}

        # Extract policy tags
        tags = ['p', 'sp', 'pct', 'rua', 'ruf', 'fo', 'adkim', 'aspf']

        for tag in tags:
            match = re.search(f'{tag}=([^;]+)', dmarc_record)
            if match:
                policy[tag] = match.group(1).strip()

        return policy
