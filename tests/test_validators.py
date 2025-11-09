"""
Unit tests for email validators (SPF, DKIM, DMARC)
"""

import unittest
from unittest.mock import Mock, patch
from cybermailconnect.validators import SPFValidator, DKIMValidator, DMARCValidator, ValidationResult


class TestSPFValidator(unittest.TestCase):
    """Test cases for SPFValidator."""

    def setUp(self):
        """Set up test fixtures."""
        self.validator = SPFValidator()

    def test_spf_syntax_validation(self):
        """Test SPF record syntax validation."""
        # Valid SPF record
        valid_spf = "v=spf1 include:_spf.google.com ~all"
        errors = self.validator._validate_spf_syntax(valid_spf)
        self.assertEqual(len(errors), 0)

        # SPF with +all (insecure)
        insecure_spf = "v=spf1 +all"
        errors = self.validator._validate_spf_syntax(insecure_spf)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("allows any server" in err.lower() for err in errors))

    def test_spf_too_many_lookups(self):
        """Test detection of too many DNS lookups."""
        # SPF with many includes (>10)
        many_lookups = "v=spf1 " + " ".join([f"include:spf{i}.example.com" for i in range(12)]) + " ~all"
        errors = self.validator._validate_spf_syntax(many_lookups)

        has_lookup_error = any("too many" in err.lower() for err in errors)
        self.assertTrue(has_lookup_error)

    def test_spf_ptr_mechanism(self):
        """Test detection of deprecated PTR mechanism."""
        spf_with_ptr = "v=spf1 ptr:example.com ~all"
        errors = self.validator._validate_spf_syntax(spf_with_ptr)

        has_ptr_warning = any("ptr" in err.lower() for err in errors)
        self.assertTrue(has_ptr_warning)


class TestDKIMValidator(unittest.TestCase):
    """Test cases for DKIMValidator."""

    def setUp(self):
        """Set up test fixtures."""
        self.validator = DKIMValidator()

    def test_dkim_syntax_validation(self):
        """Test DKIM record syntax validation."""
        # Valid DKIM record
        valid_dkim = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA..."
        errors = self.validator._validate_dkim_syntax(valid_dkim)
        self.assertEqual(len(errors), 0)

        # DKIM without public key
        no_key = "v=DKIM1; k=rsa"
        errors = self.validator._validate_dkim_syntax(no_key)
        self.assertGreater(len(errors), 0)

    def test_dkim_revoked_key(self):
        """Test detection of revoked DKIM key."""
        revoked_dkim = "v=DKIM1; p=; k=rsa"
        errors = self.validator._validate_dkim_syntax(revoked_dkim)

        has_revoked_error = any("revoked" in err.lower() for err in errors)
        self.assertTrue(has_revoked_error)


class TestDMARCValidator(unittest.TestCase):
    """Test cases for DMARCValidator."""

    def setUp(self):
        """Set up test fixtures."""
        self.validator = DMARCValidator()

    def test_dmarc_syntax_validation(self):
        """Test DMARC record syntax validation."""
        # Valid DMARC record
        valid_dmarc = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        errors = self.validator._validate_dmarc_syntax(valid_dmarc)
        # Should have warning about monitoring but valid syntax
        self.assertIsInstance(errors, list)

        # DMARC without policy
        no_policy = "v=DMARC1; rua=mailto:dmarc@example.com"
        errors = self.validator._validate_dmarc_syntax(no_policy)
        self.assertGreater(len(errors), 0)

    def test_dmarc_policy_parsing(self):
        """Test DMARC policy parsing."""
        dmarc_record = "v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:reports@example.com"
        policy = self.validator._parse_dmarc_policy(dmarc_record)

        self.assertEqual(policy.get('p'), 'quarantine')
        self.assertEqual(policy.get('sp'), 'reject')
        self.assertEqual(policy.get('pct'), '100')

    def test_dmarc_none_policy_warning(self):
        """Test warning for DMARC policy set to 'none'."""
        none_policy = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
        errors = self.validator._validate_dmarc_syntax(none_policy)

        has_none_warning = any("none" in err.lower() and "monitoring" in err.lower() for err in errors)
        self.assertTrue(has_none_warning)


class TestValidationResult(unittest.TestCase):
    """Test cases for ValidationResult dataclass."""

    def test_validation_result_creation(self):
        """Test ValidationResult creation."""
        result = ValidationResult(
            valid=True,
            details="Test passed",
            record="v=spf1 ~all"
        )

        self.assertTrue(result.valid)
        self.assertEqual(result.details, "Test passed")
        self.assertEqual(result.record, "v=spf1 ~all")


if __name__ == '__main__':
    unittest.main()
