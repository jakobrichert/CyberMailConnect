"""
CyberMailConnect - Secure Email Connection Testing and Analysis Library

A comprehensive toolkit for security researchers and penetration testers
to analyze email server configurations and identify vulnerabilities.

Author: Jakob
Year: 2022
"""

__version__ = "1.2.0"
__author__ = "Jakob"

from .connector import MailConnector
from .security_analyzer import SecurityAnalyzer, ScanResult
from .header_parser import HeaderParser
from .validators import SPFValidator, DKIMValidator, DMARCValidator
from .auth import AuthManager

__all__ = [
    'MailConnector',
    'SecurityAnalyzer',
    'ScanResult',
    'HeaderParser',
    'SPFValidator',
    'DKIMValidator',
    'DMARCValidator',
    'AuthManager',
]
