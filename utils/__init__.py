"""
Utility modules for iKARMA BYOVD Detection

This package contains utility functions for API scanning,
pattern matching, and detection.
"""

from .api_scanner import (
    find_dangerous_apis,
    detect_string_match,
    detect_call_patterns,
    detect_string_references,
    get_scanner_statistics,
)

__all__ = [
    'find_dangerous_apis',
    'detect_string_match',
    'detect_call_patterns',
    'detect_string_references',
    'get_scanner_statistics',
]
