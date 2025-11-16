"""
Core modules for iKARMA BYOVD Detection

This package contains core functionality for API pattern matching,
risk scoring, and confidence analysis.
"""

from .api_patterns import (
    API_DATABASE,
    API_CALL_CHAINS,
    OPCODE_PATTERNS,
    STRING_INDICATORS,
    get_all_api_names,
    get_api_info,
    get_apis_by_risk,
    get_apis_by_category,
)

__all__ = [
    'API_DATABASE',
    'API_CALL_CHAINS',
    'OPCODE_PATTERNS',
    'STRING_INDICATORS',
    'get_all_api_names',
    'get_api_info',
    'get_apis_by_risk',
    'get_apis_by_category',
]
