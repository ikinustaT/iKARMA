"""
Compatibility wrapper for the legacy BYOVD API signature database.

This makes the v1 `core/api_patterns.py` available under the v2 package
namespace without copying the entire file.
"""

try:
    from core.api_patterns import (  # type: ignore
        API_DATABASE,
        STRING_INDICATORS,
        get_all_api_names,
        get_api_info,
    )
    IMPORT_ERROR = None
except Exception as e:  # pragma: no cover - fallback when legacy file missing
    IMPORT_ERROR = str(e)
    API_DATABASE = {}
    STRING_INDICATORS = {}

    def get_all_api_names():
        return []

    def get_api_info(name: str):
        return (None, None)
