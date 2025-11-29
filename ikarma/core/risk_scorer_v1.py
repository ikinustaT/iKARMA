"""
Compatibility wrapper for the legacy BYOVD risk scorer (v1).

Exposes the original v1 scoring module under the v2 package namespace
without overwriting the v2 risk scorer.
"""

try:
    from core.risk_scorer import *  # type: ignore  # noqa: F401,F403
    IMPORT_ERROR = None
except Exception as e:  # pragma: no cover - fallback when legacy file missing
    IMPORT_ERROR = str(e)
