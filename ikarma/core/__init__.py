"""
iKARMA Core Module

Production-ready kernel driver analysis for memory forensics.
"""

from ikarma.core.driver import (
    DriverInfo,
    DriverCapability,
    AntiForensicIndicator,
    AnalysisResult,
    CrossViewResult,
    CapabilityType,
    AntiForensicType,
    ConfidenceLevel,
    EnumerationSource,
    SignatureInfo,
    IOCTLHandler,
    MajorFunctionInfo,
    CodePattern,
)

from ikarma.core.analyzer import Analyzer
from ikarma.core.enhanced_analyzer import EnhancedAnalyzer
from ikarma.core.memory_parser import MemoryParser
from ikarma.core.capability_engine import CapabilityEngine
from ikarma.core.antiforensic_detector import AntiForensicDetector
from ikarma.core.risk_scorer import RiskScorer
from ikarma.core.loldrivers import LOLDriversMatcher
from ikarma.core.html_report import HTMLReportGenerator
# Legacy BYOVD API patterns (v1 compatibility)
from ikarma.core.api_patterns_v1 import (
    API_DATABASE as LEGACY_API_DATABASE,
    STRING_INDICATORS as LEGACY_STRING_INDICATORS,
    get_all_api_names as get_all_api_names_legacy,
    get_api_info as get_api_info_legacy,
)
# Legacy risk scorer wrapper (does not replace v2 scorer)
from ikarma.core import risk_scorer_v1  # noqa: F401

__all__ = [
    # Data classes
    'DriverInfo',
    'DriverCapability',
    'AntiForensicIndicator',
    'AnalysisResult',
    'CrossViewResult',
    'SignatureInfo',
    'IOCTLHandler',
    'MajorFunctionInfo',
    'CodePattern',

    # Enums
    'CapabilityType',
    'AntiForensicType',
    'ConfidenceLevel',
    'EnumerationSource',

    # Analyzers
    'Analyzer',
    'EnhancedAnalyzer',
    'MemoryParser',
    'CapabilityEngine',
    'AntiForensicDetector',
    'RiskScorer',
    'LOLDriversMatcher',
    'HTMLReportGenerator',

    # Legacy BYOVD API database (v1 compatibility)
    'LEGACY_API_DATABASE',
    'LEGACY_STRING_INDICATORS',
    'get_all_api_names_legacy',
    'get_api_info_legacy',
]
