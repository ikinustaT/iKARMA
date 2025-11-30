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
from ikarma.core.api_patterns import (
    API_DATABASE,
    STRING_INDICATORS,
    get_all_api_names,
    get_api_info,
)
from ikarma.core.loldrivers import LOLDriversMatcher
from ikarma.core.html_report import HTMLReportGenerator

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
    'API_DATABASE',
    'STRING_INDICATORS',
    'get_all_api_names',
    'get_api_info',
    'LOLDriversMatcher',
    'HTMLReportGenerator',
]
