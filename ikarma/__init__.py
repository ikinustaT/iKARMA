"""
iKARMA - Kernel Driver Analysis for Memory Forensics

Production Release v2.0.0

iKARMA is a specialized memory forensics tool designed to identify and
analyze potentially dangerous kernel drivers in Windows memory dumps.

Key Features:
- Volatility3 integration with PE carving fallback
- Cross-view validation for DKOM detection
- Capability detection with "Because" tags
- Hook detection for MajorFunction tables
- Risk scoring with legitimacy bonus
- SIEM-ready JSON output
- LOLDrivers database matching

Usage:
    from ikarma import Analyzer
    
    analyzer = Analyzer("memory.dmp")
    analyzer.initialize()
    result = analyzer.analyze()
    
    for driver in result.drivers:
        if driver.risk_score >= 7.0:
            print(f"{driver.name}: {driver.risk_category}")
            print(driver.generate_summary_because())

CLI Usage:
    ikarma analyze memory.dmp -o results.json
    ikarma loldrivers --verbose
    ikarma version
"""

__version__ = "2.0.1"
__author__ = "iKARMA Team"
__license__ = "MIT"

from ikarma.core import (
    # Main analyzer
    Analyzer,
    
    # Data classes
    DriverInfo,
    DriverCapability,
    AntiForensicIndicator,
    AnalysisResult,
    CrossViewResult,
    SignatureInfo,
    IOCTLHandler,
    MajorFunctionInfo,
    CodePattern,
    
    # Enums
    CapabilityType,
    AntiForensicType,
    ConfidenceLevel,
    EnumerationSource,
    
    # Component classes
    MemoryParser,
    CapabilityEngine,
    AntiForensicDetector,
    RiskScorer,
    LOLDriversMatcher,
)

__all__ = [
    # Version
    '__version__',
    
    # Main entry point
    'Analyzer',
    
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
    
    # Components
    'MemoryParser',
    'CapabilityEngine',
    'AntiForensicDetector',
    'RiskScorer',
    'LOLDriversMatcher',
]
