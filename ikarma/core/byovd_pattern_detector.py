"""
iKARMA BYOVD Pattern Detector

Detects Bring Your Own Vulnerable Driver (BYOVD) patterns through:
- IOCTL handler code pattern analysis
- Dangerous API call sequence detection
- Physical memory mapping primitive detection
- Process memory manipulation detection

This module detects vulnerable drivers that are NOT in the LOLDrivers database
through behavioral/capability pattern analysis.
"""

import logging
import struct
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass

from ikarma.core.driver import (
    DriverInfo, DriverCapability, IOCTLHandler,
    CapabilityType, ConfidenceLevel,
)

logger = logging.getLogger(__name__)


# =============================================================================
# BYOVD PATTERN DEFINITIONS
# =============================================================================

@dataclass
class BYOVDPattern:
    """A detected BYOVD attack pattern."""
    pattern_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM
    description: str
    evidence: str
    confidence: float
    risk_weight: float


# Dangerous API sequences that indicate BYOVD capability
BYOVD_API_SEQUENCES = [
    # Physical memory mapping - CRITICAL for BYOVD
    {
        "name": "PHYSICAL_MEMORY_MAP",
        "apis": ["MmMapIoSpace", "MmMapIoSpaceEx"],
        "description": "Maps physical memory into virtual address space",
        "severity": "CRITICAL",
        "weight": 9.5,
    },
    {
        "name": "PHYSICAL_MEMORY_UNMAP",
        "apis": ["MmUnmapIoSpace"],
        "description": "Unmaps physical memory (paired with MmMapIoSpace)",
        "severity": "HIGH",
        "weight": 7.0,
    },

    # Process memory manipulation
    {
        "name": "PROCESS_MEMORY_WRITE",
        "apis": ["ZwWriteVirtualMemory", "MmCopyVirtualMemory"],
        "description": "Writes to arbitrary process memory",
        "severity": "CRITICAL",
        "weight": 9.0,
    },
    {
        "name": "PROCESS_MEMORY_READ",
        "apis": ["ZwReadVirtualMemory", "MmCopyVirtualMemory"],
        "description": "Reads from arbitrary process memory",
        "severity": "HIGH",
        "weight": 7.5,
    },

    # Process handle manipulation
    {
        "name": "PROCESS_OPEN",
        "apis": ["ZwOpenProcess", "PsLookupProcessByProcessId"],
        "description": "Opens arbitrary process for manipulation",
        "severity": "HIGH",
        "weight": 6.5,
    },

    # Kernel memory manipulation
    {
        "name": "KERNEL_MEMORY_ALLOC",
        "apis": ["ExAllocatePool", "ExAllocatePoolWithTag"],
        "description": "Allocates kernel memory",
        "severity": "MEDIUM",
        "weight": 5.0,
    },
]


# Dangerous IOCTL code patterns (common in BYOVD drivers)
SUSPICIOUS_IOCTL_CODES = {
    0x80102040: "Generic physical memory map",
    0x80102044: "Generic physical memory read",
    0x80102048: "Generic physical memory write",
    0x80102050: "Generic virtual memory read",
    0x80102054: "Generic virtual memory write",
    0x80102060: "Generic process terminate",
    0x80102064: "Generic virtual memory allocate",
    0x9C402084: "Common BYOVD IOCTL (seen in multiple samples)",
    0x9C40A0D8: "Common BYOVD IOCTL (seen in multiple samples)",
}


# =============================================================================
# BYOVD PATTERN DETECTOR
# =============================================================================

class BYOVDPatternDetector:
    """
    Detects BYOVD patterns in drivers through behavioral analysis.

    This is independent of the LOLDrivers database and can detect
    unknown/custom vulnerable drivers.
    """

    def __init__(self, config: Optional[Dict] = None):
        """Initialize the BYOVD pattern detector."""
        self.config = config or {}

    def analyze_driver(self, driver: DriverInfo, image: bytes) -> List[BYOVDPattern]:
        """
        Analyze a driver for BYOVD patterns.

        Args:
            driver: DriverInfo to analyze
            image: Full driver image bytes

        Returns:
            List of detected BYOVD patterns
        """
        patterns = []

        # Analyze IOCTL handlers for dangerous patterns
        for handler in driver.ioctl_handlers:
            handler_patterns = self.analyze_ioctl_handler(handler, image)
            patterns.extend(handler_patterns)

        # Analyze overall capability patterns
        capability_patterns = self.analyze_capability_patterns(driver)
        patterns.extend(capability_patterns)

        # Analyze import table for suspicious APIs
        import_patterns = self.analyze_imports(image)
        patterns.extend(import_patterns)

        return patterns

    def analyze_ioctl_handler(
        self, handler: IOCTLHandler, image: bytes
    ) -> List[BYOVDPattern]:
        """
        Analyze an IOCTL handler for BYOVD patterns.

        Looks for:
        - Suspicious IOCTL codes
        - Dangerous API call sequences
        - Memory mapping patterns
        """
        patterns = []

        # TODO: Implement proper IOCTL code extraction and checking.
        # Currently, IOCTLHandler does not have an ioctl_code attribute.
        # This requires deeper analysis of the driver's IRP_MJ_DEVICE_CONTROL handler.
        pass

        # Check handler code for dangerous API sequences
        if handler.raw_code:
            api_patterns = self._analyze_code_for_apis(handler.raw_code, handler.handler_address)
            patterns.extend(api_patterns)

        return patterns

    def analyze_capability_patterns(self, driver: DriverInfo) -> List[BYOVDPattern]:
        """
        Analyze driver capabilities for BYOVD-indicative patterns.

        Dangerous patterns:
        - Physical memory access + IOCTL handler
        - Process memory manipulation + unsigned driver
        - Multiple high-risk capabilities combined
        """
        patterns = []

        # Check for physical memory mapping capability
        has_phys_mem = any(
            cap.capability_type in [
                CapabilityType.PHYSICAL_MEMORY_MAP,
                CapabilityType.PHYSICAL_MEMORY_READ,
                CapabilityType.PHYSICAL_MEMORY_WRITE,
            ]
            for cap in driver.capabilities
        )

        # Check for process memory manipulation
        has_proc_mem = any(
            cap.capability_type in [
                CapabilityType.ARBITRARY_READ,
                CapabilityType.ARBITRARY_WRITE,
            ]
            for cap in driver.capabilities
        )

        # Physical memory access + IOCTL handler = CLASSIC BYOVD
        if has_phys_mem and len(driver.ioctl_handlers) > 0:
            is_signed = driver.signature_info and driver.signature_info.is_signed
            is_microsoft = driver.signature_info and driver.signature_info.is_microsoft_signed

            if not is_microsoft:
                severity = "CRITICAL" if not is_signed else "HIGH"
                confidence = 0.95 if not is_signed else 0.80
                weight = 9.5 if not is_signed else 8.0

                patterns.append(BYOVDPattern(
                    pattern_name="BYOVD_PHYSICAL_MEMORY_IOCTL",
                    severity=severity,
                    description="Physical memory access via IOCTL handler - CLASSIC BYOVD PATTERN",
                    evidence=f"Driver has {len(driver.ioctl_handlers)} IOCTL handlers with physical memory access capability",
                    confidence=confidence,
                    risk_weight=weight,
                ))

        # Process memory manipulation + unsigned = VERY SUSPICIOUS
        if has_proc_mem:
            is_signed = driver.signature_info and driver.signature_info.is_signed

            if not is_signed:
                patterns.append(BYOVDPattern(
                    pattern_name="BYOVD_PROCESS_MEMORY_UNSIGNED",
                    severity="CRITICAL",
                    description="Unsigned driver with arbitrary process memory access",
                    evidence="Driver can read/write arbitrary process memory without digital signature",
                    confidence=0.90,
                    risk_weight=9.0,
                ))

        # Multiple high-risk capabilities = possible BYOVD
        high_risk_caps = [
            cap for cap in driver.capabilities
            if cap.risk_weight >= 8.0  # High-risk capabilities
        ]

        if len(high_risk_caps) >= 3:
            is_signed = driver.signature_info and driver.signature_info.is_signed

            if not is_signed or (driver.signature_info and not driver.signature_info.is_microsoft_signed):
                patterns.append(BYOVDPattern(
                    pattern_name="BYOVD_MULTIPLE_HIGH_RISK",
                    severity="HIGH",
                    description=f"Non-Microsoft driver with {len(high_risk_caps)} high-risk capabilities",
                    evidence=f"Capabilities: {', '.join(c.capability_type.name for c in high_risk_caps[:5])}",
                    confidence=0.75,
                    risk_weight=7.5,
                ))

        return patterns

    def analyze_imports(self, image: bytes) -> List[BYOVDPattern]:
        """
        Analyze PE import table for BYOVD-indicative API imports.

        Focuses on APIs commonly used in BYOVD attacks.
        """
        patterns = []

        try:
            import pefile
            pe = pefile.PE(data=image, fast_load=False)

            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                return patterns

            imported_apis = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', errors='ignore')
                        imported_apis.append(api_name)

            # Check for BYOVD API sequences
            for seq in BYOVD_API_SEQUENCES:
                matching_apis = [api for api in seq["apis"] if api in imported_apis]

                if matching_apis:
                    patterns.append(BYOVDPattern(
                        pattern_name=f"BYOVD_API_{seq['name']}",
                        severity=seq["severity"],
                        description=f"{seq['description']} - imports {', '.join(matching_apis)}",
                        evidence=f"PE imports: {', '.join(matching_apis)}",
                        confidence=0.70,
                        risk_weight=seq["weight"],
                    ))

        except Exception as e:
            logger.debug(f"Error analyzing imports for BYOVD patterns: {e}")

        return patterns

    def _analyze_code_for_apis(
        self, code: bytes, base_address: int
    ) -> List[BYOVDPattern]:
        """
        Analyze code bytes for dangerous API call patterns.

        This is a simplified analysis - looks for common patterns.
        """
        patterns = []

        # For now, this is a placeholder for more sophisticated analysis
        # In a full implementation, this would use disassembly to find:
        # - Call instructions to dangerous APIs
        # - API call sequences (e.g., ZwOpenProcess followed by ZwWriteVirtualMemory)
        # - Parameter patterns indicating malicious intent

        return patterns
