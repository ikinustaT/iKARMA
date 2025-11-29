"""
iKARMA Driver Data Models - Production Release

Defines the core data structures for representing driver information,
capabilities, and anti-forensic indicators extracted from memory.

All structures include:
- SIEM-ready JSON output with consistent schema
- "Because" tags for every finding
- Comprehensive evidence documentation
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Dict, Any, Tuple, Set
from datetime import datetime, timezone
import hashlib
import json


# =============================================================================
# ENUMERATIONS
# =============================================================================

class CapabilityType(Enum):
    """Enumeration of dangerous driver capability types."""
    
    # Memory Access Capabilities
    ARBITRARY_READ = auto()
    ARBITRARY_WRITE = auto()
    PHYSICAL_MEMORY_READ = auto()
    PHYSICAL_MEMORY_WRITE = auto()
    PHYSICAL_MEMORY_MAP = auto()
    
    # Process Manipulation
    PROCESS_TERMINATE = auto()
    PROCESS_TOKEN_STEAL = auto()
    PROCESS_HANDLE_DUP = auto()
    EPROCESS_MANIPULATION = auto()
    
    # System Manipulation
    MSR_READ = auto()
    MSR_WRITE = auto()
    CR_ACCESS = auto()
    IDT_MANIPULATION = auto()
    GDT_MANIPULATION = auto()
    
    # I/O Capabilities
    PORT_IO_READ = auto()
    PORT_IO_WRITE = auto()
    PCI_CONFIG_ACCESS = auto()
    
    # Security Bypass
    CALLBACK_REMOVAL = auto()
    DSE_BYPASS = auto()
    PPL_BYPASS = auto()
    
    # File/Registry
    KERNEL_FILE_ACCESS = auto()
    KERNEL_REGISTRY_ACCESS = auto()
    
    # Code Execution
    SHELLCODE_EXECUTION = auto()
    APC_INJECTION = auto()
    
    # Hooking Detection
    MAJOR_FUNCTION_HOOK = auto()
    SSDT_HOOK = auto()
    IDT_HOOK = auto()
    
    # Unknown
    UNKNOWN = auto()


class AntiForensicType(Enum):
    """Types of anti-forensic techniques detected."""
    
    DKOM_UNLINK = auto()
    DKOM_HIDDEN = auto()
    PE_HEADER_WIPED = auto()
    PE_HEADER_MODIFIED = auto()
    IMPORT_TABLE_DESTROYED = auto()
    TIMESTAMP_MANIPULATION = auto()
    SIZE_MISMATCH = auto()
    MEMORY_SCRUBBING = auto()
    CODE_OBFUSCATION = auto()
    DRIVER_UNLOADED_REMNANT = auto()
    UNLINKED_FROM_MODULE_LIST = auto()
    CARVED_ONLY = auto()


class ConfidenceLevel(Enum):
    """Confidence levels for capability inference."""
    
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SPECULATIVE = "speculative"


class EnumerationSource(Enum):
    """How the driver was discovered."""
    
    PSLOADED_MODULE_LIST = "PsLoadedModuleList"
    DRIVER_OBJECT_SCAN = "DriverScan"
    PE_CARVING = "carved"
    CROSS_VIEW_HIDDEN = "cross_view_hidden"
    CROSS_VIEW_REMNANT = "cross_view_remnant"


# =============================================================================
# MITRE ATT&CK MAPPING
# =============================================================================

MITRE_TECHNIQUES = {
    CapabilityType.ARBITRARY_READ: ["T1003", "T1005"],
    CapabilityType.ARBITRARY_WRITE: ["T1055", "T1574"],
    CapabilityType.PHYSICAL_MEMORY_READ: ["T1003.001"],
    CapabilityType.PHYSICAL_MEMORY_WRITE: ["T1014"],
    CapabilityType.PHYSICAL_MEMORY_MAP: ["T1014"],
    CapabilityType.PROCESS_TERMINATE: ["T1489", "T1562.001"],
    CapabilityType.PROCESS_TOKEN_STEAL: ["T1134"],
    CapabilityType.MSR_READ: ["T1082"],
    CapabilityType.MSR_WRITE: ["T1014"],
    CapabilityType.CALLBACK_REMOVAL: ["T1562.001"],
    CapabilityType.DSE_BYPASS: ["T1553.006"],
    CapabilityType.MAJOR_FUNCTION_HOOK: ["T1014", "T1574.013"],
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CodePattern:
    """Represents a code pattern found in driver memory."""
    
    offset: int
    virtual_address: int
    raw_bytes: bytes
    disassembly: List[str]
    pattern_name: str
    pattern_type: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": hex(self.offset),
            "virtual_address": hex(self.virtual_address),
            "raw_bytes": self.raw_bytes.hex() if self.raw_bytes else None,
            "disassembly": self.disassembly,
            "pattern_name": self.pattern_name,
            "pattern_type": self.pattern_type,
        }


@dataclass
class DriverCapability:
    """
    Represents an inferred capability of a kernel driver.
    
    Every capability includes a "because" tag explaining why it was flagged.
    """
    
    capability_type: CapabilityType
    confidence: float
    confidence_level: ConfidenceLevel
    description: str
    evidence: str  # "Because" tag - why this was flagged
    
    # Technical details
    handler_offset: Optional[int] = None
    handler_address: Optional[int] = None
    ioctl_code: Optional[int] = None
    code_patterns: List[CodePattern] = field(default_factory=list)
    
    # Risk assessment
    risk_weight: float = 5.0
    exploitability: str = "medium"
    mitre_techniques: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Set MITRE techniques if not provided."""
        if not self.mitre_techniques:
            self.mitre_techniques = MITRE_TECHNIQUES.get(self.capability_type, [])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_type": self.capability_type.name,
            "confidence": round(self.confidence, 3),
            "confidence_level": self.confidence_level.value,
            "description": self.description,
            "because": self.evidence,
            "handler_offset": hex(self.handler_offset) if self.handler_offset else None,
            "handler_address": hex(self.handler_address) if self.handler_address else None,
            "ioctl_code": hex(self.ioctl_code) if self.ioctl_code else None,
            "code_patterns": [p.to_dict() for p in self.code_patterns],
            "risk_weight": self.risk_weight,
            "exploitability": self.exploitability,
            "mitre_techniques": self.mitre_techniques,
        }


@dataclass
class AntiForensicIndicator:
    """
    Represents a detected anti-forensic technique.
    
    Every indicator includes a "because" tag explaining the detection.
    """
    
    indicator_type: AntiForensicType
    confidence: float
    description: str
    evidence: str  # "Because" tag
    severity: str = "medium"
    affected_region: Optional[Tuple[int, int]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator_type": self.indicator_type.name,
            "confidence": round(self.confidence, 3),
            "description": self.description,
            "because": self.evidence,
            "severity": self.severity,
            "affected_region": [hex(self.affected_region[0]), hex(self.affected_region[1])] if self.affected_region else None,
        }


@dataclass
class MajorFunctionInfo:
    """Information about a MajorFunction entry."""
    
    index: int
    handler_address: int
    is_hooked: bool = False
    hook_target: Optional[int] = None
    expected_range: Optional[Tuple[int, int]] = None
    because: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "function_name": self._get_name(),
            "handler_address": hex(self.handler_address),
            "is_hooked": self.is_hooked,
            "hook_target": hex(self.hook_target) if self.hook_target else None,
            "expected_range": [hex(self.expected_range[0]), hex(self.expected_range[1])] if self.expected_range else None,
            "because": self.because if self.is_hooked else None,
        }
    
    def _get_name(self) -> str:
        names = {
            0: "IRP_MJ_CREATE", 2: "IRP_MJ_CLOSE", 3: "IRP_MJ_READ",
            4: "IRP_MJ_WRITE", 14: "IRP_MJ_DEVICE_CONTROL",
            15: "IRP_MJ_INTERNAL_DEVICE_CONTROL", 22: "IRP_MJ_POWER",
            23: "IRP_MJ_SYSTEM_CONTROL", 27: "IRP_MJ_PNP",
        }
        return names.get(self.index, f"IRP_MJ_{self.index}")


@dataclass
class IOCTLHandler:
    """Extracted IOCTL handler code and analysis."""
    
    major_function: int
    handler_address: int
    handler_offset: int
    code_size: int
    raw_code: bytes
    disassembly: List[str]
    detected_apis: List[str] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)
    is_valid: bool = True
    validation_errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "major_function": self.major_function,
            "major_function_name": self._get_name(),
            "handler_address": hex(self.handler_address),
            "handler_offset": hex(self.handler_offset),
            "code_size": self.code_size,
            "raw_code_preview": self.raw_code[:64].hex() if self.raw_code else None,
            "disassembly_preview": self.disassembly[:20] if self.disassembly else [],
            "detected_apis": self.detected_apis,
            "suspicious_patterns": self.suspicious_patterns,
            "is_valid": self.is_valid,
        }
    
    def _get_name(self) -> str:
        names = {
            0: "IRP_MJ_CREATE", 2: "IRP_MJ_CLOSE", 3: "IRP_MJ_READ",
            4: "IRP_MJ_WRITE", 14: "IRP_MJ_DEVICE_CONTROL",
            15: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        }
        return names.get(self.major_function, f"IRP_MJ_{self.major_function}")


@dataclass
class SignatureInfo:
    """Digital signature information."""
    
    is_signed: bool = False
    signer_name: Optional[str] = None
    signer_issuer: Optional[str] = None
    signature_valid: bool = False
    is_microsoft_signed: bool = False
    is_whql_signed: bool = False
    certificate_thumbprint: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_signed": self.is_signed,
            "signer_name": self.signer_name,
            "signer_issuer": self.signer_issuer,
            "signature_valid": self.signature_valid,
            "is_microsoft_signed": self.is_microsoft_signed,
            "is_whql_signed": self.is_whql_signed,
            "certificate_thumbprint": self.certificate_thumbprint,
        }


@dataclass
class DriverInfo:
    """
    Complete information about a kernel driver extracted from memory.
    
    This is the primary data structure returned by iKARMA analysis.
    All fields support SIEM-ready JSON serialization.
    """
    
    # Basic identification
    name: str
    base_address: int
    size: int
    
    # Path and metadata
    driver_path: Optional[str] = None
    service_name: Optional[str] = None
    
    # PE Information - pe_timestamp is stored as int (Unix timestamp) for safety
    pe_timestamp: Optional[int] = None
    pe_timestamp_datetime: Optional[datetime] = None
    pe_checksum: Optional[int] = None
    pe_machine: Optional[int] = None
    entry_point: Optional[int] = None
    image_size: Optional[int] = None
    
    # Text section range for hook detection
    text_section_start: Optional[int] = None
    text_section_end: Optional[int] = None
    
    # Hash values
    md5_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    imphash: Optional[str] = None
    
    # Signature information
    signature_info: Optional[SignatureInfo] = None
    
    # DRIVER_OBJECT information from Volatility3
    driver_object_address: Optional[int] = None
    device_object_address: Optional[int] = None
    driver_start: Optional[int] = None
    driver_size_from_object: Optional[int] = None
    
    # MajorFunction table (runtime values from DRIVER_OBJECT)
    major_functions: Dict[int, int] = field(default_factory=dict)
    major_function_info: List[MajorFunctionInfo] = field(default_factory=list)
    ioctl_handlers: List[IOCTLHandler] = field(default_factory=list)
    
    # Analysis results
    capabilities: List[DriverCapability] = field(default_factory=list)
    anti_forensic_indicators: List[AntiForensicIndicator] = field(default_factory=list)
    
    # Risk scoring
    risk_score: float = 0.0
    risk_score_raw: float = 0.0
    legitimacy_bonus: float = 0.0
    risk_confidence: float = 0.0
    risk_category: str = "unknown"
    risk_factors: List[str] = field(default_factory=list)
    
    # Cross-view validation
    found_in_pslist: bool = False
    found_in_driverscan: bool = False
    found_in_carving: bool = False
    cross_view_status: str = "unknown"
    
    # Known driver matching
    is_known_vulnerable: bool = False
    loldrivers_match: Optional[Dict[str, Any]] = None
    known_cves: List[str] = field(default_factory=list)
    
    # Validation
    is_valid_pe: bool = True
    pe_validation_errors: List[str] = field(default_factory=list)
    
    # Enumeration source
    enumeration_source: str = "PsLoadedModuleList"
    
    def __post_init__(self):
        """Initialize computed fields."""
        self._update_risk_category()
        if self.pe_timestamp and not self.pe_timestamp_datetime:
            try:
                self.pe_timestamp_datetime = datetime.fromtimestamp(self.pe_timestamp)
            except (ValueError, OSError):
                pass
    
    def _update_risk_category(self):
        """Update risk category based on risk score."""
        if self.risk_score >= 8.0:
            self.risk_category = "critical"
        elif self.risk_score >= 6.0:
            self.risk_category = "high"
        elif self.risk_score >= 4.0:
            self.risk_category = "medium"
        else:
            self.risk_category = "low"
    
    def add_capability(self, capability: DriverCapability):
        """Add a capability."""
        self.capabilities.append(capability)
    
    def add_anti_forensic_indicator(self, indicator: AntiForensicIndicator):
        """Add an anti-forensic indicator."""
        self.anti_forensic_indicators.append(indicator)
    
    def get_high_risk_capabilities(self, threshold: float = 0.7) -> List[DriverCapability]:
        """Return capabilities above confidence threshold."""
        return [c for c in self.capabilities if c.confidence >= threshold]
    
    def has_dangerous_capabilities(self) -> bool:
        """Check if driver has any high-risk capabilities."""
        DANGEROUS = {
            CapabilityType.ARBITRARY_WRITE,
            CapabilityType.PHYSICAL_MEMORY_WRITE,
            CapabilityType.PHYSICAL_MEMORY_MAP,
            CapabilityType.PROCESS_TERMINATE,
            CapabilityType.MSR_WRITE,
            CapabilityType.CALLBACK_REMOVAL,
            CapabilityType.DSE_BYPASS,
            CapabilityType.SHELLCODE_EXECUTION,
            CapabilityType.MAJOR_FUNCTION_HOOK,
        }
        return any(c.capability_type in DANGEROUS for c in self.capabilities)
    
    def has_hooks(self) -> bool:
        """Check if driver has hooked MajorFunctions."""
        return any(mf.is_hooked for mf in self.major_function_info)
    
    def generate_summary_because(self) -> str:
        """Generate a summary 'Because' tag for this driver."""
        reasons = []
        
        if self.has_dangerous_capabilities():
            cap_names = [c.capability_type.name for c in self.capabilities if c.confidence >= 0.7][:3]
            reasons.append(f"has dangerous capabilities ({', '.join(cap_names)})")
        
        if self.has_hooks():
            reasons.append("has hooked MajorFunction entries")
        
        if self.anti_forensic_indicators:
            af_names = [i.indicator_type.name for i in self.anti_forensic_indicators][:2]
            reasons.append(f"shows anti-forensic behavior ({', '.join(af_names)})")
        
        if self.signature_info and not self.signature_info.is_signed:
            reasons.append("is not digitally signed")
        
        if self.cross_view_status == "hidden":
            reasons.append("is hidden via DKOM")
        
        if not reasons:
            reasons.append("no significant risk factors detected")
        
        return f"Flagged BECAUSE: {' AND '.join(reasons)}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to SIEM-ready dictionary for JSON serialization."""
        # Safely convert timestamp
        timestamp_str = None
        if self.pe_timestamp_datetime:
            timestamp_str = self.pe_timestamp_datetime.isoformat()
        elif self.pe_timestamp:
            try:
                timestamp_str = datetime.fromtimestamp(self.pe_timestamp).isoformat()
            except (ValueError, OSError):
                timestamp_str = str(self.pe_timestamp)
        
        return {
            # Metadata
            "schema_version": "1.0",
            "analysis_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            
            # Identification
            "name": self.name,
            "base_address": hex(self.base_address),
            "size": self.size,
            "driver_path": self.driver_path,
            "service_name": self.service_name,
            
            # PE Info
            "pe_timestamp": timestamp_str,
            "pe_timestamp_raw": self.pe_timestamp,
            "pe_checksum": hex(self.pe_checksum) if self.pe_checksum else None,
            "entry_point": hex(self.entry_point) if self.entry_point else None,
            "image_size": self.image_size,
            
            # Hashes
            "md5_hash": self.md5_hash,
            "sha256_hash": self.sha256_hash,
            "imphash": self.imphash,
            
            # Signature
            "signature": self.signature_info.to_dict() if self.signature_info else None,
            
            # DRIVER_OBJECT
            "driver_object_address": hex(self.driver_object_address) if self.driver_object_address else None,
            "major_functions": {str(k): hex(v) for k, v in self.major_functions.items()},
            "major_function_info": [mf.to_dict() for mf in self.major_function_info],
            "ioctl_handlers": [h.to_dict() for h in self.ioctl_handlers],
            
            # Capabilities
            "capabilities": [c.to_dict() for c in self.capabilities],
            "capabilities_count": len(self.capabilities),
            "high_risk_capabilities_count": len(self.get_high_risk_capabilities()),
            
            # Anti-forensics
            "anti_forensic_indicators": [i.to_dict() for i in self.anti_forensic_indicators],
            "anti_forensic_count": len(self.anti_forensic_indicators),
            
            # Risk Assessment
            "risk_score": round(self.risk_score, 2),
            "risk_score_raw": round(self.risk_score_raw, 2),
            "legitimacy_bonus": round(self.legitimacy_bonus, 2),
            "risk_confidence": round(self.risk_confidence, 2),
            "risk_category": self.risk_category,
            "risk_factors": self.risk_factors,
            "risk_summary": self.generate_summary_because(),
            
            # Cross-view validation
            "cross_view": {
                "found_in_pslist": self.found_in_pslist,
                "found_in_driverscan": self.found_in_driverscan,
                "found_in_carving": self.found_in_carving,
                "status": self.cross_view_status,
            },
            
            # Known vulnerabilities
            "is_known_vulnerable": self.is_known_vulnerable,
            "known_cves": self.known_cves,
            "loldrivers_match": self.loldrivers_match,
            
            # Validation
            "is_valid_pe": self.is_valid_pe,
            "pe_validation_errors": self.pe_validation_errors,
            "enumeration_source": self.enumeration_source,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    def __repr__(self) -> str:
        return (
            f"DriverInfo(name='{self.name}', base={hex(self.base_address)}, "
            f"risk={self.risk_score:.1f}/{self.risk_category}, "
            f"caps={len(self.capabilities)}, af={len(self.anti_forensic_indicators)})"
        )


@dataclass
class CrossViewResult:
    """Result of cross-view validation."""
    
    hidden_drivers: List[DriverInfo] = field(default_factory=list)
    remnant_drivers: List[DriverInfo] = field(default_factory=list)
    verified_drivers: List[DriverInfo] = field(default_factory=list)
    
    # Sets for quick lookup
    pslist_names: Set[str] = field(default_factory=set)
    pslist_bases: Set[int] = field(default_factory=set)
    scanned_names: Set[str] = field(default_factory=set)
    scanned_bases: Set[int] = field(default_factory=set)
    carved_names: Set[str] = field(default_factory=set)
    carved_bases: Set[int] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "hidden_drivers": [d.name for d in self.hidden_drivers],
            "hidden_count": len(self.hidden_drivers),
            "remnant_drivers": [d.name for d in self.remnant_drivers],
            "remnant_count": len(self.remnant_drivers),
            "verified_drivers_count": len(self.verified_drivers),
            "dkom_detected": len(self.hidden_drivers) > 0,
        }


@dataclass
class AnalysisResult:
    """Complete analysis result with SIEM-ready output."""
    
    # Summary metrics
    memory_image_path: str = ""
    memory_image_hash: str = ""
    memory_image_size: int = 0
    analysis_start_time: Optional[datetime] = None
    analysis_end_time: Optional[datetime] = None
    analysis_duration_seconds: float = 0.0
    
    # Enumeration results
    total_drivers_analyzed: int = 0
    high_risk_drivers: int = 0
    drivers_with_antiforensic: int = 0
    drivers_with_hooks: int = 0
    
    # Cross-view results
    cross_view_result: Optional[CrossViewResult] = None
    hidden_drivers_detected: int = 0
    remnant_drivers_detected: int = 0
    
    # Driver list
    drivers: List[DriverInfo] = field(default_factory=list)
    
    # Warnings and errors
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    # Configuration
    volatility_available: bool = False
    analysis_config: Dict[str, Any] = field(default_factory=dict)
    
    def add_driver(self, driver: DriverInfo):
        """Add a driver and update statistics."""
        self.drivers.append(driver)
        self.total_drivers_analyzed = len(self.drivers)
        
        if driver.risk_score >= 7.0:
            self.high_risk_drivers += 1
        
        if driver.anti_forensic_indicators:
            self.drivers_with_antiforensic += 1
        
        if driver.has_hooks():
            self.drivers_with_hooks += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to SIEM-ready dictionary."""
        return {
            "schema_version": "1.0",
            "tool": "iKARMA",
            "tool_version": "2.0.0",
            
            "metadata": {
                "memory_image_path": self.memory_image_path,
                "memory_image_hash": self.memory_image_hash,
                "memory_image_size": self.memory_image_size,
                "analysis_start_time": self.analysis_start_time.isoformat() if self.analysis_start_time else None,
                "analysis_end_time": self.analysis_end_time.isoformat() if self.analysis_end_time else None,
                "analysis_duration_seconds": round(self.analysis_duration_seconds, 2),
                "volatility_available": self.volatility_available,
            },
            
            "summary": {
                "total_drivers_analyzed": self.total_drivers_analyzed,
                "high_risk_drivers": self.high_risk_drivers,
                "drivers_with_antiforensic": self.drivers_with_antiforensic,
                "drivers_with_hooks": self.drivers_with_hooks,
                "hidden_drivers_detected": self.hidden_drivers_detected,
                "remnant_drivers_detected": self.remnant_drivers_detected,
            },
            
            "cross_view_validation": self.cross_view_result.to_dict() if self.cross_view_result else None,
            
            "drivers": [d.to_dict() for d in self.drivers],
            
            "warnings": self.warnings,
            "errors": self.errors,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
