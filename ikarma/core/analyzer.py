"""
iKARMA Analyzer - Production Release

Main analysis coordinator that orchestrates:
- Memory parsing (Volatility3 + PE carving)
- Cross-view validation (DKOM detection)
- Capability detection
- Anti-forensic detection
- Risk scoring with legitimacy bonus
- Hook detection

All findings include "Because" tags for forensic defensibility.
"""

import logging
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime, timezone

from ikarma.core.driver import (
    DriverInfo, DriverCapability, AntiForensicIndicator,
    AnalysisResult, CrossViewResult, SignatureInfo,
)
from ikarma.core.memory_parser import MemoryParser
from ikarma.core.capability_engine import CapabilityEngine
from ikarma.core.antiforensic_detector import AntiForensicDetector
from ikarma.core.risk_scorer import RiskScorer
from ikarma.core.loldrivers import LOLDriversMatcher
from ikarma.byovd_bridge import scan_dangerous_apis

logger = logging.getLogger(__name__)


class Analyzer:
    """
    Production-ready kernel driver analyzer.
    
    Orchestrates all analysis components to produce comprehensive
    driver risk assessments with full forensic defensibility.
    
    Analysis Pipeline:
    1. Initialize memory parser (Volatility3 or fallback)
    2. Enumerate drivers via multiple methods
    3. Perform cross-view validation for DKOM detection
    4. Extract and analyze IOCTL handlers
    5. Detect capabilities from code patterns
    6. Detect anti-forensic indicators
    7. Match against known vulnerable drivers
    8. Calculate risk scores with legitimacy bonus
    9. Generate comprehensive report
    """
    
    def __init__(self, memory_path: str, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the analyzer.
        
        Args:
            memory_path: Path to memory dump file
            config: Optional configuration dictionary
        """
        self.memory_path = Path(memory_path).resolve()
        self.config = config or {}
        
        # Component initialization
        self.memory_parser: Optional[MemoryParser] = None
        self.capability_engine: Optional[CapabilityEngine] = None
        self.antiforensic_detector: Optional[AntiForensicDetector] = None
        self.risk_scorer: Optional[RiskScorer] = None
        self.loldrivers_matcher: Optional[LOLDriversMatcher] = None
        
        # State
        self._is_initialized = False
        self._architecture = "x64"
        
        # Results
        self._result: Optional[AnalysisResult] = None
    
    def initialize(self) -> bool:
        """
        Initialize all analysis components.
        
        Returns:
            True if initialization successful
        """
        logger.info(f"Initializing analyzer for: {self.memory_path}")
        
        if not self.memory_path.exists():
            logger.error(f"Memory file not found: {self.memory_path}")
            return False
        
        try:
            # Initialize memory parser
            self.memory_parser = MemoryParser(str(self.memory_path))
            if not self.memory_parser.initialize():
                logger.warning("Memory parser initialization incomplete")
            
            # Get architecture
            self._architecture = "x64" if self.memory_parser._pointer_size == 8 else "x86"
            
            # Initialize other components
            self.capability_engine = CapabilityEngine(self._architecture, self.config)
            self.antiforensic_detector = AntiForensicDetector(self._architecture, self.config)
            self.risk_scorer = RiskScorer(self.config)
            
            # Initialize LOLDrivers matcher
            self.loldrivers_matcher = LOLDriversMatcher()
            self.loldrivers_matcher.load_database()
            
            self._is_initialized = True
            logger.info(f"Analyzer initialized - arch: {self._architecture}, volatility: {self.memory_parser.volatility_available}")
            
            return True
            
        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            return False
    
    def analyze(self) -> AnalysisResult:
        """
        Perform comprehensive driver analysis.
        
        Returns:
            AnalysisResult with all drivers and findings
        """
        if not self._is_initialized:
            if not self.initialize():
                return self._create_error_result("Initialization failed")
        
        result = AnalysisResult()
        result.analysis_start_time = datetime.now(timezone.utc)
        result.memory_image_path = str(self.memory_path)
        result.memory_image_size = self.memory_parser.get_memory_size()
        result.volatility_available = self.memory_parser.volatility_available
        
        try:
            # Step 1: Enumerate drivers from multiple sources
            logger.info("Step 1: Enumerating drivers...")
            pslist_drivers, scanned_drivers, carved_drivers = self._enumerate_all_drivers()
            
            result.analysis_config = {
                "pslist_count": len(pslist_drivers),
                "scanned_count": len(scanned_drivers),
                "carved_count": len(carved_drivers),
                "volatility_mode": not self.memory_parser.is_fallback_mode,
            }
            
            # Step 2: Cross-view validation for DKOM detection
            logger.info("Step 2: Cross-view validation...")
            cross_view = self._perform_cross_view_validation(
                pslist_drivers, scanned_drivers, carved_drivers
            )
            result.cross_view_result = cross_view
            result.hidden_drivers_detected = len(cross_view.hidden_drivers)
            result.remnant_drivers_detected = len(cross_view.remnant_drivers)
            
            # Step 3: Merge and deduplicate drivers
            logger.info("Step 3: Merging driver lists...")
            all_drivers = self._merge_driver_lists(
                pslist_drivers, scanned_drivers, carved_drivers, cross_view
            )
            
            # Step 4: Analyze each driver
            logger.info(f"Step 4: Analyzing {len(all_drivers)} drivers...")
            for i, driver in enumerate(all_drivers):
                if i % 20 == 0:
                    logger.info(f"  Analyzing driver {i+1}/{len(all_drivers)}: {driver.name}")
                
                self._analyze_single_driver(driver)
                result.add_driver(driver)
            
            # Step 5: Compute memory image hash
            logger.info("Step 5: Computing image hash...")
            result.memory_image_hash = self.memory_parser.get_memory_hash()
            
            result.analysis_end_time = datetime.now(timezone.utc)
            result.analysis_duration_seconds = (
                result.analysis_end_time - result.analysis_start_time
            ).total_seconds()
            
            self._result = result
            
            logger.info(
                f"Analysis complete: {result.total_drivers_analyzed} drivers, "
                f"{result.high_risk_drivers} high risk, {result.hidden_drivers_detected} hidden"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            result.errors.append(str(e))
            return result
    
    def _enumerate_all_drivers(self) -> Tuple[List[DriverInfo], List[DriverInfo], List[DriverInfo]]:
        """Enumerate drivers from all available sources."""
        pslist_drivers = []
        scanned_drivers = []
        carved_drivers = []
        
        # Try Volatility3 enumeration
        if self.memory_parser.volatility_available:
            pslist_drivers = self.memory_parser.enumerate_drivers_volatility()
            scanned_drivers = self.memory_parser.enumerate_drivers_scan()
        
        # Always do PE carving for cross-view validation
        carved_drivers = self.memory_parser.enumerate_drivers_carving()
        
        # If Volatility3 failed completely, carved drivers are our primary source
        if not pslist_drivers and not scanned_drivers:
            logger.warning("Volatility3 enumeration returned no results - using carving only")
        
        return pslist_drivers, scanned_drivers, carved_drivers
    
    def _perform_cross_view_validation(
        self,
        pslist_drivers: List[DriverInfo],
        scanned_drivers: List[DriverInfo],
        carved_drivers: List[DriverInfo]
    ) -> CrossViewResult:
        """Perform cross-view validation to detect DKOM."""
        return self.antiforensic_detector.cross_view_validation(
            pslist_drivers, scanned_drivers, carved_drivers
        )
    
    def _merge_driver_lists(
        self,
        pslist_drivers: List[DriverInfo],
        scanned_drivers: List[DriverInfo],
        carved_drivers: List[DriverInfo],
        cross_view: CrossViewResult
    ) -> List[DriverInfo]:
        """Merge driver lists, avoiding duplicates."""
        seen_bases = set()
        merged = []
        
        # Priority 1: PsLoadedModuleList (most authoritative)
        for driver in pslist_drivers:
            if driver.base_address not in seen_bases:
                seen_bases.add(driver.base_address)
                merged.append(driver)
        
        # Priority 2: Hidden drivers from cross-view (DKOM detected)
        for driver in cross_view.hidden_drivers:
            if driver.base_address not in seen_bases:
                seen_bases.add(driver.base_address)
                merged.append(driver)
        
        # Priority 3: Scanned drivers not already seen
        for driver in scanned_drivers:
            if driver.base_address not in seen_bases:
                # Merge MajorFunction info into existing if found
                existing = next((d for d in merged if d.name.lower() == driver.name.lower()), None)
                if existing:
                    if driver.major_functions and not existing.major_functions:
                        existing.major_functions = driver.major_functions
                        existing.major_function_info = driver.major_function_info
                        existing.driver_object_address = driver.driver_object_address
                else:
                    seen_bases.add(driver.base_address)
                    merged.append(driver)
        
        # Priority 4: Remnant drivers
        for driver in cross_view.remnant_drivers:
            if driver.base_address not in seen_bases:
                seen_bases.add(driver.base_address)
                merged.append(driver)
        
        # Priority 5: Carved drivers not already seen (additional coverage)
        for driver in carved_drivers:
            if driver.base_address not in seen_bases:
                # Only add if not already represented by name
                if not any(d.name.lower() == driver.name.lower() for d in merged):
                    seen_bases.add(driver.base_address)
                    merged.append(driver)
        
        return merged
    
    def _analyze_single_driver(self, driver: DriverInfo):
        """Perform complete analysis on a single driver."""
        
        # Read driver image
        image = self._read_driver_image(driver)
        pe_header = image[:0x1000] if image and len(image) >= 0x1000 else None
        
        # Extract IOCTL handlers
        self._extract_handlers(driver)
        
        # Detect capabilities
        self._detect_capabilities(driver, image)

        # BYOVD/IOCTL dangerous API analysis (legacy scanner integration)
        if self.config.get("byovd_enabled", True):
            self._detect_byovd_capabilities(driver)
        
        # Detect anti-forensic indicators
        self._detect_antiforensics(driver, pe_header, image)
        
        # Check for hooks
        self._check_hooks(driver)
        
        # Match against known vulnerable drivers
        self._match_loldrivers(driver)
        
        # Get signature info (simulated - would need actual verification)
        self._check_signature(driver, image)
        
        # Calculate risk score
        self.risk_scorer.score_driver(driver)
    
    def _read_driver_image(self, driver: DriverInfo) -> Optional[bytes]:
        """Read driver image from memory."""
        if driver.base_address == 0:
            return None
        
        # Limit read size
        read_size = min(driver.size or 0x100000, 0x200000)  # Max 2MB
        if read_size < 0x1000:
            read_size = 0x100000  # Default to 1MB
        
        return self.memory_parser.read_memory(driver.base_address, read_size)
    
    def _extract_handlers(self, driver: DriverInfo):
        """Extract IOCTL and other handlers from driver."""
        if driver.major_functions:
            handlers = self.memory_parser.extract_all_handlers(driver)
            driver.ioctl_handlers = handlers
        else:
            # Fall back to extracting from entry point
            handler = self.memory_parser.extract_ioctl_handler(driver)
            if handler:
                driver.ioctl_handlers = [handler]
    
    def _detect_capabilities(self, driver: DriverInfo, image: Optional[bytes]):
        """Detect driver capabilities."""
        capabilities = []
        
        # Analyze IOCTL handlers
        for handler in driver.ioctl_handlers:
            handler_caps = self.capability_engine.analyze_handler(handler)
            capabilities.extend(handler_caps)
        
        # Analyze full image if available
        if image and len(image) > 0x200:
            image_caps = self.capability_engine.analyze_image(image, driver.base_address)
            capabilities.extend(image_caps)
        
        # Deduplicate
        seen = set()
        for cap in capabilities:
            key = (cap.capability_type, cap.handler_offset)
            if key not in seen:
                seen.add(key)
                driver.add_capability(cap)

    def _detect_byovd_capabilities(self, driver: DriverInfo):
        """
        Run legacy BYOVD dangerous API scanner against IOCTL handlers and
        translate findings into capabilities.
        """
        from ikarma.core.driver import CapabilityType, ConfidenceLevel, DriverCapability

        if not driver.ioctl_handlers:
            return

        detailed = self.config.get("byovd_detailed", False)

        category_map = {
            "MEMORY_ACCESS": CapabilityType.ARBITRARY_READ,
            "PHYSICAL_MEMORY": CapabilityType.PHYSICAL_MEMORY_MAP,
            "PROCESS": CapabilityType.PROCESS_TERMINATE,
            "CALLBACK": CapabilityType.CALLBACK_REMOVAL,
            "REGISTRY_FILE": CapabilityType.KERNEL_REGISTRY_ACCESS,
            "KERNEL_OBJECTS": CapabilityType.EPROCESS_MANIPULATION,
            "SECURITY": CapabilityType.DSE_BYPASS,
        }

        for handler in driver.ioctl_handlers:
            findings = scan_dangerous_apis(handler.disassembly or [])
            if not findings:
                continue

            for finding in findings:
                name = finding.get("name", "unknown_api")
                category = (finding.get("category") or "UNKNOWN").upper()
                method = finding.get("method", "unknown")
                risk_weight = float(finding.get("risk", 3))

                cap_type = category_map.get(category, CapabilityType.UNKNOWN)

                # Map confidence to our enum
                confidence = float(finding.get("confidence", 0.5))
                if confidence >= 0.85:
                    confidence_level = ConfidenceLevel.HIGH
                elif confidence >= 0.65:
                    confidence_level = ConfidenceLevel.MEDIUM
                elif confidence >= 0.45:
                    confidence_level = ConfidenceLevel.LOW
                else:
                    confidence_level = ConfidenceLevel.SPECULATIVE

                evidence_parts = [
                    f"Detected {name} via {method} match",
                ]
                if finding.get("instruction"):
                    evidence_parts.append(finding["instruction"])
                if finding.get("address"):
                    evidence_parts.append(f"@ {finding['address']}")
                if detailed and finding.get("why_dangerous"):
                    evidence_parts.append(finding["why_dangerous"])

                cap = DriverCapability(
                    capability_type=cap_type,
                    confidence=confidence,
                    confidence_level=confidence_level,
                    description=f"Dangerous API: {name} ({category})",
                    evidence="; ".join(evidence_parts),
                    handler_address=handler.handler_address,
                    risk_weight=risk_weight,
                    exploitability="high" if risk_weight >= 8 else "medium",
                )
                driver.add_capability(cap)
    
    def _detect_antiforensics(
        self,
        driver: DriverInfo,
        pe_header: Optional[bytes],
        image: Optional[bytes]
    ):
        """Detect anti-forensic indicators."""
        indicators = self.antiforensic_detector.analyze_driver(driver, pe_header, image)
        
        for indicator in indicators:
            driver.add_anti_forensic_indicator(indicator)
    
    def _check_hooks(self, driver: DriverInfo):
        """Check for MajorFunction hooks and add as capabilities."""
        from ikarma.core.driver import CapabilityType, ConfidenceLevel, DriverCapability
        
        for mf in driver.major_function_info:
            if mf.is_hooked:
                cap = DriverCapability(
                    capability_type=CapabilityType.MAJOR_FUNCTION_HOOK,
                    confidence=0.95,
                    confidence_level=ConfidenceLevel.HIGH,
                    description=f"Hooked {mf._get_name()} handler",
                    evidence=mf.because,
                    handler_address=mf.handler_address,
                    risk_weight=9.0,
                    exploitability="high",
                )
                driver.add_capability(cap)
    
    def _match_loldrivers(self, driver: DriverInfo):
        """Match driver against LOLDrivers database."""
        if not self.loldrivers_matcher:
            return
        
        match = self.loldrivers_matcher.match_driver(driver)
        
        if match:
            driver.is_known_vulnerable = True
            driver.loldrivers_match = match
            driver.known_cves = match.get("cves", [])
    
    def _check_signature(self, driver: DriverInfo, image: Optional[bytes]):
        """Check driver signature status."""
        # This is a simplified check - full verification would need
        # authenticode parsing and certificate validation
        
        sig_info = SignatureInfo()
        
        # Heuristic: Microsoft drivers often have specific characteristics
        name_lower = driver.name.lower()
        path_lower = (driver.driver_path or "").lower()
        
        # Common Microsoft driver indicators
        microsoft_indicators = [
            "microsoft" in path_lower,
            "windows" in path_lower,
            "\\system32\\drivers\\" in path_lower,
            driver.imphash and driver.imphash in self._get_known_ms_imphashes(),
        ]
        
        if any(microsoft_indicators):
            sig_info.is_signed = True
            sig_info.signature_valid = True
            sig_info.is_microsoft_signed = True
            sig_info.signer_name = "Microsoft Windows"
        
        # Check for WHQL signed indicators
        whql_indicators = [
            "hardware compatibility" in path_lower,
            "whql" in path_lower,
        ]
        
        if any(whql_indicators):
            sig_info.is_whql_signed = True
            sig_info.signer_name = "Microsoft Windows Hardware Compatibility Publisher"
        
        driver.signature_info = sig_info
    
    def _get_known_ms_imphashes(self) -> set:
        """Get known Microsoft driver import hashes."""
        # This would be populated with known good Microsoft imphashes
        return set()
    
    def _create_error_result(self, error: str) -> AnalysisResult:
        """Create an error result."""
        result = AnalysisResult()
        result.errors.append(error)
        return result
    
    def get_high_risk_drivers(self, threshold: float = 7.0) -> List[DriverInfo]:
        """Get drivers above risk threshold."""
        if not self._result:
            return []
        
        return [d for d in self._result.drivers if d.risk_score >= threshold]
    
    def get_hidden_drivers(self) -> List[DriverInfo]:
        """Get DKOM-hidden drivers."""
        if not self._result or not self._result.cross_view_result:
            return []
        
        return self._result.cross_view_result.hidden_drivers
    
    def export_json(self, output_path: str, indent: int = 2):
        """Export analysis results to JSON file."""
        if not self._result:
            logger.error("No results to export")
            return
        
        import json
        
        with open(output_path, 'w') as f:
            json.dump(self._result.to_dict(), f, indent=indent, default=str)
        
        logger.info(f"Results exported to: {output_path}")
    
    def close(self):
        """Clean up resources."""
        if self.memory_parser:
            self.memory_parser.close()
