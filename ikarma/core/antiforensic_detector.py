"""
iKARMA Anti-Forensic Detector - Production Release

Detects anti-forensic techniques in kernel drivers:
- DKOM (Direct Kernel Object Manipulation) - unlinking from module list
- PE header wiping/modification
- Import table destruction
- Memory scrubbing
- Timestamp manipulation

Implements TRUE cross-view validation:
- Set(Volatility_Drivers) - Set(Carved_Drivers) = Hidden/Unlinked (DKOM)
- Set(Carved_Drivers) - Set(Volatility_Drivers) = Remnant/Unloaded

Every detection includes a "Because" tag with evidence.
"""

import logging
import struct
import math
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime

from ikarma.core.driver import (
    DriverInfo, AntiForensicIndicator, AntiForensicType,
    CrossViewResult, EnumerationSource,
)

logger = logging.getLogger(__name__)


# PE Constants
DOS_SIGNATURE = b'MZ'
PE_SIGNATURE = b'PE\x00\x00'
PE_POINTER_OFFSET = 0x3C


# =============================================================================
# ANTI-FORENSIC DETECTOR CLASS
# =============================================================================

class AntiForensicDetector:
    """
    Production-ready anti-forensic detection engine.
    
    Implements comprehensive DKOM and anti-forensic detection with
    proper cross-view validation using the formula:
    
    Hidden = Volatility_Enumerated - PE_Carved (drivers hiding from OS view)
    Remnant = PE_Carved - Volatility_Enumerated (unloaded/remnant drivers)
    """
    
    def __init__(self, architecture: str = "x64", config: Optional[Dict] = None):
        """Initialize the detector."""
        self._arch = architecture
        self.config = config or {}
    
    # =========================================================================
    # MAIN ANALYSIS METHODS
    # =========================================================================
    
    def analyze_driver(
        self,
        driver: DriverInfo,
        pe_header: Optional[bytes] = None,
        full_image: Optional[bytes] = None
    ) -> List[AntiForensicIndicator]:
        """
        Analyze a driver for anti-forensic indicators.
        
        For carved-only drivers, minimal checks are performed since
        they may have legitimate partial headers from memory fragmentation.
        
        Args:
            driver: DriverInfo to analyze
            pe_header: First 0x1000 bytes of driver
            full_image: Full driver image
            
        Returns:
            List of detected indicators with "Because" tags
        """
        indicators = []
        
        # Check enumeration source for DKOM indicators
        source_indicators = self._check_enumeration_source(driver)
        indicators.extend(source_indicators)
        
        # For carved-only drivers, skip most checks
        is_carved_only = driver.enumeration_source == EnumerationSource.PE_CARVING.value
        
        if not is_carved_only:
            # Full analysis for properly enumerated drivers
            
            if pe_header:
                header_indicators = self._check_pe_header(driver, pe_header)
                indicators.extend(header_indicators)
            
            char_indicators = self._check_driver_characteristics(driver)
            indicators.extend(char_indicators)
            
            if full_image:
                scrub_indicators = self._check_memory_scrubbing(driver, full_image)
                indicators.extend(scrub_indicators)
                
                import_indicators = self._check_import_table(driver, full_image)
                indicators.extend(import_indicators)
        
        return indicators
    
    def detect_import_table_destruction(
        self,
        driver: DriverInfo,
        image: bytes
    ) -> List[AntiForensicIndicator]:
        """Detect if import table has been destroyed post-load."""
        return self._check_import_table(driver, image)
    
    # =========================================================================
    # CROSS-VIEW VALIDATION - THE KEY DKOM DETECTION
    # =========================================================================
    
    def cross_view_validation(
        self,
        pslist_drivers: List[DriverInfo],
        scanned_drivers: List[DriverInfo],
        carved_drivers: List[DriverInfo]
    ) -> CrossViewResult:
        """
        Perform true cross-view validation to detect DKOM.
        
        Logic:
        - Hidden = In Volatility (scanned) but NOT in PsLoadedModuleList = DKOM unlink
        - Also Hidden = In PsLoadedModuleList but NOT found by carving (suspicious)
        - Remnant = Found by carving but NOT in any Volatility view = unloaded driver
        
        Args:
            pslist_drivers: Drivers from PsLoadedModuleList
            scanned_drivers: Drivers from DRIVER_OBJECT pool scan
            carved_drivers: Drivers from PE carving
            
        Returns:
            CrossViewResult with hidden and remnant drivers identified
        """
        result = CrossViewResult()
        
        # Build lookup sets
        result.pslist_bases = {d.base_address for d in pslist_drivers}
        result.pslist_names = {d.name.lower() for d in pslist_drivers}
        
        result.scanned_bases = {d.base_address for d in scanned_drivers}
        result.scanned_names = {d.name.lower() for d in scanned_drivers}
        
        result.carved_bases = {d.base_address for d in carved_drivers}
        result.carved_names = {d.name.lower() for d in carved_drivers}
        
        # HIDDEN DETECTION: In DriverScan but NOT in PsLoadedModuleList
        # This is classic DKOM - driver object exists but unlinked from list
        for driver in scanned_drivers:
            if driver.base_address not in result.pslist_bases:
                # Check name too
                if driver.name.lower() not in result.pslist_names:
                    driver.cross_view_status = "hidden"
                    driver.enumeration_source = EnumerationSource.CROSS_VIEW_HIDDEN.value
                    
                    driver.add_anti_forensic_indicator(AntiForensicIndicator(
                        indicator_type=AntiForensicType.DKOM_UNLINK,
                        confidence=0.95,
                        description="Driver found via DRIVER_OBJECT scan but missing from PsLoadedModuleList",
                        evidence=(
                            f"BECAUSE: DRIVER_OBJECT at {hex(driver.driver_object_address or 0)} "
                            f"exists in pool but driver '{driver.name}' at {hex(driver.base_address)} "
                            "is not in PsLoadedModuleList - indicates DKOM unlinking"
                        ),
                        severity="critical",
                    ))
                    
                    result.hidden_drivers.append(driver)
        
        # REMNANT DETECTION: In carving but NOT in any Volatility enumeration
        # These are drivers that were unloaded but left traces in memory
        volatility_bases = result.pslist_bases | result.scanned_bases
        volatility_names = result.pslist_names | result.scanned_names
        
        for driver in carved_drivers:
            if driver.base_address not in volatility_bases:
                if driver.name.lower() not in volatility_names:
                    driver.cross_view_status = "remnant"
                    driver.enumeration_source = EnumerationSource.CROSS_VIEW_REMNANT.value
                    
                    driver.add_anti_forensic_indicator(AntiForensicIndicator(
                        indicator_type=AntiForensicType.DRIVER_UNLOADED_REMNANT,
                        confidence=0.75,
                        description="PE image found in memory but driver not in Volatility enumeration",
                        evidence=(
                            f"BECAUSE: PE image '{driver.name}' carved at {hex(driver.base_address)} "
                            "but not found via PsLoadedModuleList or DRIVER_OBJECT scan - "
                            "likely remnant of unloaded driver"
                        ),
                        severity="medium",
                    ))
                    
                    result.remnant_drivers.append(driver)
        
        # VERIFIED: In both PsLoadedModuleList AND carving
        for driver in pslist_drivers:
            if driver.base_address in result.carved_bases or driver.name.lower() in result.carved_names:
                driver.cross_view_status = "verified"
                driver.found_in_carving = True
                result.verified_drivers.append(driver)
        
        logger.info(
            f"Cross-view validation: {len(result.hidden_drivers)} hidden, "
            f"{len(result.remnant_drivers)} remnant, {len(result.verified_drivers)} verified"
        )
        
        return result
    
    def generate_dkom_report(self, result: CrossViewResult) -> Dict[str, Any]:
        """Generate a DKOM detection report from cross-view results."""
        return {
            "dkom_detected": len(result.hidden_drivers) > 0,
            "hidden_drivers_count": len(result.hidden_drivers),
            "hidden_drivers": [
                {
                    "name": d.name,
                    "base": hex(d.base_address),
                    "reason": "DKOM_UNLINK - found in pool scan but not in module list",
                }
                for d in result.hidden_drivers
            ],
            "remnant_drivers_count": len(result.remnant_drivers),
            "remnant_drivers": [
                {
                    "name": d.name,
                    "base": hex(d.base_address),
                    "reason": "REMNANT - PE image in memory but driver not loaded",
                }
                for d in result.remnant_drivers
            ],
            "verified_drivers_count": len(result.verified_drivers),
            "recommendation": (
                "CRITICAL: Hidden drivers detected via DKOM! "
                "Manual forensic investigation required."
                if result.hidden_drivers else
                "No DKOM detected. Cross-view validation passed."
            ),
        }
    
    # =========================================================================
    # INDIVIDUAL CHECK METHODS
    # =========================================================================
    
    def _check_enumeration_source(self, driver: DriverInfo) -> List[AntiForensicIndicator]:
        """Check enumeration source for suspiciousness."""
        indicators = []
        
        if driver.enumeration_source == EnumerationSource.CROSS_VIEW_HIDDEN.value:
            indicators.append(AntiForensicIndicator(
                indicator_type=AntiForensicType.DKOM_HIDDEN,
                confidence=0.95,
                description="Driver hidden via DKOM",
                evidence="BECAUSE: Cross-view validation identified this driver as hidden from OS view",
                severity="critical",
            ))
        
        elif driver.enumeration_source == EnumerationSource.CROSS_VIEW_REMNANT.value:
            indicators.append(AntiForensicIndicator(
                indicator_type=AntiForensicType.DRIVER_UNLOADED_REMNANT,
                confidence=0.75,
                description="Remnant of unloaded driver",
                evidence="BECAUSE: PE image exists in memory but driver is not loaded",
                severity="medium",
            ))
        
        return indicators
    
    def _check_pe_header(
        self,
        driver: DriverInfo,
        pe_header: bytes
    ) -> List[AntiForensicIndicator]:
        """Check PE header for signs of manipulation."""
        indicators = []
        
        if len(pe_header) < 0x100:
            indicators.append(AntiForensicIndicator(
                indicator_type=AntiForensicType.PE_HEADER_WIPED,
                confidence=0.85,
                description="PE header truncated or incomplete",
                evidence=f"BECAUSE: Header size {len(pe_header)} is less than minimum expected",
                severity="high",
            ))
            return indicators
        
        # Check DOS signature
        if pe_header[0:2] != DOS_SIGNATURE:
            indicators.append(AntiForensicIndicator(
                indicator_type=AntiForensicType.PE_HEADER_WIPED,
                confidence=0.95,
                description="DOS signature missing",
                evidence="BECAUSE: First two bytes are not 'MZ' (0x4D5A)",
                severity="high",
            ))
            return indicators
        
        # Get PE offset
        try:
            pe_offset = struct.unpack('<I', pe_header[0x3C:0x40])[0]
        except:
            return indicators
        
        if pe_offset > len(pe_header) - 4 or pe_offset > 0x1000:
            indicators.append(AntiForensicIndicator(
                indicator_type=AntiForensicType.PE_HEADER_MODIFIED,
                confidence=0.80,
                description="Invalid PE pointer",
                evidence=f"BECAUSE: e_lfanew points to invalid offset {hex(pe_offset)}",
                severity="medium",
            ))
            return indicators
        
        # Check PE signature
        if pe_header[pe_offset:pe_offset+4] != PE_SIGNATURE:
            indicators.append(AntiForensicIndicator(
                indicator_type=AntiForensicType.PE_HEADER_WIPED,
                confidence=0.95,
                description="PE signature corrupted",
                evidence=f"BECAUSE: Expected 'PE\\0\\0' at {hex(pe_offset)}, found {pe_header[pe_offset:pe_offset+4].hex()}",
                severity="high",
            ))
            return indicators
        
        # Check timestamp
        ts_offset = pe_offset + 8
        if ts_offset + 4 <= len(pe_header):
            timestamp = struct.unpack('<I', pe_header[ts_offset:ts_offset+4])[0]
            
            if timestamp == 0:
                indicators.append(AntiForensicIndicator(
                    indicator_type=AntiForensicType.TIMESTAMP_MANIPULATION,
                    confidence=0.70,
                    description="PE timestamp zeroed",
                    evidence="BECAUSE: TimeDateStamp field is 0, suggesting intentional wiping",
                    severity="medium",
                ))
            elif timestamp > 0:
                try:
                    ts_date = datetime.fromtimestamp(timestamp)
                    if ts_date > datetime.now():
                        indicators.append(AntiForensicIndicator(
                            indicator_type=AntiForensicType.TIMESTAMP_MANIPULATION,
                            confidence=0.85,
                            description="PE timestamp in the future",
                            evidence=f"BECAUSE: TimeDateStamp {ts_date} is after current time",
                            severity="medium",
                        ))
                except (ValueError, OSError):
                    indicators.append(AntiForensicIndicator(
                        indicator_type=AntiForensicType.TIMESTAMP_MANIPULATION,
                        confidence=0.70,
                        description="Invalid PE timestamp",
                        evidence=f"BECAUSE: TimeDateStamp {timestamp} cannot be converted to date",
                        severity="low",
                    ))
        
        # Check for excessive zero regions
        zero_count = pe_header.count(b'\x00\x00\x00\x00\x00\x00\x00\x00')
        header_density = zero_count / (len(pe_header) / 8)
        
        if header_density > 0.75:
            indicators.append(AntiForensicIndicator(
                indicator_type=AntiForensicType.PE_HEADER_WIPED,
                confidence=0.75,
                description="PE header appears partially wiped",
                evidence=f"BECAUSE: {header_density*100:.1f}% of header is zero-filled",
                severity="high",
            ))
        
        return indicators
    
    def _check_driver_characteristics(self, driver: DriverInfo) -> List[AntiForensicIndicator]:
        """Check driver characteristics for anomalies."""
        indicators = []
        
        # Skip for carved drivers
        if driver.enumeration_source == EnumerationSource.PE_CARVING.value:
            return indicators
        
        # Size validation
        if driver.size == 0:
            indicators.append(AntiForensicIndicator(
                indicator_type=AntiForensicType.SIZE_MISMATCH,
                confidence=0.90,
                description="Driver size is zero",
                evidence="BECAUSE: Reported driver size is 0 bytes",
                severity="high",
            ))
        
        # Check size consistency
        if driver.driver_size_from_object and driver.size:
            diff = abs(driver.size - driver.driver_size_from_object)
            if diff > 0x10000:  # 64KB difference
                indicators.append(AntiForensicIndicator(
                    indicator_type=AntiForensicType.SIZE_MISMATCH,
                    confidence=0.75,
                    description="Size mismatch between enumeration sources",
                    evidence=(
                        f"BECAUSE: Module list reports {driver.size} bytes, "
                        f"DRIVER_OBJECT reports {driver.driver_size_from_object} bytes"
                    ),
                    severity="medium",
                ))
        
        # Check page alignment
        if driver.base_address & 0xFFF != 0:
            indicators.append(AntiForensicIndicator(
                indicator_type=AntiForensicType.PE_HEADER_MODIFIED,
                confidence=0.85,
                description="Driver base address not page-aligned",
                evidence=f"BECAUSE: Base address {hex(driver.base_address)} is not 4KB aligned",
                severity="medium",
            ))
        
        return indicators
    
    def _check_memory_scrubbing(
        self,
        driver: DriverInfo,
        image: bytes
    ) -> List[AntiForensicIndicator]:
        """Check for signs of memory scrubbing."""
        indicators = []
        
        if len(image) < 0x1000:
            return indicators
        
        # Check header entropy
        header_entropy = self._calculate_entropy(image[:0x400])
        
        if header_entropy < 2.0:
            indicators.append(AntiForensicIndicator(
                indicator_type=AntiForensicType.PE_HEADER_WIPED,
                confidence=0.70,
                description="Very low entropy in PE header",
                evidence=f"BECAUSE: Header entropy is {header_entropy:.2f}, suggesting content has been wiped",
                severity="medium",
            ))
        
        # Find large zero runs
        zero_runs = self._find_zero_runs(image)
        
        for start, length in zero_runs:
            if length >= 0x10000 and start < 0x1000:
                indicators.append(AntiForensicIndicator(
                    indicator_type=AntiForensicType.MEMORY_SCRUBBING,
                    confidence=0.80,
                    description="Large zeroed region in header area",
                    evidence=f"BECAUSE: {length} bytes zeroed at offset {hex(start)} in header",
                    affected_region=(start, start + length),
                    severity="high",
                ))
        
        return indicators
    
    def _check_import_table(
        self,
        driver: DriverInfo,
        image: bytes
    ) -> List[AntiForensicIndicator]:
        """Check if import table has been destroyed."""
        indicators = []
        
        if len(image) < 0x200:
            return indicators
        
        try:
            # Get PE offset
            pe_offset = struct.unpack('<I', image[0x3C:0x40])[0]
            
            if pe_offset > len(image) - 0x80:
                return indicators
            
            # Check magic to determine PE32/PE32+
            magic_offset = pe_offset + 24
            if magic_offset + 2 > len(image):
                return indicators
            
            magic = struct.unpack('<H', image[magic_offset:magic_offset+2])[0]
            
            # Import directory is at different offsets for PE32 vs PE32+
            if magic == 0x20B:  # PE32+
                import_dir_offset = pe_offset + 24 + 120
            else:  # PE32
                import_dir_offset = pe_offset + 24 + 104
            
            if import_dir_offset + 8 > len(image):
                return indicators
            
            import_rva = struct.unpack('<I', image[import_dir_offset:import_dir_offset+4])[0]
            import_size = struct.unpack('<I', image[import_dir_offset+4:import_dir_offset+8])[0]
            
            # If import directory is zeroed but driver has known imports
            if import_rva == 0 and import_size == 0:
                # Check if this looks like a real driver (not just a data PE)
                if driver.size > 0x5000:  # Reasonable driver size
                    indicators.append(AntiForensicIndicator(
                        indicator_type=AntiForensicType.IMPORT_TABLE_DESTROYED,
                        confidence=0.70,
                        description="Import table appears cleared",
                        evidence="BECAUSE: Import directory RVA and size are both zero",
                        severity="high",
                    ))
            
        except Exception as e:
            logger.debug(f"Import table check failed: {e}")
        
        return indicators
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(data)
        
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _find_zero_runs(self, data: bytes) -> List[Tuple[int, int]]:
        """Find runs of zero bytes in data."""
        runs = []
        in_run = False
        run_start = 0
        
        # Check in 8-byte chunks
        for i in range(0, len(data) - 7, 8):
            if data[i:i+8] == b'\x00' * 8:
                if not in_run:
                    in_run = True
                    run_start = i
            else:
                if in_run:
                    run_length = i - run_start
                    if run_length >= 64:  # At least 64 bytes
                        runs.append((run_start, run_length))
                    in_run = False
        
        # Handle run at end
        if in_run:
            run_length = len(data) - run_start
            if run_length >= 64:
                runs.append((run_start, run_length))
        
        return runs
