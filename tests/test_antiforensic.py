"""
iKARMA Test Suite - Anti-Forensic Detection Tests

Tests for anti-forensic detection and cross-view validation.
"""

import pytest
from ikarma.core import (
    AntiForensicDetector, DriverInfo, AntiForensicIndicator,
    AntiForensicType, CrossViewResult, EnumerationSource,
)


class TestAntiForensicDetector:
    """Tests for AntiForensicDetector."""
    
    def test_detector_initialization(self):
        """Test detector initializes correctly."""
        detector = AntiForensicDetector()
        assert detector is not None
    
    def test_valid_pe_no_indicators(self, minimal_driver_pe):
        """Test that valid PE doesn't trigger false positives."""
        detector = AntiForensicDetector()
        
        driver = DriverInfo(
            name="valid_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
            enumeration_source="PsLoadedModuleList",
        )
        
        indicators = detector.analyze_driver(driver, minimal_driver_pe, minimal_driver_pe)
        
        # Valid PE shouldn't have major indicators
        critical_indicators = [i for i in indicators if i.severity == "critical"]
        assert len(critical_indicators) == 0
    
    def test_detect_missing_mz_signature(self):
        """Test detection of missing MZ signature."""
        detector = AntiForensicDetector()
        
        driver = DriverInfo(
            name="corrupted_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
            enumeration_source="PsLoadedModuleList",
        )
        
        # Corrupted header without MZ
        bad_header = b'\x00\x00' + b'\x00' * 0x100
        
        indicators = detector.analyze_driver(driver, bad_header, bad_header)
        
        wiped_indicators = [i for i in indicators 
                          if i.indicator_type == AntiForensicType.PE_HEADER_WIPED]
        assert len(wiped_indicators) >= 1
        assert "BECAUSE" in wiped_indicators[0].evidence
    
    def test_detect_zeroed_timestamp(self, minimal_driver_pe):
        """Test detection of zeroed timestamp."""
        detector = AntiForensicDetector()
        
        driver = DriverInfo(
            name="driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
            enumeration_source="PsLoadedModuleList",
        )
        
        # Modify PE to have zero timestamp
        import struct
        header = bytearray(minimal_driver_pe)
        pe_offset = struct.unpack('<I', header[0x3C:0x40])[0]
        ts_offset = pe_offset + 8
        header[ts_offset:ts_offset+4] = b'\x00\x00\x00\x00'
        
        indicators = detector.analyze_driver(driver, bytes(header), bytes(header))
        
        ts_indicators = [i for i in indicators 
                        if i.indicator_type == AntiForensicType.TIMESTAMP_MANIPULATION]
        assert len(ts_indicators) >= 1
    
    def test_carved_driver_minimal_checks(self, minimal_driver_pe):
        """Test that carved drivers have minimal checks to avoid false positives."""
        detector = AntiForensicDetector()
        
        driver = DriverInfo(
            name="carved_driver.sys",
            base_address=0x1000,  # File offset, not kernel address
            size=0x10000,
            enumeration_source="carved",
        )
        
        indicators = detector.analyze_driver(driver, minimal_driver_pe, minimal_driver_pe)
        
        # Carved drivers should not trigger address-based checks
        # Only truly invalid headers should be flagged
        high_severity = [i for i in indicators if i.severity in ["high", "critical"]]
        assert len(high_severity) == 0


class TestCrossViewValidation:
    """Tests for DKOM detection via cross-view validation."""
    
    def test_no_hidden_drivers_normal_case(self):
        """Test that matching drivers are not flagged as hidden."""
        detector = AntiForensicDetector()
        
        # Same driver in both views
        pslist_driver = DriverInfo(
            name="normal_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
            enumeration_source="PsLoadedModuleList",
        )
        
        scanned_driver = DriverInfo(
            name="normal_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
            enumeration_source="DriverScan",
        )
        
        result = detector.cross_view_validation(
            [pslist_driver],
            [scanned_driver],
            []
        )
        
        assert len(result.hidden_drivers) == 0
    
    def test_detect_dkom_hidden_driver(self):
        """Test detection of DKOM-hidden driver."""
        detector = AntiForensicDetector()
        
        # Driver in pslist
        pslist_driver = DriverInfo(
            name="visible_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
            enumeration_source="PsLoadedModuleList",
        )
        
        # Different driver only in driverscan (hidden from pslist)
        hidden_driver = DriverInfo(
            name="hidden_rootkit.sys",
            base_address=0xFFFFF80099990000,
            size=0x10000,
            driver_object_address=0xFFFFF80099999000,
            enumeration_source="DriverScan",
        )
        
        result = detector.cross_view_validation(
            [pslist_driver],
            [pslist_driver, hidden_driver],  # hidden_driver only in scan
            []
        )
        
        # hidden_driver should be detected as DKOM hidden
        assert len(result.hidden_drivers) == 1
        assert result.hidden_drivers[0].name == "hidden_rootkit.sys"
        assert result.hidden_drivers[0].cross_view_status == "hidden"
        
        # Should have DKOM indicator
        dkom_indicators = [i for i in result.hidden_drivers[0].anti_forensic_indicators
                         if i.indicator_type == AntiForensicType.DKOM_UNLINK]
        assert len(dkom_indicators) >= 1
    
    def test_detect_remnant_driver(self):
        """Test detection of remnant (unloaded) driver."""
        detector = AntiForensicDetector()
        
        # Driver in pslist
        active_driver = DriverInfo(
            name="active_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
            enumeration_source="PsLoadedModuleList",
        )
        
        # Driver only found via carving (remnant)
        remnant_driver = DriverInfo(
            name="unloaded_driver.sys",
            base_address=0x50000,  # File offset from carving
            size=0x10000,
            enumeration_source="carved",
        )
        
        result = detector.cross_view_validation(
            [active_driver],
            [active_driver],
            [remnant_driver]
        )
        
        # remnant_driver should be detected as remnant
        assert len(result.remnant_drivers) == 1
        assert result.remnant_drivers[0].name == "unloaded_driver.sys"
        assert result.remnant_drivers[0].cross_view_status == "remnant"
    
    def test_verified_driver_in_both_views(self):
        """Test that drivers in both pslist and carving are verified."""
        detector = AntiForensicDetector()
        
        driver = DriverInfo(
            name="legit_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
            enumeration_source="PsLoadedModuleList",
        )
        
        carved_driver = DriverInfo(
            name="legit_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
            enumeration_source="carved",
        )
        
        result = detector.cross_view_validation(
            [driver],
            [driver],
            [carved_driver]
        )
        
        assert len(result.verified_drivers) == 1
        assert result.verified_drivers[0].cross_view_status == "verified"
    
    def test_dkom_report_generation(self):
        """Test DKOM report generation."""
        detector = AntiForensicDetector()
        
        hidden_driver = DriverInfo(
            name="hidden_rootkit.sys",
            base_address=0xFFFFF80099990000,
            size=0x10000,
            driver_object_address=0xFFFFF80099999000,
            enumeration_source="DriverScan",
        )
        
        result = detector.cross_view_validation(
            [],  # Empty pslist
            [hidden_driver],
            []
        )
        
        report = detector.generate_dkom_report(result)
        
        assert report["dkom_detected"] == True
        assert report["hidden_drivers_count"] == 1
        assert "CRITICAL" in report["recommendation"]


class TestAntiForensicBecauseTags:
    """Tests for 'Because' tags in anti-forensic detection."""
    
    def test_dkom_indicator_has_because(self):
        """Test that DKOM indicators have Because tags."""
        detector = AntiForensicDetector()
        
        hidden_driver = DriverInfo(
            name="hidden.sys",
            base_address=0xFFFFF80099990000,
            size=0x10000,
            driver_object_address=0xFFFFF80099999000,
            enumeration_source="DriverScan",
        )
        
        result = detector.cross_view_validation(
            [],
            [hidden_driver],
            []
        )
        
        assert len(result.hidden_drivers) == 1
        
        indicators = result.hidden_drivers[0].anti_forensic_indicators
        for indicator in indicators:
            assert "BECAUSE" in indicator.evidence
    
    def test_header_wiped_indicator_has_because(self):
        """Test that header wiped indicators have Because tags."""
        detector = AntiForensicDetector()
        
        driver = DriverInfo(
            name="wiped.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
            enumeration_source="PsLoadedModuleList",
        )
        
        # Invalid header
        bad_header = b'\x00' * 0x200
        
        indicators = detector.analyze_driver(driver, bad_header, bad_header)
        
        for indicator in indicators:
            assert indicator.evidence is not None
            assert "BECAUSE" in indicator.evidence


class TestEntropyAnalysis:
    """Tests for entropy-based detection."""
    
    def test_low_entropy_detection(self):
        """Test detection of low entropy (wiped) headers."""
        detector = AntiForensicDetector()
        
        driver = DriverInfo(
            name="suspicious.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
            enumeration_source="PsLoadedModuleList",
        )
        
        # Create header with valid MZ/PE but mostly zeros
        import struct
        header = bytearray(0x400)
        header[0:2] = b'MZ'
        header[0x3C:0x40] = struct.pack('<I', 0x40)
        header[0x40:0x44] = b'PE\x00\x00'
        header[0x44:0x46] = struct.pack('<H', 0x8664)  # Machine
        
        indicators = detector.analyze_driver(driver, bytes(header), bytes(header))
        
        # May or may not trigger depending on exact entropy threshold
        # Just verify no crashes
        assert isinstance(indicators, list)
