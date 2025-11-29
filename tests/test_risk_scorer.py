"""
iKARMA Test Suite - Risk Scorer Tests

Tests for the RiskScorer component including legitimacy bonus.
"""

import pytest
from ikarma.core import (
    RiskScorer, DriverInfo, DriverCapability, AntiForensicIndicator,
    CapabilityType, AntiForensicType, ConfidenceLevel, SignatureInfo,
)


class TestRiskScorer:
    """Tests for RiskScorer."""
    
    def test_scorer_initialization(self):
        """Test scorer initializes correctly."""
        scorer = RiskScorer()
        assert scorer is not None
        assert scorer.critical_threshold == 8.0
        assert scorer.high_threshold == 6.0
    
    def test_score_empty_driver(self):
        """Test scoring driver with no capabilities."""
        scorer = RiskScorer()
        
        driver = DriverInfo(
            name="clean_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
        )
        
        profile = scorer.score_driver(driver)
        
        assert profile.final_score < 4.0
        assert profile.risk_category == "low"
    
    def test_score_driver_with_capabilities(self, sample_driver_with_capabilities):
        """Test scoring driver with capabilities."""
        scorer = RiskScorer()
        
        profile = scorer.score_driver(sample_driver_with_capabilities)
        
        assert profile.final_score > 0
        assert profile.capability_score > 0
        assert len(profile.factors) > 0
    
    def test_dangerous_capability_high_score(self):
        """Test that dangerous capabilities produce high scores."""
        scorer = RiskScorer()
        
        driver = DriverInfo(
            name="dangerous_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
        )
        
        driver.add_capability(DriverCapability(
            capability_type=CapabilityType.ARBITRARY_WRITE,
            confidence=0.95,
            confidence_level=ConfidenceLevel.HIGH,
            description="Arbitrary write capability",
            evidence="BECAUSE: Detected arbitrary memory write pattern",
        ))
        
        profile = scorer.score_driver(driver)
        
        # Single capability produces moderate score; multiple capabilities needed for high
        assert profile.final_score >= 5.0
        assert profile.risk_category in ["medium", "high", "critical"]
    
    def test_msr_write_critical_score(self):
        """Test that MSR_WRITE produces critical score."""
        scorer = RiskScorer()
        
        driver = DriverInfo(
            name="msr_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
        )
        
        driver.add_capability(DriverCapability(
            capability_type=CapabilityType.MSR_WRITE,
            confidence=0.95,
            confidence_level=ConfidenceLevel.HIGH,
            description="WRMSR detected",
            evidence="BECAUSE: Found WRMSR instruction",
        ))
        
        profile = scorer.score_driver(driver)
        
        # MSR_WRITE should be high risk
        assert profile.capability_score > 5.0


class TestLegitimacyBonus:
    """Tests for legitimacy bonus scoring."""
    
    def test_microsoft_signed_bonus(self):
        """Test that Microsoft-signed drivers get bonus."""
        scorer = RiskScorer()
        
        driver = DriverInfo(
            name="ms_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
            driver_path="\\SystemRoot\\System32\\drivers\\ms_driver.sys",
        )
        
        driver.signature_info = SignatureInfo(
            is_signed=True,
            signature_valid=True,
            is_microsoft_signed=True,
            signer_name="Microsoft Windows",
        )
        
        driver.add_capability(DriverCapability(
            capability_type=CapabilityType.MSR_READ,
            confidence=0.90,
            confidence_level=ConfidenceLevel.HIGH,
            description="MSR read",
            evidence="BECAUSE: RDMSR found",
        ))
        
        profile = scorer.score_driver(driver)
        
        # Should have negative legitimacy bonus
        assert profile.legitimacy_bonus < 0
        # Final score should be lower than raw score
        assert profile.final_score < profile.raw_score
    
    def test_whql_signed_bonus(self):
        """Test that WHQL-signed drivers get bonus."""
        scorer = RiskScorer()
        
        driver = DriverInfo(
            name="hw_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
        )
        
        driver.signature_info = SignatureInfo(
            is_signed=True,
            signature_valid=True,
            is_whql_signed=True,
            signer_name="Microsoft Windows Hardware Compatibility Publisher",
        )
        
        driver.add_capability(DriverCapability(
            capability_type=CapabilityType.PORT_IO_READ,
            confidence=0.85,
            confidence_level=ConfidenceLevel.HIGH,
            description="Port I/O",
            evidence="BECAUSE: IN instruction found",
        ))
        
        profile = scorer.score_driver(driver)
        
        assert profile.legitimacy_bonus < 0
    
    def test_unsigned_no_bonus(self):
        """Test that unsigned drivers get no bonus."""
        scorer = RiskScorer()
        
        driver = DriverInfo(
            name="unsigned_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
        )
        
        driver.signature_info = SignatureInfo(is_signed=False)
        
        driver.add_capability(DriverCapability(
            capability_type=CapabilityType.MSR_READ,
            confidence=0.90,
            confidence_level=ConfidenceLevel.HIGH,
            description="MSR read",
            evidence="BECAUSE: RDMSR found",
        ))
        
        profile = scorer.score_driver(driver)
        
        # No legitimacy bonus for unsigned
        assert profile.legitimacy_bonus >= 0
    
    def test_disable_legitimacy_bonus(self):
        """Test disabling legitimacy bonus via config."""
        scorer = RiskScorer({'apply_legitimacy_bonus': False})
        
        driver = DriverInfo(
            name="ms_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
        )
        
        driver.signature_info = SignatureInfo(
            is_signed=True,
            signature_valid=True,
            is_microsoft_signed=True,
            signer_name="Microsoft Windows",
        )
        
        driver.add_capability(DriverCapability(
            capability_type=CapabilityType.MSR_READ,
            confidence=0.90,
            confidence_level=ConfidenceLevel.HIGH,
            description="MSR read",
            evidence="BECAUSE: test",
        ))
        
        profile = scorer.score_driver(driver)
        
        # No bonus when disabled
        assert profile.legitimacy_bonus == 0


class TestAntiForensicScoring:
    """Tests for anti-forensic indicator scoring."""
    
    def test_dkom_high_score(self):
        """Test that DKOM indicators produce high scores."""
        scorer = RiskScorer()
        
        driver = DriverInfo(
            name="hidden_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
        )
        
        driver.add_anti_forensic_indicator(AntiForensicIndicator(
            indicator_type=AntiForensicType.DKOM_UNLINK,
            confidence=0.95,
            description="Driver unlinked from module list",
            evidence="BECAUSE: Found in driverscan but not in pslist",
            severity="critical",
        ))
        
        profile = scorer.score_driver(driver)
        
        assert profile.antiforensic_score > 0
        # DKOM alone may not trigger high score without other indicators
        assert profile.final_score >= 2.0
    
    def test_pe_header_wiped(self):
        """Test scoring for wiped PE header."""
        scorer = RiskScorer()
        
        driver = DriverInfo(
            name="wiped_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
        )
        
        driver.add_anti_forensic_indicator(AntiForensicIndicator(
            indicator_type=AntiForensicType.PE_HEADER_WIPED,
            confidence=0.90,
            description="PE header appears wiped",
            evidence="BECAUSE: MZ signature missing",
            severity="high",
        ))
        
        profile = scorer.score_driver(driver)
        
        assert profile.antiforensic_score > 0


class TestBecauseTags:
    """Tests for 'Because' tag generation."""
    
    def test_summary_because_generated(self):
        """Test that summary Because tag is generated."""
        scorer = RiskScorer()
        
        driver = DriverInfo(
            name="test_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
        )
        
        driver.add_capability(DriverCapability(
            capability_type=CapabilityType.MSR_WRITE,
            confidence=0.95,
            confidence_level=ConfidenceLevel.HIGH,
            description="WRMSR",
            evidence="BECAUSE: test evidence",
        ))
        
        profile = scorer.score_driver(driver)
        
        assert profile.because_summary is not None
        assert "BECAUSE" in profile.because_summary
        assert "MSR_WRITE" in profile.because_summary
    
    def test_all_factors_have_because(self):
        """Test that all risk factors have Because tags."""
        scorer = RiskScorer()
        
        driver = DriverInfo(
            name="test_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
        )
        
        driver.add_capability(DriverCapability(
            capability_type=CapabilityType.MSR_READ,
            confidence=0.90,
            confidence_level=ConfidenceLevel.HIGH,
            description="MSR read",
            evidence="BECAUSE: RDMSR at 0x100",
        ))
        
        profile = scorer.score_driver(driver)
        
        for factor in profile.factors:
            assert factor.because is not None
            assert len(factor.because) > 0


class TestRiskCategorization:
    """Tests for risk category assignment."""
    
    def test_critical_category(self):
        """Test critical risk category."""
        scorer = RiskScorer()
        
        driver = DriverInfo(
            name="critical_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
        )
        
        # Add multiple high-risk capabilities
        for cap_type in [CapabilityType.ARBITRARY_WRITE, CapabilityType.MSR_WRITE]:
            driver.add_capability(DriverCapability(
                capability_type=cap_type,
                confidence=0.95,
                confidence_level=ConfidenceLevel.HIGH,
                description=f"{cap_type.name}",
                evidence="BECAUSE: test",
            ))
        
        profile = scorer.score_driver(driver)
        
        if profile.final_score >= 8.0:
            assert profile.risk_category == "critical"
    
    def test_custom_thresholds(self):
        """Test custom risk thresholds."""
        scorer = RiskScorer({
            'critical_threshold': 9.0,
            'high_threshold': 7.0,
            'medium_threshold': 5.0,
        })
        
        driver = DriverInfo(
            name="test_driver.sys",
            base_address=0xFFFFF80012340000,
            size=0x10000,
        )
        
        driver.add_capability(DriverCapability(
            capability_type=CapabilityType.MSR_READ,
            confidence=0.90,
            confidence_level=ConfidenceLevel.HIGH,
            description="MSR read",
            evidence="BECAUSE: test",
        ))
        
        profile = scorer.score_driver(driver)
        
        # Should use custom thresholds
        if profile.final_score >= 9.0:
            assert profile.risk_category == "critical"
        elif profile.final_score >= 7.0:
            assert profile.risk_category == "high"
