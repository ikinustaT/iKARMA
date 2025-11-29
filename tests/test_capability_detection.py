"""
iKARMA Test Suite - Capability Detection Tests

Tests for the CapabilityEngine component.
"""

import pytest
from ikarma.core import CapabilityEngine, CapabilityType


class TestCapabilityEngine:
    """Tests for CapabilityEngine."""
    
    def test_engine_initialization(self):
        """Test engine initializes correctly."""
        engine = CapabilityEngine()
        assert engine is not None
        assert engine.architecture == "x64"
    
    def test_detect_port_io_read(self):
        """Test detection of IN instruction."""
        engine = CapabilityEngine()
        
        # IN AL, DX (0xEC)
        code = bytes([0xEC, 0x90, 0x90])  # IN followed by NOPs
        caps = engine.analyze_code(code, 0x1000, "test")
        
        assert len(caps) >= 1
        port_io_caps = [c for c in caps if c.capability_type == CapabilityType.PORT_IO_READ]
        assert len(port_io_caps) >= 1
        assert "BECAUSE" in port_io_caps[0].evidence
    
    def test_detect_port_io_write(self):
        """Test detection of OUT instruction."""
        engine = CapabilityEngine()
        
        # OUT DX, AL (0xEE)
        code = bytes([0xEE, 0x90])
        caps = engine.analyze_code(code, 0x1000, "test")
        
        port_io_caps = [c for c in caps if c.capability_type == CapabilityType.PORT_IO_WRITE]
        assert len(port_io_caps) >= 1
    
    def test_detect_msr_read(self):
        """Test detection of RDMSR instruction."""
        engine = CapabilityEngine()
        
        # RDMSR (0x0F 0x32)
        code = bytes([0x0F, 0x32, 0x90])
        caps = engine.analyze_code(code, 0x1000, "test")
        
        msr_caps = [c for c in caps if c.capability_type == CapabilityType.MSR_READ]
        assert len(msr_caps) >= 1
        assert msr_caps[0].confidence >= 0.9
    
    def test_detect_msr_write(self):
        """Test detection of WRMSR instruction."""
        engine = CapabilityEngine()
        
        # WRMSR (0x0F 0x30)
        code = bytes([0x0F, 0x30, 0x90])
        caps = engine.analyze_code(code, 0x1000, "test")
        
        msr_caps = [c for c in caps if c.capability_type == CapabilityType.MSR_WRITE]
        assert len(msr_caps) >= 1
    
    def test_detect_cr_access(self):
        """Test detection of control register access."""
        engine = CapabilityEngine()
        
        # MOV RAX, CR0 (0x0F 0x20)
        code = bytes([0x0F, 0x20, 0xC0, 0x90])
        caps = engine.analyze_code(code, 0x1000, "test")
        
        cr_caps = [c for c in caps if c.capability_type == CapabilityType.CR_ACCESS]
        assert len(cr_caps) >= 1
    
    def test_detect_idt_manipulation(self):
        """Test detection of IDT access."""
        engine = CapabilityEngine()
        
        # SIDT (0x0F 0x01 0x08 variant)
        code = bytes([0x0F, 0x01, 0x08, 0x90])
        caps = engine.analyze_code(code, 0x1000, "test")
        
        idt_caps = [c for c in caps if c.capability_type == CapabilityType.IDT_MANIPULATION]
        assert len(idt_caps) >= 1
    
    def test_detect_multiple_capabilities(self):
        """Test detection of multiple capabilities in one code block."""
        engine = CapabilityEngine()
        
        # Multiple dangerous instructions
        code = bytes([
            0xEC,        # IN AL, DX
            0xEE,        # OUT DX, AL
            0x0F, 0x32,  # RDMSR
            0x0F, 0x30,  # WRMSR
            0xC3,        # RET
        ])
        
        caps = engine.analyze_code(code, 0x1000, "test")
        
        # Should detect at least 4 capabilities
        cap_types = {c.capability_type for c in caps}
        assert CapabilityType.PORT_IO_READ in cap_types
        assert CapabilityType.PORT_IO_WRITE in cap_types
        assert CapabilityType.MSR_READ in cap_types
        assert CapabilityType.MSR_WRITE in cap_types
    
    def test_no_false_positives_on_clean_code(self):
        """Test that clean code doesn't trigger false positives."""
        engine = CapabilityEngine()
        
        # Simple function with no dangerous instructions
        code = bytes([
            0x48, 0x89, 0xE5,  # MOV RBP, RSP
            0x48, 0x83, 0xEC, 0x20,  # SUB RSP, 0x20
            0x31, 0xC0,  # XOR EAX, EAX
            0xC3,  # RET
        ])
        
        caps = engine.analyze_code(code, 0x1000, "test")
        
        # Should not detect dangerous capabilities
        dangerous = [c for c in caps if c.capability_type in {
            CapabilityType.MSR_WRITE,
            CapabilityType.ARBITRARY_WRITE,
            CapabilityType.DSE_BYPASS,
        }]
        assert len(dangerous) == 0
    
    def test_empty_code_handling(self):
        """Test handling of empty code."""
        engine = CapabilityEngine()
        
        caps = engine.analyze_code(b'', 0x1000, "test")
        assert caps == []
    
    def test_capability_has_because_tag(self):
        """Test that all capabilities have 'Because' tags."""
        engine = CapabilityEngine()
        
        code = bytes([0xEC, 0x0F, 0x32])
        caps = engine.analyze_code(code, 0x1000, "test")
        
        for cap in caps:
            assert cap.evidence is not None
            assert "BECAUSE" in cap.evidence
    
    def test_analyze_image(self, driver_with_dangerous_opcodes):
        """Test full image analysis."""
        engine = CapabilityEngine()
        
        caps = engine.analyze_image(driver_with_dangerous_opcodes, 0x1000)
        
        # Should detect capabilities from the dangerous opcodes
        cap_types = {c.capability_type for c in caps}
        assert len(cap_types) > 0


class TestCapabilityDeduplication:
    """Tests for capability deduplication."""
    
    def test_deduplication_same_offset(self):
        """Test that duplicate capabilities at same offset are deduplicated."""
        engine = CapabilityEngine()
        
        # Same instruction twice shouldn't create duplicates
        code = bytes([0xEC])  # Single IN instruction
        
        # Analyze twice
        caps1 = engine.analyze_code(code, 0x1000, "test")
        caps2 = engine.analyze_code(code, 0x1000, "test")
        
        # Each analysis should only return 1 capability
        assert len(caps1) == 1
        assert len(caps2) == 1


class TestCapabilityConfidence:
    """Tests for capability confidence levels."""
    
    def test_opcode_detection_high_confidence(self):
        """Test that opcode detection has high confidence."""
        engine = CapabilityEngine()
        
        code = bytes([0x0F, 0x32])  # RDMSR
        caps = engine.analyze_code(code, 0x1000, "test")
        
        assert len(caps) >= 1
        assert caps[0].confidence >= 0.9
    
    def test_confidence_level_mapping(self):
        """Test confidence level string mapping."""
        from ikarma.core import ConfidenceLevel
        
        engine = CapabilityEngine()
        
        code = bytes([0x0F, 0x32])
        caps = engine.analyze_code(code, 0x1000, "test")
        
        assert caps[0].confidence_level == ConfidenceLevel.HIGH
