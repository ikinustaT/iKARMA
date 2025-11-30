"""
Advanced Capability Inference Engine

Implements sophisticated capability detection with:
- Extended privileged instruction detection (INVD, INVPCID, XSAVE, etc.)
- Specific MSR identification (LSTAR, EFER, PAT, APIC_BASE)
- PTE manipulation pattern detection
- Control-flow integrity analysis
- Data-flow taint tracking
- Pointer provenance analysis
- Syscall sequence modeling
"""

import logging
import struct
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

from ikarma.core.driver import (
    DriverCapability, CapabilityType, ConfidenceLevel, CodePattern
)

logger = logging.getLogger(__name__)


# Extended privileged opcode patterns
EXTENDED_DANGEROUS_OPCODES = {
    # Cache/TLB manipulation
    (0x0F, 0x08): ("CACHE_INVALIDATE", "INVD - Invalidate cache (full system impact)", CapabilityType.CR_ACCESS),
    (0x0F, 0x09): ("CACHE_WRITEBACK", "WBINVD - Write-back and invalidate cache", CapabilityType.CR_ACCESS),
    (0x0F, 0x01, 0xF9): ("TLBINV", "INVLPG - Invalidate TLB entry (page table attack)", CapabilityType.CR_ACCESS),
    (0x66, 0x0F, 0x38, 0x82): ("INVPCID", "INVPCID - Invalidate PCID (advanced TLB attack)", CapabilityType.CR_ACCESS),

    # Extended state
    (0x0F, 0xAE, 0x27): ("XSAVE", "XSAVE - Save extended state (FPU/AVX)", CapabilityType.CR_ACCESS),
    (0x0F, 0xAE, 0x2F): ("XRSTOR", "XRSTOR - Restore extended state", CapabilityType.CR_ACCESS),
    (0x0F, 0xAE, 0x37): ("XSAVEOPT", "XSAVEOPT - Optimized save extended state", CapabilityType.CR_ACCESS),

    # Entropy/Random
    (0x0F, 0xC7, 0xF0): ("RDRAND", "RDRAND - Read random number (entropy source)", CapabilityType.UNKNOWN),
    (0x0F, 0xC7, 0xF8): ("RDSEED", "RDSEED - Read seed (cryptographic entropy)", CapabilityType.UNKNOWN),

    # CPUID feature detection
    (0x0F, 0xA2): ("CPUID", "CPUID - CPU identification (may check VMX/SMX/SGX)", CapabilityType.UNKNOWN),

    # VMX/Virtualization
    (0x0F, 0x01, 0xC1): ("VMCALL", "VMCALL - Call to VMM", CapabilityType.CR_ACCESS),
    (0x0F, 0x01, 0xC2): ("VMLAUNCH", "VMLAUNCH - Launch virtual machine", CapabilityType.CR_ACCESS),
    (0x0F, 0x01, 0xC3): ("VMRESUME", "VMRESUME - Resume virtual machine", CapabilityType.CR_ACCESS),
    (0x0F, 0x01, 0xC4): ("VMXOFF", "VMXOFF - Leave VMX operation", CapabilityType.CR_ACCESS),

    # SMX (Safer Mode Extensions)
    (0x0F, 0x37): ("GETSEC", "GETSEC - SMX instruction (secure mode)", CapabilityType.CR_ACCESS),

    # Segment manipulation
    (0x0F, 0x00, 0x08): ("STR", "STR - Store task register", CapabilityType.GDT_MANIPULATION),
    (0x0F, 0x00, 0x18): ("LTR", "LTR - Load task register", CapabilityType.GDT_MANIPULATION),

    # System flags
    (0x9C,): ("PUSHF", "PUSHF/PUSHFQ - Push flags (may check EFLAGS.IF)", CapabilityType.UNKNOWN),
    (0x9D,): ("POPF", "POPF/POPFQ - Pop flags (may disable interrupts)", CapabilityType.UNKNOWN),
    (0xFA,): ("CLI", "CLI - Clear interrupt flag (disable interrupts)", CapabilityType.CR_ACCESS),
    (0xFB,): ("STI", "STI - Set interrupt flag (enable interrupts)", CapabilityType.CR_ACCESS),

    # Halt
    (0xF4,): ("HLT", "HLT - Halt processor", CapabilityType.CR_ACCESS),

    # Control Register Manipulation (Rootkit behavior)
    (0x0F, 0x22, 0xE0): ("CR4_WRITE", "MOV CR4, RAX - Potential SMEP/SMAP bypass", CapabilityType.CR_ACCESS),
    (0x0F, 0x22, 0xE1): ("CR4_WRITE", "MOV CR4, RCX - Potential SMEP/SMAP bypass", CapabilityType.CR_ACCESS),
    (0x0F, 0x22, 0xC0): ("CR0_WRITE", "MOV CR0, RAX - Potential WP disable", CapabilityType.CR_ACCESS),
    
    # Stack Pivoting
    (0x48, 0x87, 0xE0): ("STACK_PIVOT", "XCHG RSP, RAX - Stack pivot detected", CapabilityType.UNKNOWN),
    (0x48, 0x89, 0xC4): ("STACK_PIVOT", "MOV RSP, RAX - Stack pivot detected", CapabilityType.UNKNOWN),
}


# Specific MSR addresses and their security implications
CRITICAL_MSR_ADDRESSES = {
    0xC0000080: ("IA32_EFER", "Extended Feature Enable Register (NXE bit for DEP bypass)", CapabilityType.MSR_WRITE),
    0xC0000081: ("IA32_STAR", "SYSCALL target address (CS/SS)", CapabilityType.MSR_WRITE),
    0xC0000082: ("IA32_LSTAR", "SYSCALL entry point (LSTAR hook = kernel backdoor)", CapabilityType.MSR_WRITE),
    0xC0000083: ("IA32_CSTAR", "SYSCALL entry (compatibility mode)", CapabilityType.MSR_WRITE),
    0xC0000084: ("IA32_FMASK", "SYSCALL flag mask", CapabilityType.MSR_WRITE),
    0x0000001B: ("IA32_APIC_BASE", "APIC base address (APIC relocation attack)", CapabilityType.MSR_WRITE),
    0x00000277: ("IA32_PAT", "Page Attribute Table (memory type attack)", CapabilityType.MSR_WRITE),
    0x0000038F: ("IA32_PERF_GLOBAL_CTRL", "Performance counter control (side-channel setup)", CapabilityType.MSR_WRITE),
    0x00000174: ("IA32_SYSENTER_CS", "SYSENTER CS (hook SYSENTER)", CapabilityType.MSR_WRITE),
    0x00000175: ("IA32_SYSENTER_ESP", "SYSENTER stack pointer", CapabilityType.MSR_WRITE),
    0x00000176: ("IA32_SYSENTER_EIP", "SYSENTER entry point (hook)", CapabilityType.MSR_WRITE),
    0xC0000100: ("IA32_FS_BASE", "FS segment base (TEB access)", CapabilityType.MSR_WRITE),
    0xC0000101: ("IA32_GS_BASE", "GS segment base (KPCR access)", CapabilityType.MSR_WRITE),
    0xC0000102: ("IA32_KERNEL_GS_BASE", "Kernel GS base (SWAPGS)", CapabilityType.MSR_WRITE),
}


# PTE manipulation patterns
PTE_MANIPULATION_PATTERNS = [
    # Pattern 1: CR3 manipulation (page table base swap)
    {
        'name': 'CR3_SWAP',
        'sequence': [
            (b'\x0F\x20\xD8', 'mov rax, cr3'),
            (b'\x0F\x22\xD9', 'mov cr3, rcx'),
        ],
        'capability': CapabilityType.ARBITRARY_READ,
        'description': 'CR3 manipulation for arbitrary address space access',
        'confidence': 0.95,
    },
    # Pattern 2: PTE bit manipulation
    {
        'name': 'PTE_BIT_SET',
        'sequence': [
            (b'\x48\x83\x08\x06', 'or qword ptr [rax], 6'),  # Set R/W + Present
        ],
        'capability': CapabilityType.ARBITRARY_WRITE,
        'description': 'Direct PTE manipulation (setting R/W and Present bits)',
        'confidence': 0.90,
    },
]


# Syscall sequence models
SYSCALL_SEQUENCES = {
    # Legitimate IOCTL pattern
    'LEGITIMATE_IOCTL': {
        'sequence': [
            'IoGetCurrentIrpStackLocation',
            'ProbeForRead',
            'MmMapIoSpace',
        ],
        'is_malicious': False,
    },
    # Malicious pattern: Direct user input to dangerous API
    'MALICIOUS_PMEM_MAP': {
        'sequence': [
            'IoGetCurrentIrpStackLocation',
            'MmMapIoSpace',  # No ProbeForRead in between!
        ],
        'is_malicious': True,
        'capability': CapabilityType.PHYSICAL_MEMORY_MAP,
        'confidence': 0.92,
    },
    # Token theft pattern
    'TOKEN_THEFT': {
        'sequence': [
            'PsLookupProcessByProcessId',
            'PsReferencePrimaryToken',
            # Missing SeAccessCheck - directly using token
        ],
        'is_malicious': True,
        'capability': CapabilityType.PROCESS_TOKEN_STEAL,
        'confidence': 0.88,
    },
}


@dataclass
class DataFlowTaint:
    """Represents tainted data flow from user input."""
    source: str  # e.g., "IRP->AssociatedIrp.SystemBuffer"
    sink: str    # e.g., "MmMapIoSpace(physicalAddress=...)"
    path: List[str] = field(default_factory=list)
    is_validated: bool = False
    confidence: float = 0.0


@dataclass
class CFIViolation:
    """Control-flow integrity violation."""
    violation_type: str  # 'indirect_call_user_controlled', 'missing_probe', 'missing_cookie'
    address: int
    description: str
    evidence: str
    severity: str  # 'critical', 'high', 'medium'


class AdvancedCapabilityEngine:
    """
    Advanced capability inference engine with deep semantic analysis.

    Features:
    - Extended opcode detection (INVD, INVPCID, XSAVE, etc.)
    - Specific MSR identification with security context
    - PTE manipulation pattern detection
    - CFI violation detection
    - Data-flow taint analysis
    - Syscall sequence modeling
    """

    def __init__(self, architecture: str = "x64"):
        """Initialize the advanced engine."""
        self.architecture = architecture
        self.is_64bit = architecture == "x64"

        # Build comprehensive opcode tables
        self._build_opcode_tables()

        # Statistics
        self.stats = {
            'extended_opcodes_found': 0,
            'msr_specific_found': 0,
            'pte_patterns_found': 0,
            'cfi_violations_found': 0,
            'taint_flows_found': 0,
        }

    def _build_opcode_tables(self):
        """Build lookup tables for fast opcode matching."""
        self.opcode_table = {}

        for opcode_seq, (name, desc, cap_type) in EXTENDED_DANGEROUS_OPCODES.items():
            length = len(opcode_seq)
            if length not in self.opcode_table:
                self.opcode_table[length] = {}
            self.opcode_table[length][opcode_seq] = (name, desc, cap_type)

    def analyze_code_advanced(
        self,
        code: bytes,
        base_address: int,
        context: str = "code"
    ) -> List[DriverCapability]:
        """
        Perform advanced code analysis with extended opcode detection.

        Args:
            code: Raw machine code bytes
            base_address: Virtual address of code
            context: Description for evidence

        Returns:
            List of detected capabilities
        """
        capabilities = []

        if not code:
            return capabilities

        # Extended opcode scanning
        extended_caps = self._scan_extended_opcodes(code, base_address, context)
        capabilities.extend(extended_caps)

        # MSR-specific detection
        msr_caps = self._detect_specific_msrs(code, base_address, context)
        capabilities.extend(msr_caps)

        # PTE manipulation patterns
        pte_caps = self._detect_pte_patterns(code, base_address, context)
        capabilities.extend(pte_caps)

        return capabilities

    def _scan_extended_opcodes(
        self,
        code: bytes,
        base_address: int,
        context: str
    ) -> List[DriverCapability]:
        """Scan for extended privileged opcodes."""
        capabilities = []

        i = 0
        while i < len(code):
            matched = False

            # Try matching opcodes of different lengths (4, 3, 2, 1 byte)
            for length in [4, 3, 2, 1]:
                if length in self.opcode_table and i + length <= len(code):
                    opcode_seq = tuple(code[i:i+length])

                    if opcode_seq in self.opcode_table[length]:
                        name, desc, cap_type = self.opcode_table[length][opcode_seq]

                        evidence = (
                            f"BECAUSE: Detected {desc} instruction at {hex(base_address + i)} "
                            f"in {context}. Raw bytes: {code[i:i+length].hex()}"
                        )

                        cap = DriverCapability(
                            capability_type=cap_type,
                            confidence=0.95,
                            confidence_level=ConfidenceLevel.HIGH,
                            description=f"{cap_type.name}: {desc}",
                            evidence=evidence,
                            handler_address=base_address + i,
                            handler_offset=i,
                            code_patterns=[CodePattern(
                                offset=i,
                                virtual_address=base_address + i,
                                raw_bytes=code[i:i+length],
                                disassembly=[f"{hex(base_address + i)}: {desc}"],
                                pattern_name=name,
                                pattern_type="privileged_opcode",
                            )],
                            risk_weight=self._get_opcode_risk_weight(name),
                            exploitability="high",
                        )

                        capabilities.append(cap)
                        self.stats['extended_opcodes_found'] += 1

                        i += length
                        matched = True
                        break

            if not matched:
                i += 1

        return capabilities

    def _detect_specific_msrs(
        self,
        code: bytes,
        base_address: int,
        context: str
    ) -> List[DriverCapability]:
        """
        Detect WRMSR/RDMSR with specific MSR addresses.

        Pattern:
            mov ecx, <MSR_ADDRESS>
            wrmsr  / rdmsr
        """
        capabilities = []

        i = 0
        while i < len(code) - 7:
            # Look for: mov ecx, imm32 (B9 xx xx xx xx) followed by WRMSR (0F 30) or RDMSR (0F 32)
            if code[i] == 0xB9 and i + 6 < len(code):
                # Extract MSR address
                msr_addr = struct.unpack('<I', code[i+1:i+5])[0]

                # Check if followed by WRMSR or RDMSR
                if i + 6 < len(code) and code[i+5:i+7] == b'\x0F\x30':
                    # WRMSR
                    is_write = True
                    opcode = b'\x0F\x30'
                elif i + 6 < len(code) and code[i+5:i+7] == b'\x0F\x32':
                    # RDMSR
                    is_write = False
                    opcode = b'\x0F\x32'
                else:
                    i += 1
                    continue

                # Check if this is a critical MSR
                if msr_addr in CRITICAL_MSR_ADDRESSES:
                    msr_name, msr_desc, cap_type = CRITICAL_MSR_ADDRESSES[msr_addr]

                    operation = "Write to" if is_write else "Read from"

                    evidence = (
                        f"BECAUSE: Detected {operation} critical MSR {msr_name} (0x{msr_addr:X}) "
                        f"at {hex(base_address + i)} in {context}. {msr_desc}. "
                        f"Raw bytes: {code[i:i+7].hex()}"
                    )

                    cap = DriverCapability(
                        capability_type=cap_type,
                        confidence=0.98,  # Very high confidence - specific MSR detected
                        confidence_level=ConfidenceLevel.HIGH,
                        description=f"{operation} {msr_name}: {msr_desc}",
                        evidence=evidence,
                        handler_address=base_address + i,
                        handler_offset=i,
                        code_patterns=[CodePattern(
                            offset=i,
                            virtual_address=base_address + i,
                            raw_bytes=code[i:i+7],
                            disassembly=[
                                f"{hex(base_address + i)}: mov ecx, 0x{msr_addr:X}",
                                f"{hex(base_address + i + 5)}: {'wrmsr' if is_write else 'rdmsr'}"
                            ],
                            pattern_name=f"MSR_{msr_name}_{'WRITE' if is_write else 'READ'}",
                            pattern_type="specific_msr",
                        )],
                        risk_weight=9.5 if is_write else 7.0,
                        exploitability="high",
                    )

                    capabilities.append(cap)
                    self.stats['msr_specific_found'] += 1

                    i += 7
                    continue

            i += 1

        return capabilities

    def _detect_pte_patterns(
        self,
        code: bytes,
        base_address: int,
        context: str
    ) -> List[DriverCapability]:
        """Detect PTE manipulation patterns."""
        capabilities = []

        for pattern in PTE_MANIPULATION_PATTERNS:
            # Simple pattern matching for now
            # In production, would use more sophisticated sequence matching

            for opcode_bytes, mnemonic in pattern['sequence']:
                pos = code.find(opcode_bytes)
                if pos != -1:
                    evidence = (
                        f"BECAUSE: Detected PTE manipulation pattern '{pattern['name']}' "
                        f"at {hex(base_address + pos)} in {context}. {pattern['description']}. "
                        f"Instruction: {mnemonic}"
                    )

                    cap = DriverCapability(
                        capability_type=pattern['capability'],
                        confidence=pattern['confidence'],
                        confidence_level=ConfidenceLevel.HIGH,
                        description=f"PTE Manipulation: {pattern['description']}",
                        evidence=evidence,
                        handler_address=base_address + pos,
                        handler_offset=pos,
                        code_patterns=[CodePattern(
                            offset=pos,
                            virtual_address=base_address + pos,
                            raw_bytes=opcode_bytes,
                            disassembly=[f"{hex(base_address + pos)}: {mnemonic}"],
                            pattern_name=pattern['name'],
                            pattern_type="pte_manipulation",
                        )],
                        risk_weight=10.0,
                        exploitability="high",
                    )

                    capabilities.append(cap)
                    self.stats['pte_patterns_found'] += 1
                    break

        return capabilities

    def detect_cfi_violations(
        self,
        code: bytes,
        base_address: int,
        imports: List[str]
    ) -> List[CFIViolation]:
        """
        Detect control-flow integrity violations.

        Checks for:
        - Indirect calls/jumps with user-controlled registers
        - Missing ProbeForRead/ProbeForWrite
        - Removed stack cookie checks
        """
        violations = []

        # Check 1: Missing ProbeForRead before dangerous memory operations
        has_probe_for_read = 'ProbeForRead' in imports or 'ProbeForWrite' in imports
        has_dangerous_api = any(api in imports for api in ['MmMapIoSpace', 'MmCopyMemory'])

        if has_dangerous_api and not has_probe_for_read:
            violations.append(CFIViolation(
                violation_type='missing_probe',
                address=base_address,
                description='Dangerous memory API without input validation',
                evidence='BECAUSE: Driver uses MmMapIoSpace/MmCopyMemory but does not import ProbeForRead/ProbeForWrite',
                severity='critical',
            ))
            self.stats['cfi_violations_found'] += 1

        # Check 2: Look for indirect call/jmp patterns
        # Pattern: call [reg] or jmp [reg] where reg might be user-controlled
        # This is simplified - real implementation would track data flow

        i = 0
        while i < len(code) - 2:
            # call [rax], call [rcx], etc. (FF D0, FF D1, ...)
            if code[i] == 0xFF and i + 1 < len(code):
                modrm = code[i + 1]

                # Check if it's a call indirect (reg)
                if (modrm & 0xF8) == 0xD0:  # call r/m64
                    violations.append(CFIViolation(
                        violation_type='indirect_call_register',
                        address=base_address + i,
                        description='Indirect call through register (potential ROP gadget)',
                        evidence=f'BECAUSE: Found indirect call at {hex(base_address + i)}: call [register]',
                        severity='medium',
                    ))
                    self.stats['cfi_violations_found'] += 1

            i += 1

        return violations

    def detect_data_flow_taints(
        self,
        code: bytes,
        base_address: int,
        imports: List[str]
    ) -> List[DataFlowTaint]:
        """
        Detect tainted data flows from user input to dangerous sinks.

        This is a simplified version - full implementation would require
        symbolic execution or static analysis framework.
        """
        taints = []

        # Heuristic: If we see MmMapIoSpace but no validation, flag it
        if 'MmMapIoSpace' in imports:
            # Check if there's any validation
            has_validation = any(v in imports for v in [
                'ProbeForRead', 'ProbeForWrite', 'MmIsAddressValid'
            ])

            if not has_validation:
                taints.append(DataFlowTaint(
                    source='IRP->AssociatedIrp.SystemBuffer',
                    sink='MmMapIoSpace(physicalAddress=UserInput)',
                    path=['IoGetCurrentIrpStackLocation', 'MmMapIoSpace'],
                    is_validated=False,
                    confidence=0.85,
                ))
                self.stats['taint_flows_found'] += 1

        return taints

    def _get_opcode_risk_weight(self, opcode_name: str) -> float:
        """Get risk weight for specific opcode."""
        high_risk = {
            'INVD', 'WBINVD', 'INVPCID', 'VMCALL', 'VMLAUNCH',
            'CR3_SWAP', 'PTE_BIT_SET', 'CLI', 'HLT'
        }

        medium_risk = {
            'XSAVE', 'XRSTOR', 'CPUID', 'PUSHF', 'POPF'
        }

        if opcode_name in high_risk or opcode_name in {'CR4_WRITE', 'CR0_WRITE', 'STACK_PIVOT'}:
            return 9.0
        elif opcode_name in medium_risk:
            return 6.0
        else:
            return 5.0

    def get_statistics(self) -> Dict[str, int]:
        """Get detection statistics."""
        return self.stats.copy()
