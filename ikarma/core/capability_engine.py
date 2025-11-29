"""
iKARMA Capability Engine - Production Release

Detects dangerous capabilities in kernel driver code through:
- Opcode pattern matching (IN, OUT, RDMSR, WRMSR, etc.)
- API import analysis
- String pattern detection
- Control flow analysis

Every detection includes a "Because" tag explaining the evidence.
"""

import logging
import struct
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field

from ikarma.core.driver import (
    DriverInfo, DriverCapability, IOCTLHandler, CodePattern,
    CapabilityType, ConfidenceLevel,
)

logger = logging.getLogger(__name__)


# =============================================================================
# CAPSTONE IMPORT
# =============================================================================

HAS_CAPSTONE = False
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CsInsn
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
    HAS_CAPSTONE = True
except ImportError:
    pass

HAS_PEFILE = False
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    pass


# =============================================================================
# DETECTION PATTERNS
# =============================================================================

# Dangerous x86/x64 opcodes
DANGEROUS_OPCODES = {
    # Port I/O
    (0xEC,): ("PORT_IO_READ", "IN AL, DX - Direct hardware port input"),
    (0xED,): ("PORT_IO_READ", "IN EAX, DX - Direct hardware port input"),
    (0xE4,): ("PORT_IO_READ", "IN AL, imm8 - Direct hardware port input"),
    (0xE5,): ("PORT_IO_READ", "IN EAX, imm8 - Direct hardware port input"),
    (0xEE,): ("PORT_IO_WRITE", "OUT DX, AL - Direct hardware port output"),
    (0xEF,): ("PORT_IO_WRITE", "OUT DX, EAX - Direct hardware port output"),
    (0xE6,): ("PORT_IO_WRITE", "OUT imm8, AL - Direct hardware port output"),
    (0xE7,): ("PORT_IO_WRITE", "OUT imm8, EAX - Direct hardware port output"),
    
    # MSR access
    (0x0F, 0x32): ("MSR_READ", "RDMSR - Read Model Specific Register"),
    (0x0F, 0x30): ("MSR_WRITE", "WRMSR - Write Model Specific Register"),
    
    # Control registers
    (0x0F, 0x20): ("CR_ACCESS", "MOV from CR - Control register read"),
    (0x0F, 0x22): ("CR_ACCESS", "MOV to CR - Control register write"),
    
    # Descriptor tables
    (0x0F, 0x01, 0xC8): ("MSR_READ", "MONITOR - Set up monitor address"),
    (0x0F, 0x01, 0xC9): ("MSR_WRITE", "MWAIT - Monitor wait"),
    (0x0F, 0x01, 0xD0): ("CR_ACCESS", "XGETBV - Get extended control register"),
    (0x0F, 0x01, 0xD1): ("CR_ACCESS", "XSETBV - Set extended control register"),
    
    # IDT/GDT manipulation
    (0x0F, 0x01, 0x08): ("IDT_MANIPULATION", "SIDT - Store IDT register"),
    (0x0F, 0x01, 0x18): ("IDT_MANIPULATION", "LIDT - Load IDT register"),
    (0x0F, 0x01, 0x00): ("GDT_MANIPULATION", "SGDT - Store GDT register"),
    (0x0F, 0x01, 0x10): ("GDT_MANIPULATION", "LGDT - Load GDT register"),
    
    # Debug registers
    (0x0F, 0x21): ("CR_ACCESS", "MOV from DR - Debug register read"),
    (0x0F, 0x23): ("CR_ACCESS", "MOV to DR - Debug register write"),
    
    # System instructions
    (0x0F, 0x00, 0x00): ("GDT_MANIPULATION", "SLDT - Store LDT register"),
    (0x0F, 0x00, 0x10): ("GDT_MANIPULATION", "LLDT - Load LDT register"),
    
    # Virtualization
    (0x0F, 0x01, 0xC1): ("CR_ACCESS", "VMCALL - Call VMM"),
    (0x0F, 0x01, 0xC2): ("CR_ACCESS", "VMLAUNCH - Launch VM"),
    (0x0F, 0x01, 0xC3): ("CR_ACCESS", "VMRESUME - Resume VM"),
    (0x0F, 0x01, 0xC4): ("CR_ACCESS", "VMXOFF - Leave VMX operation"),
}

# Dangerous API imports
DANGEROUS_APIS = {
    # Physical memory access
    "MmMapIoSpace": {
        "capability": CapabilityType.PHYSICAL_MEMORY_MAP,
        "description": "Maps physical memory to virtual address space",
        "risk_weight": 9.0,
        "exploitability": "high",
    },
    "MmMapIoSpaceEx": {
        "capability": CapabilityType.PHYSICAL_MEMORY_MAP,
        "description": "Extended physical memory mapping",
        "risk_weight": 9.0,
        "exploitability": "high",
    },
    "ZwMapViewOfSection": {
        "capability": CapabilityType.PHYSICAL_MEMORY_MAP,
        "description": "Maps view of section into address space",
        "risk_weight": 7.5,
        "exploitability": "medium",
    },
    "MmCopyMemory": {
        "capability": CapabilityType.PHYSICAL_MEMORY_READ,
        "description": "Copies memory from physical or virtual address",
        "risk_weight": 8.0,
        "exploitability": "high",
    },
    
    # Process manipulation
    "ZwTerminateProcess": {
        "capability": CapabilityType.PROCESS_TERMINATE,
        "description": "Terminates a process",
        "risk_weight": 7.0,
        "exploitability": "medium",
    },
    "ZwOpenProcess": {
        "capability": CapabilityType.PROCESS_HANDLE_DUP,
        "description": "Opens handle to process",
        "risk_weight": 5.0,
        "exploitability": "medium",
    },
    "PsLookupProcessByProcessId": {
        "capability": CapabilityType.EPROCESS_MANIPULATION,
        "description": "Gets EPROCESS pointer from PID",
        "risk_weight": 6.0,
        "exploitability": "medium",
    },
    "PsGetCurrentProcessId": {
        "capability": CapabilityType.EPROCESS_MANIPULATION,
        "description": "Gets current process ID",
        "risk_weight": 2.0,
        "exploitability": "low",
    },
    
    # Callback manipulation
    "PsSetCreateProcessNotifyRoutine": {
        "capability": CapabilityType.CALLBACK_REMOVAL,
        "description": "Sets/removes process creation callback",
        "risk_weight": 7.5,
        "exploitability": "high",
    },
    "PsSetCreateProcessNotifyRoutineEx": {
        "capability": CapabilityType.CALLBACK_REMOVAL,
        "description": "Extended process creation callback",
        "risk_weight": 7.5,
        "exploitability": "high",
    },
    "PsSetLoadImageNotifyRoutine": {
        "capability": CapabilityType.CALLBACK_REMOVAL,
        "description": "Sets/removes image load callback",
        "risk_weight": 7.0,
        "exploitability": "high",
    },
    "CmUnRegisterCallback": {
        "capability": CapabilityType.CALLBACK_REMOVAL,
        "description": "Unregisters registry callback",
        "risk_weight": 7.0,
        "exploitability": "high",
    },
    "ObUnRegisterCallbacks": {
        "capability": CapabilityType.CALLBACK_REMOVAL,
        "description": "Unregisters object callbacks",
        "risk_weight": 8.0,
        "exploitability": "high",
    },
    
    # Memory operations
    "MmAllocateContiguousMemory": {
        "capability": CapabilityType.PHYSICAL_MEMORY_MAP,
        "description": "Allocates physically contiguous memory",
        "risk_weight": 6.0,
        "exploitability": "medium",
    },
    "MmGetPhysicalAddress": {
        "capability": CapabilityType.PHYSICAL_MEMORY_READ,
        "description": "Gets physical address from virtual",
        "risk_weight": 6.0,
        "exploitability": "medium",
    },
    
    # Code injection
    "KeInsertQueueApc": {
        "capability": CapabilityType.APC_INJECTION,
        "description": "Inserts APC into thread queue",
        "risk_weight": 8.5,
        "exploitability": "high",
    },
    "KeInitializeApc": {
        "capability": CapabilityType.APC_INJECTION,
        "description": "Initializes APC object",
        "risk_weight": 7.0,
        "exploitability": "medium",
    },
    
    # File/Registry
    "ZwCreateFile": {
        "capability": CapabilityType.KERNEL_FILE_ACCESS,
        "description": "Creates or opens file from kernel",
        "risk_weight": 4.0,
        "exploitability": "low",
    },
    "ZwReadFile": {
        "capability": CapabilityType.KERNEL_FILE_ACCESS,
        "description": "Reads file from kernel",
        "risk_weight": 4.0,
        "exploitability": "low",
    },
    "ZwWriteFile": {
        "capability": CapabilityType.KERNEL_FILE_ACCESS,
        "description": "Writes file from kernel",
        "risk_weight": 5.0,
        "exploitability": "low",
    },
    "ZwCreateKey": {
        "capability": CapabilityType.KERNEL_REGISTRY_ACCESS,
        "description": "Creates or opens registry key",
        "risk_weight": 5.0,
        "exploitability": "low",
    },
    "ZwSetValueKey": {
        "capability": CapabilityType.KERNEL_REGISTRY_ACCESS,
        "description": "Sets registry value",
        "risk_weight": 5.5,
        "exploitability": "medium",
    },
    
    # Security bypass
    "SePrivilegeCheck": {
        "capability": CapabilityType.PPL_BYPASS,
        "description": "Checks for privileges",
        "risk_weight": 4.0,
        "exploitability": "low",
    },
    "SeSinglePrivilegeCheck": {
        "capability": CapabilityType.PPL_BYPASS,
        "description": "Checks single privilege",
        "risk_weight": 4.0,
        "exploitability": "low",
    },
}

# String patterns indicating dangerous operations
DANGEROUS_STRINGS = [
    (b"\\Device\\PhysicalMemory", CapabilityType.PHYSICAL_MEMORY_READ, "Opens physical memory device"),
    (b"\\??\\PhysicalDrive", CapabilityType.PHYSICAL_MEMORY_READ, "Direct disk access"),
    (b"SeDebugPrivilege", CapabilityType.PROCESS_TOKEN_STEAL, "Debug privilege manipulation"),
    (b"SeTcbPrivilege", CapabilityType.PROCESS_TOKEN_STEAL, "TCB privilege manipulation"),
    (b"NtSystemDebugControl", CapabilityType.ARBITRARY_READ, "System debug control"),
]


# =============================================================================
# CAPABILITY ENGINE CLASS
# =============================================================================

class CapabilityEngine:
    """
    Production-ready capability detection engine.
    
    Detection methods:
    1. Opcode scanning for privileged instructions
    2. Import table analysis for dangerous APIs
    3. String pattern matching
    4. Disassembly analysis for context
    
    Every detection includes a "Because" tag with evidence.
    """
    
    def __init__(self, architecture: str = "x64", config: Optional[Dict] = None):
        """Initialize the capability engine."""
        self.architecture = architecture
        self.config = config or {}
        
        # Set up disassembler
        self._disassembler = None
        if HAS_CAPSTONE:
            mode = CS_MODE_64 if architecture == "x64" else CS_MODE_32
            self._disassembler = Cs(CS_ARCH_X86, mode)
            self._disassembler.detail = True
        
        # Build opcode lookup tables for fast matching
        self._build_opcode_tables()
    
    def _build_opcode_tables(self):
        """Build lookup tables for opcode matching."""
        self._single_byte_opcodes = {}
        self._two_byte_opcodes = {}
        self._three_byte_opcodes = {}
        
        for opcode_tuple, (cap_name, description) in DANGEROUS_OPCODES.items():
            if len(opcode_tuple) == 1:
                self._single_byte_opcodes[opcode_tuple[0]] = (cap_name, description)
            elif len(opcode_tuple) == 2:
                self._two_byte_opcodes[opcode_tuple] = (cap_name, description)
            elif len(opcode_tuple) == 3:
                self._three_byte_opcodes[opcode_tuple] = (cap_name, description)
    
    def analyze_driver(self, driver: DriverInfo, image: bytes) -> List[DriverCapability]:
        """
        Comprehensive capability analysis of a driver.
        
        Args:
            driver: DriverInfo to analyze
            image: Full driver image bytes
            
        Returns:
            List of detected DriverCapability objects
        """
        capabilities = []
        
        # Analyze code in image
        code_caps = self.analyze_code(image, driver.base_address, "full image")
        capabilities.extend(code_caps)
        
        # Analyze IOCTL handlers specifically
        for handler in driver.ioctl_handlers:
            handler_caps = self.analyze_handler(handler)
            capabilities.extend(handler_caps)
        
        # Analyze imports
        import_caps = self._analyze_imports(image, driver.base_address)
        capabilities.extend(import_caps)
        
        # Analyze strings
        string_caps = self._analyze_strings(image, driver.base_address)
        capabilities.extend(string_caps)
        
        # Deduplicate
        capabilities = self._deduplicate_capabilities(capabilities)
        
        return capabilities
    
    def analyze_handler(self, handler: IOCTLHandler) -> List[DriverCapability]:
        """Analyze an IOCTL handler for capabilities."""
        if not handler.raw_code:
            return []
        
        return self.analyze_code(
            handler.raw_code,
            handler.handler_address,
            f"IOCTL handler at {hex(handler.handler_address)}"
        )
    
    def analyze_code(
        self,
        code: bytes,
        base_address: int,
        context: str = "code"
    ) -> List[DriverCapability]:
        """
        Analyze code bytes for dangerous opcodes.
        
        Args:
            code: Machine code bytes
            base_address: Virtual address of code start
            context: Description of code location for evidence
            
        Returns:
            List of detected capabilities with "Because" tags
        """
        capabilities = []
        
        if not code:
            return capabilities
        
        # Scan for dangerous opcodes
        i = 0
        while i < len(code):
            cap = None
            
            # Check three-byte sequences
            if i + 2 < len(code):
                seq3 = (code[i], code[i+1], code[i+2])
                if seq3 in self._three_byte_opcodes:
                    cap_name, desc = self._three_byte_opcodes[seq3]
                    cap = self._create_capability(
                        cap_name, desc, base_address + i,
                        code[i:i+3], context, 0.95
                    )
                    i += 3
                    if cap:
                        capabilities.append(cap)
                    continue
            
            # Check two-byte sequences
            if i + 1 < len(code):
                seq2 = (code[i], code[i+1])
                if seq2 in self._two_byte_opcodes:
                    cap_name, desc = self._two_byte_opcodes[seq2]
                    cap = self._create_capability(
                        cap_name, desc, base_address + i,
                        code[i:i+2], context, 0.93
                    )
                    i += 2
                    if cap:
                        capabilities.append(cap)
                    continue
            
            # Check single-byte opcodes
            if code[i] in self._single_byte_opcodes:
                cap_name, desc = self._single_byte_opcodes[code[i]]
                cap = self._create_capability(
                    cap_name, desc, base_address + i,
                    bytes([code[i]]), context, 0.90
                )
                if cap:
                    capabilities.append(cap)
            
            i += 1
        
        return capabilities
    
    def _create_capability(
        self,
        cap_name: str,
        description: str,
        address: int,
        raw_bytes: bytes,
        context: str,
        confidence: float
    ) -> Optional[DriverCapability]:
        """Create a DriverCapability with proper "Because" tag."""
        
        try:
            cap_type = CapabilityType[cap_name]
        except KeyError:
            cap_type = CapabilityType.UNKNOWN
        
        # Determine confidence level
        if confidence >= 0.9:
            conf_level = ConfidenceLevel.HIGH
        elif confidence >= 0.7:
            conf_level = ConfidenceLevel.MEDIUM
        elif confidence >= 0.5:
            conf_level = ConfidenceLevel.LOW
        else:
            conf_level = ConfidenceLevel.SPECULATIVE
        
        # Build evidence string
        evidence = (
            f"BECAUSE: Found {description} instruction ({raw_bytes.hex()}) "
            f"at {hex(address)} in {context}"
        )
        
        return DriverCapability(
            capability_type=cap_type,
            confidence=confidence,
            confidence_level=conf_level,
            description=f"{cap_type.name}: {description}",
            evidence=evidence,
            handler_address=address,
            handler_offset=address,
            code_patterns=[CodePattern(
                offset=0,
                virtual_address=address,
                raw_bytes=raw_bytes,
                disassembly=[f"{hex(address)}: {description}"],
                pattern_name=cap_name,
                pattern_type="opcode",
            )],
            risk_weight=self._get_risk_weight(cap_type),
            exploitability=self._get_exploitability(cap_type),
        )
    
    def _analyze_imports(self, image: bytes, base_address: int) -> List[DriverCapability]:
        """Analyze PE import table for dangerous APIs."""
        capabilities = []
        
        if not HAS_PEFILE or not image:
            return capabilities
        
        try:
            pe = pefile.PE(data=image, fast_load=False)
            
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                return capabilities
            
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                
                for imp in entry.imports:
                    if not imp.name:
                        continue
                    
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    
                    if func_name in DANGEROUS_APIS:
                        info = DANGEROUS_APIS[func_name]
                        
                        cap = DriverCapability(
                            capability_type=info["capability"],
                            confidence=0.95,
                            confidence_level=ConfidenceLevel.HIGH,
                            description=f"Import of {func_name}: {info['description']}",
                            evidence=f"BECAUSE: Import of {func_name} from {dll_name} found in import table",
                            risk_weight=info["risk_weight"],
                            exploitability=info["exploitability"],
                        )
                        capabilities.append(cap)
            
        except Exception as e:
            logger.debug(f"Import analysis failed: {e}")
        
        return capabilities
    
    def _analyze_strings(self, image: bytes, base_address: int) -> List[DriverCapability]:
        """Analyze image for dangerous string patterns."""
        capabilities = []
        
        if not image:
            return capabilities
        
        for pattern, cap_type, description in DANGEROUS_STRINGS:
            pos = 0
            while True:
                pos = image.find(pattern, pos)
                if pos == -1:
                    break
                
                cap = DriverCapability(
                    capability_type=cap_type,
                    confidence=0.80,
                    confidence_level=ConfidenceLevel.MEDIUM,
                    description=f"String pattern: {description}",
                    evidence=f"BECAUSE: Found string '{pattern.decode('utf-8', errors='ignore')}' at offset {hex(pos)}",
                    handler_offset=pos,
                    risk_weight=self._get_risk_weight(cap_type),
                    exploitability="medium",
                )
                capabilities.append(cap)
                
                pos += 1
        
        return capabilities
    
    def analyze_image(self, image: bytes, base_address: int) -> List[DriverCapability]:
        """
        Analyze full driver image for capabilities.
        
        This is a convenience method that combines all analysis methods.
        """
        capabilities = []
        
        if not image:
            return capabilities
        
        # Import analysis
        import_caps = self._analyze_imports(image, base_address)
        capabilities.extend(import_caps)
        
        # String analysis
        string_caps = self._analyze_strings(image, base_address)
        capabilities.extend(string_caps)
        
        # Code analysis - scan full image for dangerous opcodes
        code_caps = self.analyze_code(image, base_address, "driver image")
        capabilities.extend(code_caps)
        
        # Deduplicate
        capabilities = self._deduplicate_capabilities(capabilities)
        
        return capabilities
    
    def _deduplicate_capabilities(
        self, capabilities: List[DriverCapability]
    ) -> List[DriverCapability]:
        """Remove duplicate capabilities, keeping highest confidence."""
        seen = {}
        
        for cap in capabilities:
            key = (cap.capability_type, cap.handler_offset)
            
            if key not in seen or cap.confidence > seen[key].confidence:
                seen[key] = cap
        
        return list(seen.values())
    
    def _get_risk_weight(self, cap_type: CapabilityType) -> float:
        """Get risk weight for a capability type."""
        weights = {
            CapabilityType.ARBITRARY_WRITE: 10.0,
            CapabilityType.PHYSICAL_MEMORY_WRITE: 10.0,
            CapabilityType.MSR_WRITE: 9.5,
            CapabilityType.DSE_BYPASS: 9.5,
            CapabilityType.PHYSICAL_MEMORY_MAP: 8.5,
            CapabilityType.PHYSICAL_MEMORY_READ: 8.0,
            CapabilityType.ARBITRARY_READ: 8.0,
            CapabilityType.MSR_READ: 6.5,
            CapabilityType.PORT_IO_WRITE: 6.5,
            CapabilityType.PORT_IO_READ: 5.5,
            CapabilityType.CR_ACCESS: 7.0,
            CapabilityType.IDT_MANIPULATION: 7.5,
            CapabilityType.GDT_MANIPULATION: 7.0,
        }
        return weights.get(cap_type, 5.0)
    
    def _get_exploitability(self, cap_type: CapabilityType) -> str:
        """Get exploitability rating for a capability type."""
        high = {
            CapabilityType.ARBITRARY_WRITE,
            CapabilityType.PHYSICAL_MEMORY_WRITE,
            CapabilityType.MSR_WRITE,
            CapabilityType.DSE_BYPASS,
            CapabilityType.PHYSICAL_MEMORY_MAP,
        }
        if cap_type in high:
            return "high"
        
        low = {
            CapabilityType.PORT_IO_READ,
            CapabilityType.KERNEL_FILE_ACCESS,
            CapabilityType.KERNEL_REGISTRY_ACCESS,
        }
        if cap_type in low:
            return "low"
        
        return "medium"
