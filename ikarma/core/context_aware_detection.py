"""
iKARMA Context-Aware Detection Module

Provides context-aware filtering for privileged operations to reduce false positives.
Implements whitelists for legitimate uses of MSRs, control registers, and port I/O.
"""

import logging
from typing import Optional, Dict, Tuple, Set
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# MSR WHITELIST - Legitimate Model Specific Register Uses
# =============================================================================

class MSRContext(Enum):
    """Classification of MSR usage context."""
    POWER_MANAGEMENT = "power_management"
    PERFORMANCE_MONITORING = "performance_monitoring"
    THERMAL_MANAGEMENT = "thermal_management"
    CPU_FEATURES = "cpu_features"
    SYSCALL_HOOK = "syscall_hook"  # Suspicious
    UNKNOWN = "unknown"  # Suspicious


# Legitimate MSRs - commonly accessed by OS/driver for non-malicious purposes
LEGITIMATE_MSR_USES = {
    # Power Management MSRs (VERY common in drivers)
    0x199: ("IA32_PERF_CTL", MSRContext.POWER_MANAGEMENT, "P-state control register"),
    0x19A: ("IA32_CLOCK_MODULATION", MSRContext.POWER_MANAGEMENT, "CPU throttling control"),
    0x1A0: ("IA32_MISC_ENABLE", MSRContext.CPU_FEATURES, "CPU feature enable/disable"),
    0x19C: ("IA32_THERM_STATUS", MSRContext.THERMAL_MANAGEMENT, "Thermal sensor status"),
    0x19D: ("IA32_THERM_INTERRUPT", MSRContext.THERMAL_MANAGEMENT, "Thermal interrupt control"),
    0x1A2: ("MSR_TEMPERATURE_TARGET", MSRContext.THERMAL_MANAGEMENT, "Target temperature"),
    0x19B: ("IA32_THERM_DIODE_OFFSET", MSRContext.THERMAL_MANAGEMENT, "Thermal diode offset"),

    # Performance Monitoring MSRs
    0x38D: ("IA32_FIXED_CTR0", MSRContext.PERFORMANCE_MONITORING, "Fixed-function perf counter"),
    0x38E: ("IA32_FIXED_CTR1", MSRContext.PERFORMANCE_MONITORING, "Fixed-function perf counter"),
    0x38F: ("IA32_FIXED_CTR2", MSRContext.PERFORMANCE_MONITORING, "Fixed-function perf counter"),
    0x309: ("IA32_FIXED_CTR_CTRL", MSRContext.PERFORMANCE_MONITORING, "Fixed counter control"),
    0x38F: ("IA32_PERF_GLOBAL_STATUS", MSRContext.PERFORMANCE_MONITORING, "Performance global status"),
    0xC1: ("IA32_PMC0", MSRContext.PERFORMANCE_MONITORING, "Performance counter 0"),
    0xC2: ("IA32_PMC1", MSRContext.PERFORMANCE_MONITORING, "Performance counter 1"),

    # CPU Features/Info MSRs
    0x1B: ("IA32_APIC_BASE", MSRContext.CPU_FEATURES, "APIC base address"),
    0x17: ("IA32_PLATFORM_ID", MSRContext.CPU_FEATURES, "Platform ID"),
    0xCE: ("MSR_PLATFORM_INFO", MSRContext.CPU_FEATURES, "Platform information"),
    0x35: ("MSR_CORE_THREAD_COUNT", MSRContext.CPU_FEATURES, "Core/thread count"),

    # Virtualization MSRs (legitimate for hypervisor drivers)
    0x480: ("IA32_VMX_BASIC", MSRContext.CPU_FEATURES, "VMX capability"),
    0x481: ("IA32_VMX_PINBASED_CTLS", MSRContext.CPU_FEATURES, "VMX pin-based controls"),
    0x482: ("IA32_VMX_PROCBASED_CTLS", MSRContext.CPU_FEATURES, "VMX processor controls"),

    # Memory Type Range Registers (legitimate for drivers)
    0x2FF: ("IA32_MTRR_DEF_TYPE", MSRContext.CPU_FEATURES, "Default memory type"),
    0x200: ("IA32_MTRR_PHYSBASE0", MSRContext.CPU_FEATURES, "MTRR physical base 0"),
}

# SUSPICIOUS MSRs - Should NEVER be accessed by normal drivers
SUSPICIOUS_MSR_USES = {
    # Syscall hooks (CRITICAL - used for kernel malware)
    0xC0000082: ("IA32_LSTAR", MSRContext.SYSCALL_HOOK, "SYSCALL entry point (x64) - HOOK POINT"),
    0xC0000081: ("IA32_STAR", MSRContext.SYSCALL_HOOK, "SYSCALL target address - HOOK POINT"),
    0x176: ("IA32_SYSENTER_EIP", MSRContext.SYSCALL_HOOK, "SYSENTER entry point - HOOK POINT"),

    # Debugging/Trace MSRs (suspicious for normal drivers)
    0x1D9: ("IA32_DEBUGCTL", MSRContext.UNKNOWN, "Debug control register"),
    0x1DB: ("MSR_LASTBRANCH_TOS", MSRContext.UNKNOWN, "Last branch record top-of-stack"),

    # SMM-related (VERY suspicious)
    0x9E: ("IA32_SMM_MONITOR_CTL", MSRContext.UNKNOWN, "SMM monitor control - RARE"),
}


def is_legitimate_msr_access(msr_value: int, is_microsoft_signed: bool, is_whql_signed: bool) -> Tuple[bool, str]:
    """
    Determine if an MSR access is legitimate based on MSR value and driver trust.

    Args:
        msr_value: MSR index being accessed
        is_microsoft_signed: True if driver is Microsoft-signed
        is_whql_signed: True if driver is WHQL-certified

    Returns:
        Tuple of (is_legitimate, reason_string)
    """
    # Check if it's a known suspicious MSR
    if msr_value in SUSPICIOUS_MSR_USES:
        msr_name, context, desc = SUSPICIOUS_MSR_USES[msr_value]
        # Microsoft can access anything (kernel legitimately needs these)
        if is_microsoft_signed:
            return (True, f"Microsoft driver legitimately accessing {msr_name} ({desc})")
        else:
            return (False, f"NON-MICROSOFT driver accessing {msr_name} ({desc}) - SUSPICIOUS")

    # Check if it's a known legitimate MSR
    if msr_value in LEGITIMATE_MSR_USES:
        msr_name, context, desc = LEGITIMATE_MSR_USES[msr_value]

        # Power management MSRs - legitimate for signed drivers
        if context in [MSRContext.POWER_MANAGEMENT, MSRContext.THERMAL_MANAGEMENT]:
            if is_microsoft_signed or is_whql_signed:
                return (True, f"Signed driver accessing {msr_name} for {context.value}")
            else:
                # Unsigned accessing power MSR is somewhat suspicious
                return (False, f"UNSIGNED driver accessing {msr_name} - moderately suspicious")

        # Performance monitoring - generally OK for any signed driver
        if context == MSRContext.PERFORMANCE_MONITORING:
            if is_microsoft_signed or is_whql_signed:
                return (True, f"Signed driver accessing performance MSR {msr_name}")
            else:
                return (False, f"Unsigned driver accessing performance MSR - suspicious")

        # CPU features - should be Microsoft only
        if context == MSRContext.CPU_FEATURES:
            if is_microsoft_signed:
                return (True, f"Microsoft driver accessing CPU feature MSR {msr_name}")
            else:
                return (False, f"Non-Microsoft accessing CPU feature MSR {msr_name} - suspicious")

    # Unknown MSR - suspicious for anyone except Microsoft
    if is_microsoft_signed:
        return (True, f"Microsoft driver accessing unknown MSR 0x{msr_value:X}")
    else:
        return (False, f"Unknown MSR 0x{msr_value:X} - VERY SUSPICIOUS for non-Microsoft driver")


# =============================================================================
# CONTROL REGISTER CONTEXT
# =============================================================================

LEGITIMATE_CR_ACCESS_CONTEXTS = {
    "CR0": ["Microsoft", "WHQL"],  # CPU mode control
    "CR2": ["Microsoft"],  # Page fault address - kernel only
    "CR3": ["Microsoft"],  # Page directory - kernel only (SUSPICIOUS if third-party)
    "CR4": ["Microsoft", "WHQL"],  # Extended CPU features
    "CR8": ["Microsoft"],  # Task priority - kernel only
}


def is_legitimate_cr_access(cr_register: str, is_microsoft_signed: bool, is_whql_signed: bool) -> Tuple[bool, str]:
    """
    Determine if a control register access is legitimate.

    Args:
        cr_register: Register name (e.g., "CR3")
        is_microsoft_signed: True if Microsoft-signed
        is_whql_signed: True if WHQL-signed

    Returns:
        Tuple of (is_legitimate, reason_string)
    """
    if cr_register not in LEGITIMATE_CR_ACCESS_CONTEXTS:
        return (False, f"Access to {cr_register} - unknown control register")

    allowed_signers = LEGITIMATE_CR_ACCESS_CONTEXTS[cr_register]

    if is_microsoft_signed and "Microsoft" in allowed_signers:
        return (True, f"Microsoft driver legitimately accessing {cr_register}")

    if is_whql_signed and "WHQL" in allowed_signers:
        return (True, f"WHQL driver legitimately accessing {cr_register}")

    return (False, f"Unauthorized access to {cr_register} by non-trusted driver - SUSPICIOUS")


# =============================================================================
# PORT I/O CONTEXT
# =============================================================================

# Common legitimate port ranges
LEGITIMATE_PORT_RANGES = {
    # Legacy hardware (less common in modern systems but legitimate)
    (0x0000, 0x00FF): ("Legacy DMA/PIC/PIT", ["Microsoft", "WHQL"]),
    (0x0170, 0x0177): ("Secondary ATA", ["Microsoft", "WHQL"]),
    (0x01F0, 0x01F7): ("Primary ATA", ["Microsoft", "WHQL"]),
    (0x0278, 0x027F): ("Parallel port 2", ["Microsoft", "WHQL"]),
    (0x02F8, 0x02FF): ("Serial port 2", ["Microsoft", "WHQL"]),
    (0x0378, 0x037F): ("Parallel port 1", ["Microsoft", "WHQL"]),
    (0x03F8, 0x03FF): ("Serial port 1", ["Microsoft", "WHQL"]),

    # PCI configuration
    (0x0CF8, 0x0CFF): ("PCI configuration", ["Microsoft", "WHQL"]),

    # ACPI/Power management
    (0x0400, 0x04FF): ("ACPI PM", ["Microsoft", "WHQL"]),
    (0x0500, 0x05FF): ("GPIO/ACPI", ["Microsoft", "WHQL"]),
}


def is_legitimate_port_io(port: int, is_microsoft_signed: bool, is_whql_signed: bool) -> Tuple[bool, str]:
    """
    Determine if port I/O access is legitimate.

    Args:
        port: Port number being accessed
        is_microsoft_signed: True if Microsoft-signed
        is_whql_signed: True if WHQL-signed

    Returns:
        Tuple of (is_legitimate, reason_string)
    """
    for (start, end), (desc, allowed_signers) in LEGITIMATE_PORT_RANGES.items():
        if start <= port <= end:
            if is_microsoft_signed and "Microsoft" in allowed_signers:
                return (True, f"Microsoft driver accessing {desc} port 0x{port:X}")
            if is_whql_signed and "WHQL" in allowed_signers:
                return (True, f"WHQL driver accessing {desc} port 0x{port:X}")
            return (False, f"Untrusted driver accessing {desc} port 0x{port:X} - SUSPICIOUS")

    # Unknown port range
    if is_microsoft_signed:
        return (True, f"Microsoft driver accessing port 0x{port:X}")
    else:
        return (False, f"Untrusted driver accessing unknown port 0x{port:X} - SUSPICIOUS")


# =============================================================================
# CAPABILITY WEIGHT ADJUSTER
# =============================================================================

def get_context_aware_weight(
    base_weight: float,
    capability_type: str,
    is_microsoft_signed: bool,
    is_whql_signed: bool,
    is_signed: bool
) -> Tuple[float, str]:
    """
    Adjust capability weight based on driver legitimacy.

    Args:
        base_weight: Original capability weight
        capability_type: Type of capability (e.g., "MSR_WRITE")
        is_microsoft_signed: Microsoft signature
        is_whql_signed: WHQL certification
        is_signed: Any digital signature

    Returns:
        Tuple of (adjusted_weight, reason_string)
    """
    # Microsoft-signed: MASSIVE reduction for most capabilities
    if is_microsoft_signed:
        if capability_type in ["MSR_READ", "MSR_WRITE"]:
            adjusted = base_weight * 0.05  # 95% reduction
            reason = "Microsoft-signed driver - legitimate MSR access expected"
        elif capability_type in ["CR_ACCESS", "PORT_IO_READ", "PORT_IO_WRITE"]:
            adjusted = base_weight * 0.10  # 90% reduction
            reason = "Microsoft-signed driver - legitimate hardware access expected"
        elif capability_type in ["GDT_MANIPULATION", "IDT_MANIPULATION"]:
            adjusted = base_weight * 0.15  # 85% reduction
            reason = "Microsoft-signed driver - kernel operations expected"
        else:
            adjusted = base_weight * 0.20  # 80% baseline reduction
            reason = "Microsoft-signed driver - trusted signer"
        return (adjusted, reason)

    # WHQL-signed: Moderate reduction
    if is_whql_signed:
        if capability_type in ["MSR_READ", "MSR_WRITE", "CR_ACCESS"]:
            adjusted = base_weight * 0.40  # 60% reduction
            reason = "WHQL-certified driver - hardware driver expected"
        elif capability_type in ["PORT_IO_READ", "PORT_IO_WRITE"]:
            adjusted = base_weight * 0.50  # 50% reduction
            reason = "WHQL-certified driver - port I/O expected for hardware"
        else:
            adjusted = base_weight * 0.60  # 40% baseline reduction
            reason = "WHQL-certified driver - moderately trusted"
        return (adjusted, reason)

    # Generic signed: Slight reduction
    if is_signed:
        adjusted = base_weight * 0.85  # 15% reduction
        reason = "Digitally signed driver - minor trust boost"
        return (adjusted, reason)

    # Unsigned: NO reduction (full weight)
    return (base_weight, "Unsigned driver - full risk weight applied")
