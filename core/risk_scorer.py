"""
Risk Scoring Module for iKARMA BYOVD Detection

This module implements the risk scoring algorithm that assigns explainable
risk scores (0-100) to kernel drivers based on multiple indicators:

1. IOCTL surface (Custom vs Generic handlers)
2. Module size (complexity proxy)
3. System driver heuristics (whitelist)
4. Anti-rename detection (DKOM indicator)
5. Size anomalies
6. Handler address validation
7. Dangerous API detections (Person 2's work)
8. Disassembly pattern analysis (optional)

Author: Person 3 (Risk Analyst) with Person 1 integration
Last Updated: 2025-11-19
"""

from typing import List, Dict, Tuple, Optional


# ============================================================================
# SYSTEM DRIVER WHITELIST
# ============================================================================

SYSTEM_DRIVER_WHITELIST = {
    # Common Microsoft / known system drivers (normalized names, without .sys)
    "msrpc", "ksecdd", "werkernel", "clfs", "tm", "fltmgr", "clipsp",
    "cmimcext", "ntosext", "cng", "wdfldr", "acpiex", "mssecflt",
    "acpi", "wmilib", "intelpep", "pcw", "msisadrv", "pci", "vdrvroot",
    "pdc", "partmgr", "intelide", "pciidex", "volmgr", "volmgrx",
    "mountmgr", "atapi", "ataport", "ehstorclass", "fileinfo", "wof",
    "ntfs", "vboxguest", "ndis", "netio", "tcpip", "fvevol", "volume",
    "volsnap", "rdyboost", "mup", "disk", "win32k", "win32kfull",
    "win32kbase", "usb", "dxgkrnl", "kbdclass", "mouclass", "usbxhci",
    "http", "afd", "ndiswan", "storqosflt", "mrxsmb", "srvnet",
    "msfs", "npfs", "fastfat", "exfat", "refs", "cdfs", "udfs",
    "volmgr", "crashdmp", "dump", "dumpata", "dumpfve", "processr",
}


# ============================================================================
# EXPECTED DRIVER SIZES (for anomaly detection)
# ============================================================================

EXPECTED_DRIVER_SIZES = {
    # name: expected_size (bytes) -- approximate reference values
    "tcpip": 0x2db000,
    "ntfs": 0x28d000,
    "ntoskrnl": 0x400000,
    "wdfldr": 0xd1000,
    "vboxguest": 0x5f000,
    "ndis": 0x200000,
    "win32kfull": 0x800000,
    "win32kbase": 0x200000,
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def is_system_driver(normalized_name: str) -> bool:
    """
    Return True if driver is a common system driver (heuristic).
    
    Args:
        normalized_name: driver name already lower-cased and without ".sys"
        
    Returns:
        True if likely a system driver, False otherwise
    """
    if not normalized_name:
        return False

    # Exact match
    if normalized_name in SYSTEM_DRIVER_WHITELIST:
        return True

    # Prefix matches for very common prefixes
    prefixes = ("microsoft", "win", "nt", "ms", "pci", "vbox", "vmware", "qemu")
    for p in prefixes:
        if normalized_name.startswith(p):
            return True

    return False


def detect_size_anomaly(normalized_name: str, size: int) -> Tuple[bool, int]:
    """
    Detect if driver size differs significantly from expected values.
    
    Args:
        normalized_name: driver name (normalized)
        size: actual driver size in bytes
        
    Returns:
        Tuple of (is_anomalous, deviation_percentage)
    """
    if normalized_name not in EXPECTED_DRIVER_SIZES:
        return False, 0
        
    expected = EXPECTED_DRIVER_SIZES[normalized_name]
    if size and expected:
        deviation = abs(size - expected)
        deviation_pct = int((deviation / expected) * 100)
        
        # Flag if differs by >30%
        if deviation > (expected * 0.30):
            return True, deviation_pct
            
    return False, 0


def detect_handler_anomaly(handler_addr: int, 
                          module_ranges: List[Tuple[int, int, str]]) -> Tuple[bool, str]:
    """
    Detect if IOCTL handler points to unexpected memory location.
    
    Args:
        handler_addr: Address of IOCTL handler
        module_ranges: List of (start, end, name) tuples for all loaded modules
        
    Returns:
        Tuple of (is_anomalous, location_description)
    """
    if not handler_addr or not module_ranges:
        return False, ""
        
    for (mstart, mend, mname) in module_ranges:
        if mstart <= handler_addr < mend:
            # Handler is in a known module
            return False, mname
            
    # Handler points to unmapped or injected memory
    return True, "unmapped/injected"


def detect_name_mismatch(driver_obj_name: Optional[str], 
                        module_name: Optional[str]) -> bool:
    """
    Detect potential driver rename/spoofing (DKOM indicator).
    
    Args:
        driver_obj_name: Name from DRIVER_OBJECT.DriverName
        module_name: Name from MODULE entry (BaseDllName)
        
    Returns:
        True if names don't match (potential rename), False otherwise
    """
    if not driver_obj_name or not module_name:
        return False
        
    # Normalize both names
    obj_short = driver_obj_name.lower().split('\\')[-1].replace('.sys', '')
    mod_short = module_name.lower().replace('.sys', '').split('\\')[-1]
    
    return obj_short != mod_short


# ============================================================================
# MAIN RISK SCORING FUNCTION
# ============================================================================

def calculate_driver_risk(
    normalized_name: str,
    analysis_result: str,
    ioctl_handler_display: str,
    size: int,
    handler_addr: Optional[int] = None,
    module_name: Optional[str] = None,
    driver_obj_name: Optional[str] = None,
    module_ranges: Optional[List[Tuple[int, int, str]]] = None,
    found_apis: Optional[List[Dict]] = None
) -> Dict[str, any]:
    """
    Compute explainable risk score for a kernel driver.
    
    Args:
        normalized_name: Driver name (lowercase, no .sys)
        analysis_result: "Custom IOCTL", "Generic IOCTL", or "Enumerated"
        ioctl_handler_display: Handler address string or status
        size: Driver module size in bytes
        handler_addr: Numeric handler address (optional)
        module_name: Module name from MODULE list (optional)
        driver_obj_name: Name from DRIVER_OBJECT (optional)
        module_ranges: List of (start, end, name) for all modules (optional)
        found_apis: List of dangerous APIs detected by Person 2's scanner (optional)
        
    Returns:
        Dict with keys:
            - 'score': int (0-100)
            - 'level': str ("Low", "Medium", "High", "Critical")
            - 'reasons': str (semicolon-separated explanation)
            - 'confidence': float (0.0-1.0, not yet implemented)
    """
    score = 0
    reasons = []
    
    # ========================================================================
    # FACTOR 1: IOCTL Surface (+40 Custom, +10 Generic)
    # ========================================================================
    if analysis_result == "Custom IOCTL":
        score += 40
        reasons.append("Custom IOCTL +40")
    elif analysis_result == "Generic IOCTL":
        score += 10
        reasons.append("Generic IOCTL +10")
    else:
        reasons.append("No handler +0")
    
    # ========================================================================
    # FACTOR 2: Module Size (complexity proxy, +5 to +10)
    # ========================================================================
    try:
        if size and size > 0x40000:  # >256KB
            score += 10
            reasons.append("Large module +10")
        elif size and size > 0x20000:  # >128KB
            score += 5
            reasons.append("Medium module +5")
    except Exception:
        pass
    
    # ========================================================================
    # FACTOR 3: Dangerous API Detections (Person 2's work, +5 per API up to +30)
    # ========================================================================
    if found_apis and len(found_apis) > 0:
        api_score = min(len(found_apis) * 5, 30)  # Cap at +30
        score += api_score
        api_names = [api['name'] for api in found_apis[:5]]
        reasons.append(f"Dangerous APIs +{api_score} ({', '.join(api_names)}{'...' if len(found_apis) > 5 else ''})")
    
    # ========================================================================
    # FACTOR 4: System Driver Reduction (known safe drivers, -15)
    # ========================================================================
    is_sys_driver = False
    try:
        if is_system_driver(normalized_name):
            is_sys_driver = True
            score -= 15
            reasons.append("Known system driver -15")
    except Exception:
        pass
    
    # ========================================================================
    # FACTOR 5: Anti-Rename Detection (DKOM indicator, +25)
    # ========================================================================
    try:
        if detect_name_mismatch(driver_obj_name, module_name):
            score += 25
            reasons.append("Name mismatch (renamed?) +25")
            
            # If driver was whitelisted but names don't match, override whitelist
            if is_sys_driver:
                score += 15  # Restore the -15 reduction
                reasons.append("Whitelist override due to mismatch +15")
    except Exception:
        pass
    
    # ========================================================================
    # FACTOR 6: Size Anomaly Detection (+15)
    # ========================================================================
    try:
        is_anomalous, deviation = detect_size_anomaly(normalized_name, size)
        if is_anomalous:
            score += 15
            reasons.append(f"Size anomaly +15 ({deviation}% deviation)")
    except Exception:
        pass
    
    # ========================================================================
    # FACTOR 7: Handler Address Anomaly (+15)
    # ========================================================================
    try:
        if handler_addr and module_ranges:
            is_anomalous, location = detect_handler_anomaly(handler_addr, module_ranges)
            if is_anomalous:
                score += 15
                reasons.append(f"Handler in unexpected memory +15 ({location})")
    except Exception:
        pass
    
    # ========================================================================
    # FACTOR 8: Generic Handler Outside Module (slight reduction, -3)
    # ========================================================================
    if isinstance(ioctl_handler_display, str) and ioctl_handler_display.startswith("Generic"):
        score -= 3
        reasons.append("Generic handler (lower risk) -3")
    
    # ========================================================================
    # Normalize and Clamp Score
    # ========================================================================
    score = max(0, min(100, int(score)))
    
    # ========================================================================
    # Risk Level Mapping
    # ========================================================================
    if score >= 90:
        level = "Critical"
    elif score >= 70:
        level = "High"
    elif score >= 40:
        level = "Medium"
    else:
        level = "Low"
    
    # ========================================================================
    # Build Explanation String
    # ========================================================================
    reasons_str = "; ".join(reasons) if reasons else "No indicators"
    
    # Trim very long explanations for display purposes
    MAX_REASON_LEN = 200
    if len(reasons_str) > MAX_REASON_LEN:
        reasons_str = reasons_str[:MAX_REASON_LEN].rstrip() + "..."
    
    return {
        'score': score,
        'level': level,
        'reasons': reasons_str,
        'confidence': 0.0  # Placeholder for Person 3's confidence framework
    }


# ============================================================================
# CONFIDENCE FRAMEWORK (Future: Person 3's advanced work)
# ============================================================================

def calculate_confidence(detection_methods: List[str], context: Dict) -> float:
    """
    Calculate confidence level for risk assessment.
    
    Detection method hierarchy (from Person 3's plan):
    - Direct call detection: 0.95 confidence
    - Import table match: 0.90 confidence
    - String reference: 0.75 confidence
    - Opcode pattern: 0.70 confidence
    
    Args:
        detection_methods: List of methods used (e.g., ['direct_call', 'import'])
        context: Additional context (handler location, string proximity, etc.)
        
    Returns:
        Overall confidence score (0.0 - 1.0)
    """
    # TODO: Implement by Person 3 during Week 1 Day 3-4
    return 0.0
