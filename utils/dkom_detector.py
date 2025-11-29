"""
DKOM (Direct Kernel Object Manipulation) Detector for iKARMA BYOVD Detection

This module implements cross-view validation between:
1. PsLoadedModuleList (what the OS thinks is loaded)
2. Memory scanning for PE headers (what's actually in memory)

Discrepancies indicate potential DKOM manipulation:
- HIDDEN_DRIVER: PE in memory but not in PsLoadedModuleList
- UNLINKED_OR_PAGED: In list but PE not found in memory

Author: iKARMA Team (Anti-Forensic Detection)
Version: 1.0
Last Updated: 2025-11-26
"""

import struct
from typing import List, Dict, Tuple, Optional, Set


# ============================================================================
# DKOM ANOMALY CLASSIFICATIONS
# ============================================================================

DKOM_ANOMALY_TYPES = {
    'HIDDEN_DRIVER': {
        'description': 'PE header found in memory but driver not in PsLoadedModuleList',
        'why_dangerous': 'Driver may be hidden via DKOM (Direct Kernel Object Manipulation)',
        'risk_weight': 60,
        'confidence': 0.9,
    },
    'UNLINKED_OR_PAGED': {
        'description': 'Driver in PsLoadedModuleList but PE header not found at base address',
        'why_dangerous': 'Driver may be unlinked from memory or header is paged out',
        'risk_weight': 10,  # Lower - could just be paged out
        'confidence': 0.5,
    },
    'BASE_ADDRESS_MISMATCH': {
        'description': 'PE header found at different address than listed in PsLoadedModuleList',
        'why_dangerous': 'Driver base address may have been manipulated',
        'risk_weight': 40,
        'confidence': 0.7,
    },
    'SIZE_MISMATCH': {
        'description': 'PE size does not match the size listed in PsLoadedModuleList',
        'why_dangerous': 'Driver size may have been manipulated to hide code regions',
        'risk_weight': 30,
        'confidence': 0.7,
    },
    'ORPHANED_PE': {
        'description': 'Valid PE header in kernel space not associated with any known driver',
        'why_dangerous': 'Could be injected code, unpacked payload, or manually mapped driver',
        'risk_weight': 50,
        'confidence': 0.8,
    },
}


# ============================================================================
# PE HEADER VALIDATION
# ============================================================================

def validate_pe_header(data: bytes, offset: int = 0) -> Tuple[bool, Dict]:
    """
    Validate a PE header structure.
    
    Args:
        data: Raw bytes potentially containing a PE header
        offset: Offset within data to check
    
    Returns:
        Tuple of (is_valid, pe_info_dict)
    """
    pe_info = {
        'valid': False,
        'reason': 'Unknown',
        'machine': None,
        'size_of_image': None,
        'entry_point': None,
        'timestamp': None,
        'is_driver': False,
    }
    
    try:
        if len(data) < offset + 0x40:
            pe_info['reason'] = 'Data too short for DOS header'
            return False, pe_info
        
        # Check MZ signature
        if data[offset:offset+2] != b'MZ':
            pe_info['reason'] = 'No MZ signature'
            return False, pe_info
        
        # Get e_lfanew (PE header offset)
        e_lfanew = struct.unpack('<I', data[offset + 0x3c:offset + 0x40])[0]
        
        # Sanity check e_lfanew
        if e_lfanew > 0x1000 or e_lfanew < 0x40:
            pe_info['reason'] = f'Invalid e_lfanew: {hex(e_lfanew)}'
            return False, pe_info
        
        pe_offset = offset + e_lfanew
        
        if len(data) < pe_offset + 0x18:
            pe_info['reason'] = 'Data too short for PE header'
            return False, pe_info
        
        # Check PE signature
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            pe_info['reason'] = 'No PE signature'
            return False, pe_info
        
        # Parse COFF header
        machine = struct.unpack('<H', data[pe_offset + 4:pe_offset + 6])[0]
        num_sections = struct.unpack('<H', data[pe_offset + 6:pe_offset + 8])[0]
        timestamp = struct.unpack('<I', data[pe_offset + 8:pe_offset + 12])[0]
        characteristics = struct.unpack('<H', data[pe_offset + 22:pe_offset + 24])[0]
        
        # Validate machine type
        valid_machines = {0x14c, 0x8664, 0xaa64}  # i386, AMD64, ARM64
        if machine not in valid_machines:
            pe_info['reason'] = f'Invalid machine type: {hex(machine)}'
            return False, pe_info
        
        # Validate section count
        if num_sections == 0 or num_sections > 96:
            pe_info['reason'] = f'Invalid section count: {num_sections}'
            return False, pe_info
        
        # Check if it's a driver (IMAGE_FILE_SYSTEM flag or common characteristics)
        # IMAGE_FILE_SYSTEM = 0x1000
        is_system = (characteristics & 0x1000) != 0
        # IMAGE_FILE_DLL = 0x2000
        is_dll = (characteristics & 0x2000) != 0
        
        # Parse optional header for SizeOfImage
        opt_header_offset = pe_offset + 24
        
        if len(data) < opt_header_offset + 60:
            pe_info['reason'] = 'Data too short for optional header'
            pe_info['valid'] = True  # PE header is valid, just truncated
            pe_info['machine'] = machine
            pe_info['timestamp'] = timestamp
            pe_info['is_driver'] = is_system
            return True, pe_info
        
        # Read optional header magic to determine 32/64-bit
        opt_magic = struct.unpack('<H', data[opt_header_offset:opt_header_offset + 2])[0]
        
        if opt_magic == 0x10b:  # PE32
            size_of_image = struct.unpack('<I', data[opt_header_offset + 56:opt_header_offset + 60])[0]
            entry_point = struct.unpack('<I', data[opt_header_offset + 16:opt_header_offset + 20])[0]
        elif opt_magic == 0x20b:  # PE32+
            size_of_image = struct.unpack('<I', data[opt_header_offset + 56:opt_header_offset + 60])[0]
            entry_point = struct.unpack('<I', data[opt_header_offset + 16:opt_header_offset + 20])[0]
        else:
            pe_info['reason'] = f'Invalid optional header magic: {hex(opt_magic)}'
            return False, pe_info
        
        pe_info.update({
            'valid': True,
            'reason': 'Valid PE header',
            'machine': machine,
            'size_of_image': size_of_image,
            'entry_point': entry_point,
            'timestamp': timestamp,
            'is_driver': is_system,
            'is_dll': is_dll,
            'num_sections': num_sections,
            'characteristics': characteristics,
        })
        
        return True, pe_info
        
    except Exception as e:
        pe_info['reason'] = f'Exception: {str(e)}'
        return False, pe_info


# ============================================================================
# MEMORY SCANNING FOR PE HEADERS
# ============================================================================

def scan_for_pe_headers(
    layer,
    start_addr: int,
    end_addr: int,
    page_size: int = 0x1000,
    known_bases: Set[int] = None
) -> List[Dict]:
    """
    Scan memory for PE headers (MZ + PE signature).
    
    This implements memory carving to find driver PE headers that may not be
    in the official driver list (hidden via DKOM).
    
    Args:
        layer: Volatility memory layer
        start_addr: Start address for scanning (typically kernel base)
        end_addr: End address for scanning
        page_size: Page size for alignment (default 4KB)
        known_bases: Set of known driver base addresses to skip
    
    Returns:
        List of dicts with PE header information:
        {
            'base_address': int,
            'size_of_image': int,
            'timestamp': int,
            'is_known': bool,
            'pe_info': dict
        }
    """
    found_pe_headers = []
    
    if known_bases is None:
        known_bases = set()
    
    # Scan memory in page-aligned increments
    # In kernel mode, drivers are typically page-aligned
    current_addr = start_addr & ~(page_size - 1)  # Align to page boundary
    
    scan_count = 0
    max_scans = (end_addr - current_addr) // page_size
    
    # Limit scanning to avoid excessive time
    max_pages_to_scan = min(max_scans, 100000)  # Cap at 100K pages (400MB)
    
    while current_addr < end_addr and scan_count < max_pages_to_scan:
        try:
            # Read first two bytes to check for MZ
            mz_check = layer.read(current_addr, 2, pad=True)
            
            if mz_check == b'MZ':
                # Potential PE header - read more to validate
                header_data = layer.read(current_addr, 0x400, pad=True)  # Read 1KB for header
                
                is_valid, pe_info = validate_pe_header(header_data)
                
                if is_valid:
                    is_known = current_addr in known_bases
                    
                    found_pe_headers.append({
                        'base_address': current_addr,
                        'size_of_image': pe_info.get('size_of_image', 0),
                        'timestamp': pe_info.get('timestamp', 0),
                        'is_known': is_known,
                        'is_driver': pe_info.get('is_driver', False),
                        'pe_info': pe_info,
                    })
        
        except Exception:
            # Memory not readable at this address - continue
            pass
        
        current_addr += page_size
        scan_count += 1
    
    return found_pe_headers


def scan_kernel_space_for_pe(
    layer,
    kernel_base: int,
    kernel_size: int = 0x10000000  # Default 256MB scan range
) -> List[Dict]:
    """
    Scan kernel space for PE headers.
    
    This is a convenience wrapper for scan_for_pe_headers that targets
    typical kernel address ranges.
    
    Args:
        layer: Volatility memory layer
        kernel_base: Base address of the kernel
        kernel_size: Size of kernel space to scan
    
    Returns:
        List of found PE headers
    """
    end_addr = kernel_base + kernel_size
    return scan_for_pe_headers(layer, kernel_base, end_addr)


# ============================================================================
# CROSS-VIEW VALIDATION
# ============================================================================

def detect_dkom_anomalies(
    enumerated_drivers: List[Dict],
    carved_pe_bases: List[Dict],
    layer = None
) -> List[Dict]:
    """
    Compare enumerated drivers vs carved PE headers to detect DKOM.
    
    Cross-view validation strategy:
    1. For each enumerated driver, verify PE header exists at base address
    2. For each carved PE, check if it's in the enumerated list
    3. Flag discrepancies as potential DKOM
    
    Args:
        enumerated_drivers: List of drivers from PsLoadedModuleList
            Each dict must have: 'base_address', 'size', 'name'
        carved_pe_bases: List of PE headers found via memory carving
            Each dict must have: 'base_address', 'size_of_image', 'is_known'
        layer: Optional Volatility memory layer for additional validation
    
    Returns:
        List of DKOM anomaly findings:
        {
            'anomaly_type': str,
            'description': str,
            'base_address': int,
            'driver_name': str or None,
            'confidence': float,
            'risk_weight': int,
            'because': str,
            'details': dict
        }
    """
    findings = []
    
    # Build set of enumerated base addresses for quick lookup
    enumerated_bases = {d['base_address']: d for d in enumerated_drivers}
    
    # Build set of carved base addresses
    carved_bases = {pe['base_address']: pe for pe in carved_pe_bases}
    
    # CHECK 1: Find HIDDEN_DRIVER anomalies
    # PE headers in memory that are NOT in the enumerated list
    for base_addr, pe_info in carved_bases.items():
        if base_addr not in enumerated_bases:
            # Found a PE header not in the driver list!
            anomaly = DKOM_ANOMALY_TYPES['HIDDEN_DRIVER']
            
            # Higher confidence if it looks like a driver (system file)
            confidence = anomaly['confidence']
            if pe_info.get('is_driver', False):
                confidence = min(1.0, confidence + 0.1)
            
            findings.append({
                'anomaly_type': 'HIDDEN_DRIVER',
                'description': anomaly['description'],
                'base_address': base_addr,
                'driver_name': None,  # Unknown - not in list
                'confidence': confidence,
                'risk_weight': anomaly['risk_weight'],
                'because': f'PE header at {hex(base_addr)} not found in PsLoadedModuleList - driver may be hidden via DKOM',
                'details': {
                    'size_of_image': pe_info.get('size_of_image', 0),
                    'timestamp': pe_info.get('timestamp', 0),
                    'is_system_file': pe_info.get('is_driver', False),
                }
            })
    
    # CHECK 2: Find UNLINKED_OR_PAGED anomalies
    # Drivers in the list but PE header not found in memory
    for base_addr, driver_info in enumerated_bases.items():
        if base_addr not in carved_bases:
            # Driver in list but PE not found at base address
            # This could be:
            # - Legitimate paging (header paged out)
            # - DKOM unlinking from memory
            
            anomaly = DKOM_ANOMALY_TYPES['UNLINKED_OR_PAGED']
            
            # Try to read the base address to determine if paged
            is_readable = False
            if layer:
                try:
                    test_read = layer.read(base_addr, 2, pad=False)
                    is_readable = len(test_read) == 2
                except:
                    pass
            
            # Lower confidence if memory is just not readable (likely paging)
            confidence = anomaly['confidence']
            if not is_readable:
                confidence = 0.3  # Likely just paged out
            
            findings.append({
                'anomaly_type': 'UNLINKED_OR_PAGED',
                'description': anomaly['description'],
                'base_address': base_addr,
                'driver_name': driver_info.get('name', 'Unknown'),
                'confidence': confidence,
                'risk_weight': anomaly['risk_weight'] if is_readable else 5,
                'because': f'Driver {driver_info.get("name", "Unknown")} listed at {hex(base_addr)} but PE header not found - {"memory readable but no MZ" if is_readable else "memory not readable (likely paged)"}',
                'details': {
                    'listed_size': driver_info.get('size', 0),
                    'memory_readable': is_readable,
                }
            })
    
    # CHECK 3: Size mismatches
    for base_addr, driver_info in enumerated_bases.items():
        if base_addr in carved_bases:
            pe_info = carved_bases[base_addr]
            listed_size = driver_info.get('size', 0)
            carved_size = pe_info.get('size_of_image', 0)
            
            if listed_size > 0 and carved_size > 0:
                # Check for significant size mismatch (>10%)
                if abs(listed_size - carved_size) > max(listed_size, carved_size) * 0.1:
                    anomaly = DKOM_ANOMALY_TYPES['SIZE_MISMATCH']
                    
                    findings.append({
                        'anomaly_type': 'SIZE_MISMATCH',
                        'description': anomaly['description'],
                        'base_address': base_addr,
                        'driver_name': driver_info.get('name', 'Unknown'),
                        'confidence': anomaly['confidence'],
                        'risk_weight': anomaly['risk_weight'],
                        'because': f'Driver {driver_info.get("name", "Unknown")} size mismatch: listed {hex(listed_size)} vs PE header {hex(carved_size)}',
                        'details': {
                            'listed_size': listed_size,
                            'pe_header_size': carved_size,
                            'difference': abs(listed_size - carved_size),
                        }
                    })
    
    return findings


# ============================================================================
# HIGH-LEVEL DKOM DETECTION INTERFACE
# ============================================================================

def perform_dkom_detection(
    layer,
    enumerated_drivers: List[Dict],
    scan_start: int = None,
    scan_end: int = None,
    scan_range: int = 0x10000000,  # 256MB default
    deep_scan: bool = False
) -> Dict:
    """
    Perform comprehensive DKOM detection.
    
    This is the main entry point for DKOM detection. It:
    1. Scans kernel memory for PE headers
    2. Compares against enumerated driver list
    3. Reports anomalies
    
    Args:
        layer: Volatility memory layer
        enumerated_drivers: List of drivers from normal enumeration
            Each must have: 'base_address', 'size', 'name'
        scan_start: Start address for PE scanning (uses lowest driver base if None)
        scan_end: End address for PE scanning (uses scan_start + scan_range if None)
        scan_range: Size of memory to scan if scan_end not specified
    
    Returns:
        Dict with:
            - 'findings': List of DKOM anomalies
            - 'carved_pe_count': Number of PE headers found
            - 'enumerated_count': Number of enumerated drivers
            - 'hidden_count': Number of potentially hidden drivers
            - 'summary': Human-readable summary
    """
    result = {
        'findings': [],
        'carved_pe_count': 0,
        'enumerated_count': len(enumerated_drivers),
        'hidden_count': 0,
        'unlinked_count': 0,
        'mismatch_count': 0,
        'summary': '',
        'scan_performed': False,
    }
    
    if not enumerated_drivers:
        result['summary'] = 'No enumerated drivers provided - cannot perform cross-view validation'
        return result
    
    # Determine scan range
    if scan_start is None:
        # Use the lowest driver base address
        bases = [d['base_address'] for d in enumerated_drivers if d.get('base_address')]
        if bases:
            scan_start = min(bases)
        else:
            result['summary'] = 'Could not determine scan start address'
            return result
    
    if scan_end is None:
        scan_end = scan_start + (scan_range * (4 if deep_scan else 1))
    
    # Build set of known bases
    known_bases = {d['base_address'] for d in enumerated_drivers if d.get('base_address')}
    
    # Scan for PE headers
    try:
        if deep_scan:
            carved_pe_list = scan_kernel_space_for_pe(
                layer,
                scan_start,
                scan_end,
                page_size=0x1000,
                known_bases=known_bases
            )
        else:
            carved_pe_list = scan_for_pe_headers(
                layer,
                scan_start,
                scan_end,
                page_size=0x1000,
                known_bases=known_bases
            )
        result['carved_pe_count'] = len(carved_pe_list)
        result['scan_performed'] = True
    except Exception as e:
        result['summary'] = f'PE scanning failed: {str(e)}'
        return result
    
    # Detect anomalies
    findings = detect_dkom_anomalies(
        enumerated_drivers,
        carved_pe_list,
        layer
    )
    
    result['findings'] = findings
    
    # Count anomaly types
    for finding in findings:
        anomaly_type = finding.get('anomaly_type', '')
        if anomaly_type == 'HIDDEN_DRIVER':
            result['hidden_count'] += 1
        elif anomaly_type == 'UNLINKED_OR_PAGED':
            result['unlinked_count'] += 1
        elif anomaly_type == 'SIZE_MISMATCH':
            result['mismatch_count'] += 1
    
    # Build summary
    summary_parts = []
    summary_parts.append(f"Scanned {hex(scan_end - scan_start)} bytes of kernel memory")
    summary_parts.append(f"Found {result['carved_pe_count']} PE headers")
    summary_parts.append(f"Enumerated {result['enumerated_count']} drivers")
    
    if result['hidden_count'] > 0:
        summary_parts.append(f"Warning: {result['hidden_count']} potentially hidden drivers detected")
    if result['unlinked_count'] > 0:
        summary_parts.append(f"{result['unlinked_count']} drivers with unreadable/paged headers")
    if result['mismatch_count'] > 0:
        summary_parts.append(f"{result['mismatch_count']} size mismatches detected")
    
    if not findings:
        summary_parts.append("No DKOM anomalies detected")
    
    result['summary'] = " | ".join(summary_parts)
    
    return result


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_dkom_risk_weight(anomaly_type: str) -> int:
    """Get the risk weight for a DKOM anomaly type."""
    return DKOM_ANOMALY_TYPES.get(anomaly_type, {}).get('risk_weight', 0)


def format_dkom_report(detection_result: Dict) -> str:
    """
    Format DKOM detection results as a human-readable report.
    
    Args:
        detection_result: Result from perform_dkom_detection()
    
    Returns:
        Formatted string report
    """
    lines = []
    lines.append("=" * 70)
    lines.append("DKOM DETECTION REPORT (Cross-View Validation)")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Scan Performed: {'Yes' if detection_result['scan_performed'] else 'No'}")
    lines.append(f"PE Headers Found: {detection_result['carved_pe_count']}")
    lines.append(f"Enumerated Drivers: {detection_result['enumerated_count']}")
    lines.append("")
    
    if detection_result['hidden_count'] > 0:
        lines.append("WARNING: HIDDEN DRIVERS DETECTED")
        lines.append(f"    {detection_result['hidden_count']} PE header(s) found in memory but NOT in driver list")
        lines.append("")
    
    if detection_result['findings']:
        lines.append("ANOMALY DETAILS:")
        lines.append("-" * 40)
        for i, finding in enumerate(detection_result['findings'], 1):
            lines.append(f"  {i}. [{finding['anomaly_type']}]")
            lines.append(f"     Address: {hex(finding['base_address'])}")
            if finding.get('driver_name'):
                lines.append(f"     Driver: {finding['driver_name']}")
            lines.append(f"     Confidence: {finding['confidence']:.0%}")
            lines.append(f"     Risk Weight: +{finding['risk_weight']}")
            lines.append(f"     Because: {finding['because']}")
            lines.append("")
    else:
        lines.append("No DKOM anomalies detected")
        lines.append("")
    
    lines.append("-" * 40)
    lines.append(f"Summary: {detection_result['summary']}")
    lines.append("=" * 70)
    
    return "\n".join(lines)


# ============================================================================
# MODULE TESTING
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("iKARMA DKOM Detector - Test Mode")
    print("=" * 70)
    
    # Test PE validation with sample data
    print("\n[TEST 1] PE Header Validation")
    
    # Create a minimal valid PE header
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[0x3c:0x40] = struct.pack('<I', 64)  # e_lfanew = 64
    
    pe_header = bytearray(256)
    pe_header[0:4] = b'PE\x00\x00'
    pe_header[4:6] = struct.pack('<H', 0x8664)  # AMD64
    pe_header[6:8] = struct.pack('<H', 5)  # 5 sections
    pe_header[8:12] = struct.pack('<I', 0x12345678)  # timestamp
    pe_header[20:22] = struct.pack('<H', 240)  # size of optional header
    pe_header[22:24] = struct.pack('<H', 0x1022)  # characteristics (DLL + SYSTEM)
    pe_header[24:26] = struct.pack('<H', 0x20b)  # PE32+ magic
    pe_header[24+56:24+60] = struct.pack('<I', 0x10000)  # SizeOfImage
    pe_header[24+16:24+20] = struct.pack('<I', 0x1000)  # AddressOfEntryPoint
    
    test_pe = bytes(dos_header + pe_header)
    
    is_valid, pe_info = validate_pe_header(test_pe)
    print(f"  Valid: {is_valid}")
    print(f"  Machine: {hex(pe_info.get('machine', 0))}")
    print(f"  Size: {hex(pe_info.get('size_of_image', 0))}")
    print(f"  Is Driver: {pe_info.get('is_driver', False)}")
    
    print("\n[TEST 2] DKOM Anomaly Detection (simulated)")
    
    # Simulate enumerated drivers
    enumerated = [
        {'base_address': 0xfffff80000000000, 'size': 0x10000, 'name': 'driver1.sys'},
        {'base_address': 0xfffff80000100000, 'size': 0x20000, 'name': 'driver2.sys'},
        {'base_address': 0xfffff80000200000, 'size': 0x15000, 'name': 'driver3.sys'},
    ]
    
    # Simulate carved PE headers (includes a "hidden" driver)
    carved = [
        {'base_address': 0xfffff80000000000, 'size_of_image': 0x10000, 'is_known': True, 'is_driver': True},
        {'base_address': 0xfffff80000100000, 'size_of_image': 0x20000, 'is_known': True, 'is_driver': True},
        # This one is "hidden" - not in enumerated list
        {'base_address': 0xfffff80000300000, 'size_of_image': 0x8000, 'is_known': False, 'is_driver': True},
    ]
    
    findings = detect_dkom_anomalies(enumerated, carved)
    
    print(f"  Enumerated drivers: {len(enumerated)}")
    print(f"  Carved PE headers: {len(carved)}")
    print(f"  Anomalies found: {len(findings)}")
    
    for finding in findings:
        print(f"\n  [{finding['anomaly_type']}]")
        print(f"    Address: {hex(finding['base_address'])}")
        print(f"    Driver: {finding.get('driver_name', 'Unknown')}")
        print(f"    Because: {finding['because']}")
    
    print("\n" + "=" * 70)
    print("DKOM Detector test completed")
    print("=" * 70)
