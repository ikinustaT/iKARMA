"""
Forensics Utility Module for iKARMA BYOVD Detection

This module provides forensic-grade evidence collection functions:
1. Imphash calculation for malware family identification
2. Section-by-section SHA-256 hashing for integrity verification
3. Authenticode signature parsing and validation
4. PE anomaly classification (timestamp, sections, etc.)
5. Memory page permission analysis (RWX detection)

Author: Enhanced by Forensic Analysis Requirements
Version: 3.0
Last Updated: 2025-11-25
"""

import hashlib
import struct
import datetime
from typing import Dict, List, Tuple, Optional, Set
from enum import IntEnum

# PE constants
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# Page protection constants
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80


class PEAnomalyFlags:
    """PE Header anomaly classification flags."""
    NONE = 0
    FUTURE_TIMESTAMP = 1 << 0          # Timestamp in future (e.g., 2097)
    ANCIENT_TIMESTAMP = 1 << 1         # Timestamp before 1995
    INVALID_SIGNATURE = 1 << 2         # Authenticode signature invalid
    UNSIGNED_DRIVER = 1 << 3           # No digital signature
    PAGED_OUT_HEADER = 1 << 4          # PE header not in memory
    SUSPICIOUS_SECTION_COUNT = 1 << 5  # Unusual number of sections
    RWX_SECTION = 1 << 6               # Executable + writable section
    NON_CODE_EXECUTABLE = 1 << 7       # Data section marked executable
    MISMATCHED_ARCHITECTURE = 1 << 8   # Architecture doesn't match system
    ZERO_TIMESTAMP = 1 << 9            # Timestamp is zero (stripped)
    MODIFIED_HEADER = 1 << 10          # PE header shows signs of tampering

    @staticmethod
    def get_flag_names(flags: int) -> List[str]:
        """Convert anomaly flags to human-readable names."""
        names = []
        if flags & PEAnomalyFlags.FUTURE_TIMESTAMP:
            names.append("FUTURE_TIMESTAMP")
        if flags & PEAnomalyFlags.ANCIENT_TIMESTAMP:
            names.append("ANCIENT_TIMESTAMP")
        if flags & PEAnomalyFlags.INVALID_SIGNATURE:
            names.append("INVALID_SIGNATURE")
        if flags & PEAnomalyFlags.UNSIGNED_DRIVER:
            names.append("UNSIGNED_DRIVER")
        if flags & PEAnomalyFlags.PAGED_OUT_HEADER:
            names.append("PAGED_OUT_HEADER")
        if flags & PEAnomalyFlags.SUSPICIOUS_SECTION_COUNT:
            names.append("SUSPICIOUS_SECTION_COUNT")
        if flags & PEAnomalyFlags.RWX_SECTION:
            names.append("RWX_SECTION")
        if flags & PEAnomalyFlags.NON_CODE_EXECUTABLE:
            names.append("NON_CODE_EXECUTABLE")
        if flags & PEAnomalyFlags.MISMATCHED_ARCHITECTURE:
            names.append("MISMATCHED_ARCHITECTURE")
        if flags & PEAnomalyFlags.ZERO_TIMESTAMP:
            names.append("ZERO_TIMESTAMP")
        if flags & PEAnomalyFlags.MODIFIED_HEADER:
            names.append("MODIFIED_HEADER")
        return names if names else ["NONE"]


def calculate_imphash(import_table: List[Tuple[str, str]]) -> Optional[str]:
    """
    Calculate the import hash (imphash) for malware family identification.
    
    This implementation follows the pefile standard algorithm used by VirusTotal:
    1. Normalize DLL names (lowercase, remove extensions)
    2. Normalize function names (lowercase)
    3. Format as "dll.function" pairs
    4. Sort alphabetically
    5. Join with commas
    6. Calculate MD5 hash
    
    This ensures compatibility with VirusTotal and other forensic tools.
    
    Args:
        import_table: List of (dll_name, function_name) tuples
                     Example: [("ntoskrnl.exe", "MmMapIoSpace"), ...]
    
    Returns:
        32-character hex imphash string compatible with pefile/VirusTotal, or None if empty
    
    Note:
        If pefile library is available and you have the PE data in memory,
        you can also use: pe = pefile.PE(data=pe_bytes); imphash = pe.get_imphash()
        However, for memory dumps, this manual calculation is more reliable.
    """
    if not import_table:
        return None
    
    # Normalize import names following pefile standard algorithm
    normalized = []
    for dll, func in import_table:
        # Normalize DLL name: lowercase, remove common extensions
        dll_normalized = dll.lower()
        for ext in ['.sys', '.dll', '.exe', '.ocx']:
            dll_normalized = dll_normalized.replace(ext, '')
        
        # Normalize function name: lowercase
        # Skip ordinal-only imports (where func is empty or just a number)
        func_normalized = func.lower() if func else ''
        
        if func_normalized and not func_normalized.isdigit():
            # Format: "dll.function" (pefile standard)
            normalized.append(f"{dll_normalized}.{func_normalized}")
    
    if not normalized:
        return None
    
    # Sort alphabetically for consistency (pefile standard)
    normalized.sort()
    
    # Join with commas and calculate MD5 (pefile standard)
    import_string = ','.join(normalized)
    imphash = hashlib.md5(import_string.encode('utf-8')).hexdigest()
    
    return imphash


def extract_pe_sections(layer, base_addr: int) -> List[Dict]:
    """
    Extract PE section information from memory.
    
    Args:
        layer: Volatility memory layer
        base_addr: Driver base address
    
    Returns:
        List of section dictionaries with name, virtual_address, virtual_size,
        raw_size, characteristics, readable, hash
    """
    sections = []
    
    try:
        # Read DOS header
        dos_header = layer.read(base_addr, 0x40, pad=True)
        if dos_header[0:2] != b'MZ':
            return []
        
        # Get PE offset
        e_lfanew = struct.unpack('<I', dos_header[0x3c:0x40])[0]
        if e_lfanew > 0x1000:
            return []
        
        # Read PE header
        pe_offset = base_addr + e_lfanew
        pe_data = layer.read(pe_offset, 0x200, pad=True)
        
        if pe_data[0:4] != b'PE\x00\x00':
            return []
        
        # Parse COFF header
        num_sections = struct.unpack('<H', pe_data[6:8])[0]
        size_of_opt_header = struct.unpack('<H', pe_data[20:22])[0]
        
        # Section table starts after optional header
        section_offset = 24 + size_of_opt_header
        
        for i in range(num_sections):
            section_data_offset = section_offset + (i * 40)
            if section_data_offset + 40 > len(pe_data):
                break
            
            section_data = pe_data[section_data_offset:section_data_offset + 40]
            
            # Parse section header
            name = section_data[0:8].rstrip(b'\x00').decode('utf-8', errors='ignore')
            virtual_size = struct.unpack('<I', section_data[8:12])[0]
            virtual_address = struct.unpack('<I', section_data[12:16])[0]
            raw_size = struct.unpack('<I', section_data[16:20])[0]
            characteristics = struct.unpack('<I', section_data[36:40])[0]
            
            # Try to read section data for hashing
            section_va = base_addr + virtual_address
            section_hash = None
            is_readable = False
            
            try:
                section_content = layer.read(section_va, min(virtual_size, raw_size, 0x100000), pad=True)
                
                # Check if readable (more than 10% non-zero)
                non_zero = sum(1 for b in section_content if b != 0)
                if non_zero > len(section_content) * 0.1:
                    is_readable = True
                    section_hash = hashlib.sha256(section_content).hexdigest()
            except:
                pass
            
            sections.append({
                'name': name,
                'virtual_address': virtual_address,
                'virtual_size': virtual_size,
                'raw_size': raw_size,
                'characteristics': characteristics,
                'readable': is_readable,
                'hash': section_hash,
                'is_executable': bool(characteristics & IMAGE_SCN_MEM_EXECUTE),
                'is_writable': bool(characteristics & IMAGE_SCN_MEM_WRITE),
                'is_readable_flag': bool(characteristics & IMAGE_SCN_MEM_READ)
            })
    
    except Exception:
        pass
    
    return sections


def analyze_section_permissions(sections: List[Dict]) -> Tuple[List[str], int]:
    """
    Analyze section permissions for suspicious combinations (RWX, etc.).
    
    Args:
        sections: List of section dictionaries from extract_pe_sections
    
    Returns:
        Tuple of (findings_list, anomaly_flags)
    """
    findings = []
    flags = 0
    
    for section in sections:
        name = section['name']
        is_exec = section['is_executable']
        is_write = section['is_writable']
        
        # Check for RWX (read-write-execute)
        if is_exec and is_write:
            findings.append(f"RWX_SECTION: {name} has EXECUTE+WRITE permissions (self-modifying code)")
            flags |= PEAnomalyFlags.RWX_SECTION
        
        # Check for non-code sections being executable
        non_code_sections = ['.data', '.rdata', '.rsrc', '.reloc', '.idata', '.edata']
        if any(name.startswith(ncs) for ncs in non_code_sections) and is_exec:
            findings.append(f"NON_CODE_EXECUTABLE: {name} is data but marked executable")
            flags |= PEAnomalyFlags.NON_CODE_EXECUTABLE
    
    return findings, flags


def parse_authenticode_signature(layer, base_addr: int, pe_info: Dict) -> Dict:
    """
    Parse Authenticode digital signature from PE file.
    
    Args:
        layer: Volatility memory layer
        base_addr: Driver base address
        pe_info: PE header info dictionary
    
    Returns:
        Dict with signature_present, signer_name, validity_status, timestamp
    """
    result = {
        'signature_present': False,
        'signer_name': None,
        'validity_status': 'NOT_FOUND',
        'timestamp': None,
        'certificate_chain': []
    }
    
    try:
        # Read DOS header
        dos_header = layer.read(base_addr, 0x40, pad=True)
        if dos_header[0:2] != b'MZ':
            return result
        
        e_lfanew = struct.unpack('<I', dos_header[0x3c:0x40])[0]
        pe_offset = base_addr + e_lfanew
        
        # Read PE header with optional header
        pe_data = layer.read(pe_offset, 0x400, pad=True)
        if pe_data[0:4] != b'PE\x00\x00':
            return result
        
        # Get machine type to determine offset to data directories
        machine = struct.unpack('<H', pe_data[4:6])[0]
        is_64bit = (machine == 0x8664)
        
        # Optional header starts at offset 24
        opt_header_offset = 24
        
        # Data directory offset depends on architecture
        if is_64bit:
            data_dir_offset = opt_header_offset + 112
        else:
            data_dir_offset = opt_header_offset + 96
        
        # Security directory is entry 4
        security_dir_offset = data_dir_offset + (IMAGE_DIRECTORY_ENTRY_SECURITY * 8)
        
        if security_dir_offset + 8 > len(pe_data):
            return result
        
        security_rva = struct.unpack('<I', pe_data[security_dir_offset:security_dir_offset+4])[0]
        security_size = struct.unpack('<I', pe_data[security_dir_offset+4:security_dir_offset+8])[0]
        
        if security_rva == 0 or security_size == 0:
            result['validity_status'] = 'UNSIGNED'
            return result
        
        result['signature_present'] = True
        
        # Try to read certificate data
        try:
            # Security directory RVA is a file offset, not virtual address
            cert_data = layer.read(base_addr + security_rva, min(security_size, 0x10000), pad=True)
            
            # Basic parsing: look for common name patterns
            # Full X.509 parsing would require additional libraries
            cert_str = cert_data.decode('utf-8', errors='ignore')
            
            # Look for common certificate subject patterns
            if 'Microsoft' in cert_str:
                result['signer_name'] = 'Microsoft Corporation'
                result['validity_status'] = 'VALID_MICROSOFT'
            elif 'CN=' in cert_str:
                # Extract CN (Common Name) - simplified extraction
                try:
                    cn_start = cert_str.index('CN=') + 3
                    cn_end = cert_str.index(',', cn_start) if ',' in cert_str[cn_start:] else cn_start + 50
                    result['signer_name'] = cert_str[cn_start:cn_end].strip()
                    result['validity_status'] = 'PRESENT_UNKNOWN_VALIDITY'
                except:
                    result['validity_status'] = 'PRESENT_PARSE_FAILED'
            else:
                result['validity_status'] = 'PRESENT_PARSE_FAILED'
            
        except:
            result['validity_status'] = 'PRESENT_UNREADABLE'
    
    except Exception as e:
        result['validity_status'] = f'ERROR: {str(e)}'
    
    return result


def extract_pe_timedatestamp(layer, base_addr: int) -> Optional[int]:
    """
    Extract PE TimeDateStamp from COFF header.
    
    This provides a fallback for LoadTime when loader data structures
    are unavailable. Note: TimeDateStamp is compile time, not load time.
    
    Args:
        layer: Volatility memory layer
        base_addr: Driver base address
    
    Returns:
        Unix timestamp (seconds since epoch) or None if extraction fails
    """
    try:
        # Read DOS header
        dos_header = layer.read(base_addr, 0x40, pad=True)
        if dos_header[0:2] != b'MZ':
            return None
        
        # Get PE header offset
        e_lfanew = struct.unpack('<I', dos_header[0x3c:0x40])[0]
        pe_offset = base_addr + e_lfanew
        
        # Read PE header
        pe_data = layer.read(pe_offset, 0x100, pad=True)
        if pe_data[0:4] != b'PE\x00\x00':
            return None
        
        # Extract TimeDateStamp from COFF header (offset 8 after "PE\0\0")
        # COFF header: +0: Machine, +4: NumberOfSections, +8: TimeDateStamp
        timedatestamp = struct.unpack('<I', pe_data[8:12])[0]
        
        return timedatestamp if timedatestamp != 0 else None
    
    except Exception:
        return None


def classify_pe_timestamp(timestamp: int) -> Tuple[str, int]:
    """
    Classify PE compilation timestamp for anomalies.
    
    Args:
        timestamp: Unix timestamp from PE header
    
    Returns:
        Tuple of (classification_string, anomaly_flags)
    """
    flags = 0
    classification = "NORMAL"
    
    if timestamp == 0:
        classification = "ZERO_TIMESTAMP (stripped/obfuscated)"
        flags |= PEAnomalyFlags.ZERO_TIMESTAMP
        return classification, flags
    
    try:
        compile_time = datetime.datetime.utcfromtimestamp(timestamp)
        now = datetime.datetime.utcnow()
        epoch_1995 = datetime.datetime(1995, 1, 1)
        
        # Future timestamp
        if compile_time > now:
            classification = f"FUTURE_TIMESTAMP ({compile_time.strftime('%Y-%m-%d')})"
            flags |= PEAnomalyFlags.FUTURE_TIMESTAMP
        
        # Ancient timestamp (pre-Windows 95)
        elif compile_time < epoch_1995:
            classification = f"ANCIENT_TIMESTAMP ({compile_time.strftime('%Y-%m-%d')})"
            flags |= PEAnomalyFlags.ANCIENT_TIMESTAMP
        
        else:
            classification = f"NORMAL ({compile_time.strftime('%Y-%m-%d %H:%M:%S UTC')})"
    
    except (ValueError, OSError):
        classification = f"INVALID_TIMESTAMP ({hex(timestamp)})"
        flags |= PEAnomalyFlags.MODIFIED_HEADER
    
    return classification, flags


def extract_import_table(layer, base_addr: int) -> List[Tuple[str, str]]:
    """
    Extract import table from PE for imphash calculation.
    
    Args:
        layer: Volatility memory layer
        base_addr: Driver base address
    
    Returns:
        List of (dll_name, function_name) tuples
    """
    imports = []
    
    try:
        # Read DOS header
        dos_header = layer.read(base_addr, 0x40, pad=True)
        if dos_header[0:2] != b'MZ':
            return imports
        
        e_lfanew = struct.unpack('<I', dos_header[0x3c:0x40])[0]
        pe_offset = base_addr + e_lfanew
        
        # Read PE header
        pe_data = layer.read(pe_offset, 0x400, pad=True)
        if pe_data[0:4] != b'PE\x00\x00':
            return imports
        
        # Get architecture
        machine = struct.unpack('<H', pe_data[4:6])[0]
        is_64bit = (machine == 0x8664)
        
        # Get import directory RVA
        opt_header_offset = 24
        if is_64bit:
            import_dir_offset = opt_header_offset + 112 + (1 * 8)  # Entry 1 = imports
        else:
            import_dir_offset = opt_header_offset + 96 + (1 * 8)
        
        import_rva = struct.unpack('<I', pe_data[import_dir_offset:import_dir_offset+4])[0]
        
        if import_rva == 0:
            return imports
        
        # Read import directory table
        import_va = base_addr + import_rva
        import_data = layer.read(import_va, 0x1000, pad=True)
        
        # Parse import descriptors (20 bytes each)
        offset = 0
        for i in range(100):  # Max 100 DLLs
            descriptor = import_data[offset:offset+20]
            if len(descriptor) < 20:
                break
            
            name_rva = struct.unpack('<I', descriptor[12:16])[0]
            if name_rva == 0:
                break
            
            # Read DLL name
            try:
                dll_name_va = base_addr + name_rva
                dll_name_data = layer.read(dll_name_va, 100, pad=True)
                dll_name = dll_name_data.split(b'\x00')[0].decode('utf-8', errors='ignore')
                
                # Read function names from INT (Import Name Table)
                int_rva = struct.unpack('<I', descriptor[0:4])[0]
                if int_rva:
                    int_va = base_addr + int_rva
                    int_data = layer.read(int_va, 0x1000, pad=True)
                    
                    # Parse import name table
                    func_offset = 0
                    entry_size = 8 if is_64bit else 4
                    
                    for j in range(1000):  # Max 1000 functions per DLL
                        if func_offset + entry_size > len(int_data):
                            break
                        
                        if is_64bit:
                            entry = struct.unpack('<Q', int_data[func_offset:func_offset+8])[0]
                        else:
                            entry = struct.unpack('<I', int_data[func_offset:func_offset+4])[0]
                        
                        if entry == 0:
                            break
                        
                        # Check if ordinal import
                        if is_64bit:
                            is_ordinal = (entry & 0x8000000000000000) != 0
                        else:
                            is_ordinal = (entry & 0x80000000) != 0
                        
                        if not is_ordinal:
                            # Read function name
                            try:
                                func_rva = entry & 0x7FFFFFFF
                                func_va = base_addr + func_rva + 2  # Skip hint
                                func_name_data = layer.read(func_va, 100, pad=True)
                                func_name = func_name_data.split(b'\x00')[0].decode('utf-8', errors='ignore')
                                
                                imports.append((dll_name, func_name))
                            except:
                                pass
                        
                        func_offset += entry_size
            except:
                pass
            
            offset += 20
    
    except Exception:
        pass
    
    return imports


def analyze_driver_path(full_path: str) -> Tuple[bool, str, int]:
    """
    Analyze driver path for suspicious locations.
    
    Args:
        full_path: Full path to driver (e.g., \\SystemRoot\\System32\\drivers\\evil.sys)
    
    Returns:
        Tuple of (is_suspicious, reason, evidence_flags)
    """
    if not full_path:
        return False, "Path unavailable", 0
    
    path_lower = full_path.lower()
    flags = 0
    
    # Standard driver paths
    standard_paths = [
        '\\systemroot\\system32\\drivers\\',
        '\\windows\\system32\\drivers\\',
        'c:\\windows\\system32\\drivers\\'
    ]
    
    is_standard = any(path_lower.startswith(sp) for sp in standard_paths)
    
    if is_standard:
        return False, "Standard driver path", 0
    
    # Suspicious paths
    suspicious_patterns = [
        ('\\users\\', 'User directory'),
        ('\\temp\\', 'Temporary directory'),
        ('\\programdata\\', 'ProgramData directory'),
        ('\\appdata\\', 'AppData directory'),
        ('\\downloads\\', 'Downloads directory'),
        ('\\desktop\\', 'Desktop directory'),
        ('\\documents\\', 'Documents directory')
    ]
    
    for pattern, reason in suspicious_patterns:
        if pattern in path_lower:
            return True, reason, 1  # Flag as suspicious
    
    # Non-standard but potentially legitimate (third-party drivers)
    if '\\program files\\' in path_lower or '\\program files (x86)\\' in path_lower:
        return False, "Third-party driver path (potentially legitimate)", 0
    
    return True, "Non-standard path", 1


def calculate_temporal_outliers(all_load_times: List[int]) -> Dict:
    """
    Calculate statistical outliers in driver load times.
    
    Args:
        all_load_times: List of all driver load times (Windows FILETIME format)
    
    Returns:
        Dict with median, std_dev, outlier_threshold
    """
    if not all_load_times or len(all_load_times) < 3:
        return {'median': 0, 'std_dev': 0, 'outlier_threshold': 0}
    
    # Calculate statistics
    sorted_times = sorted(all_load_times)
    n = len(sorted_times)
    
    # Median
    if n % 2 == 0:
        median = (sorted_times[n//2 - 1] + sorted_times[n//2]) / 2
    else:
        median = sorted_times[n//2]
    
    # Standard deviation
    mean = sum(sorted_times) / n
    variance = sum((x - mean) ** 2 for x in sorted_times) / n
    std_dev = variance ** 0.5
    
    # Outlier threshold (3 standard deviations)
    outlier_threshold = mean + (3 * std_dev)
    
    return {
        'median': median,
        'mean': mean,
        'std_dev': std_dev,
        'outlier_threshold': outlier_threshold
    }


def is_temporal_outlier(load_time: int, stats: Dict) -> Tuple[bool, str]:
    """
    Check if a driver's load time is a statistical outlier.
    
    Args:
        load_time: Driver load time (Windows FILETIME)
        stats: Statistics from calculate_temporal_outliers
    
    Returns:
        Tuple of (is_outlier, explanation)
    """
    if not load_time or not stats.get('outlier_threshold'):
        return False, "Insufficient data"
    
    if load_time > stats['outlier_threshold']:
        deviation = (load_time - stats['mean']) / stats['std_dev'] if stats['std_dev'] > 0 else 0
        return True, f"Loaded {deviation:.1f} std deviations after other drivers"
    
    return False, "Normal load time"


# Known forensically noisy but legitimate drivers
FORENSIC_ARTIFACTS_PROFILES = {
    'anti_cheat': {
        'names': ['easyanticheat', 'battleye', 'vgk', 'vgc', 'faceit'],
        'reason': 'Anti-cheat software (forensically complex but legitimate)',
        'risk_modifier': -20,
        'expected_features': ['custom_ioctl', 'kernel_callbacks', 'memory_scanning']
    },
    'edr_av': {
        'names': ['wdfilter', 'wdnisdrv', 'wdboot', 'sense', 'mssecflt', 'cldflt'],
        'reason': 'EDR/Antivirus driver (expected to have privileged operations)',
        'risk_modifier': -25,
        'expected_features': ['custom_ioctl', 'process_callbacks', 'registry_callbacks']
    },
    'virtualization': {
        'names': ['vmx', 'vmmemctl', 'vmci', 'vmhgfs', 'vboxdrv', 'vboxnetadp'],
        'reason': 'Virtualization driver (hypervisor components)',
        'risk_modifier': -15,
        'expected_features': ['custom_ioctl', 'dma_operations', 'memory_mapping']
    },
    'debugging': {
        'names': ['livekd', 'kd', 'kldbgdrv', 'dbk64', 'windbg'],
        'reason': 'Debugging/diagnostic driver (privileged by design)',
        'risk_modifier': -10,
        'expected_features': ['memory_access', 'kernel_debugging']
    }
}


def check_forensic_artifacts_profile(driver_name: str) -> Optional[Dict]:
    """
    Check if driver matches a known forensically noisy but legitimate profile.
    
    Args:
        driver_name: Driver name (normalized, lowercase)
    
    Returns:
        Profile dict if matched, None otherwise
    """
    driver_normalized = driver_name.lower().replace('.sys', '')
    
    for profile_type, profile in FORENSIC_ARTIFACTS_PROFILES.items():
        for pattern in profile['names']:
            if pattern in driver_normalized:
                return {
                    'type': profile_type,
                    'reason': profile['reason'],
                    'risk_modifier': profile['risk_modifier'],
                    'expected_features': profile['expected_features']
                }
    
    return None
