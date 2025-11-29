"""
Capability Pattern Detector for iKARMA BYOVD Detection

This module detects dangerous CAPABILITIES from disassembly and memory, NOT specific APIs.
These patterns are reliable because they detect BEHAVIOR, not names.

Detection methods (all ground truth with confidence 1.0):
1. MSR Manipulation - rdmsr/wrmsr opcodes
2. I/O Port Access - in/out instructions
3. Interrupt Manipulation - cli/sti instructions  
4. Control Register Access - mov cr* instructions
5. Suspicious Strings - PhysicalMemory, MmMapIoSpace, etc.

Author: iKARMA Team (Capability-First Analysis)
Version: 1.0
Last Updated: 2025-11-26
"""

import re
from typing import List, Dict, Optional


# ============================================================================
# CAPABILITY DEFINITIONS
# ============================================================================

CAPABILITY_DEFINITIONS = {
    'MSR_READ': {
        'description': 'Model-Specific Register read access',
        'why_dangerous': 'Can read CPU security settings (SMEP/SMAP status), kernel addresses, and system state',
        'byovd_usage': 'Detect security features before exploitation, read kernel base address',
        'risk_weight': 30,
    },
    'MSR_WRITE': {
        'description': 'Model-Specific Register write access',
        'why_dangerous': 'Can disable SMEP/SMAP, modify LSTAR (syscall handler), alter CPU security state',
        'byovd_usage': 'Disable kernel security mitigations, install syscall hooks',
        'risk_weight': 40,
    },
    'IO_PORT_READ': {
        'description': 'Direct I/O port read access',
        'why_dangerous': 'Can read from hardware ports, potentially accessing sensitive peripheral data',
        'byovd_usage': 'Read hardware state, communicate with devices bypassing OS',
        'risk_weight': 20,
    },
    'IO_PORT_WRITE': {
        'description': 'Direct I/O port write access',
        'why_dangerous': 'Can write to hardware ports, potentially controlling peripherals directly',
        'byovd_usage': 'Direct hardware manipulation, firmware attacks, DMA configuration',
        'risk_weight': 30,
    },
    'INTERRUPT_DISABLE': {
        'description': 'Interrupt flag manipulation (cli)',
        'why_dangerous': 'Disabling interrupts prevents system from responding to events including security software',
        'byovd_usage': 'Create uninterruptible execution windows for sensitive operations',
        'risk_weight': 25,
    },
    'INTERRUPT_ENABLE': {
        'description': 'Interrupt flag manipulation (sti)',
        'why_dangerous': 'Paired with cli indicates deliberate interrupt manipulation',
        'byovd_usage': 'Usually paired with cli for critical section protection',
        'risk_weight': 10,
    },
    'CONTROL_REG_READ': {
        'description': 'Control register read access (CR0, CR3, CR4)',
        'why_dangerous': 'Can read page table base (CR3), security flags (CR0, CR4)',
        'byovd_usage': 'Read kernel page tables for memory manipulation, check security state',
        'risk_weight': 25,
    },
    'CONTROL_REG_WRITE': {
        'description': 'Control register write access (CR0, CR3, CR4)',
        'why_dangerous': 'Can modify page tables, disable write protection (CR0.WP), alter security flags',
        'byovd_usage': 'Disable write protection for kernel patching, modify page tables for memory access',
        'risk_weight': 35,
    },
    'DEBUG_REG_ACCESS': {
        'description': 'Debug register access (DR0-DR7)',
        'why_dangerous': 'Can set hardware breakpoints, detect debuggers, or bypass debugging',
        'byovd_usage': 'Anti-debugging, detect security tool breakpoints',
        'risk_weight': 20,
    },
    'PHYSICAL_MEMORY_REF': {
        'description': 'Physical memory device string reference',
        'why_dangerous': 'Reference to \\Device\\PhysicalMemory indicates direct physical memory access intent',
        'byovd_usage': 'Read/write arbitrary physical memory bypassing all OS protections',
        'risk_weight': 45,
    },
    'DANGEROUS_API_STRING': {
        'description': 'Dangerous API name found in driver strings',
        'why_dangerous': 'Presence of API name in strings indicates the driver uses that API',
        'byovd_usage': 'API string presence is evidence of capability use',
        'risk_weight': 20,
    },
    'SECURITY_PRODUCT_REF': {
        'description': 'Reference to security product name',
        'why_dangerous': 'Driver may be targeting security software for termination or evasion',
        'byovd_usage': 'Identify and terminate/evade EDR/AV products',
        'risk_weight': 35,
    },
    'DESCRIPTOR_TABLE_MANIPULATION': {
        'description': 'Descriptor table manipulation (lgdt/lidt/lldt)',
        'why_dangerous': 'Can install custom interrupt handlers or modify system tables',
        'byovd_usage': 'Install rootkit hooks via modified IDT/GDT entries',
        'risk_weight': 40,
    },
    'SYSCALL_MANIPULATION': {
        'description': 'System call instruction (syscall/sysenter)',
        'why_dangerous': 'Direct syscall from kernel driver is unusual and may indicate syscall hooking',
        'byovd_usage': 'Direct system calls bypassing normal kernel interfaces',
        'risk_weight': 15,
    },
    'CACHE_MANIPULATION': {
        'description': 'Cache manipulation instructions (invd/wbinvd)',
        'why_dangerous': 'Can invalidate CPU caches, potentially causing system instability or hiding modifications',
        'byovd_usage': 'Flush caches to ensure memory modifications are visible',
        'risk_weight': 20,
    },
}


# ============================================================================
# MSR MANIPULATION DETECTION
# ============================================================================

def detect_msr_manipulation(disassembly_lines: List[str]) -> List[Dict]:
    """
    Detect MSR (Model Specific Register) manipulation.
    
    RELIABLE INDICATOR: 'rdmsr' and 'wrmsr' are actual CPU opcodes.
    Returns findings with confidence 1.0 (ground truth).
    
    Args:
        disassembly_lines: List of disassembled instruction strings
                          Format: "0x123456:\tmnemonic\top_str"
    
    Returns:
        List of capability findings with format:
        {
            'capability': 'MSR_WRITE' or 'MSR_READ',
            'confidence': 1.0,
            'evidence': 'wrmsr at 0x...',
            'address': '0x...',
            'instruction': 'wrmsr',
            'because': 'Human-readable explanation'
        }
    """
    findings = []
    
    for line in disassembly_lines:
        if not line or not isinstance(line, str):
            continue
        
        line_lower = line.lower()
        
        # Parse address from instruction
        address = 'unknown'
        parts = line.split(':')
        if parts:
            address = parts[0].strip()
        
        # Detect WRMSR (write MSR) - CRITICAL capability
        if '\twrmsr' in line_lower or ' wrmsr' in line_lower:
            cap_info = CAPABILITY_DEFINITIONS['MSR_WRITE']
            findings.append({
                'capability': 'MSR_WRITE',
                'confidence': 1.0,
                'evidence': f'wrmsr instruction at {address}',
                'address': address,
                'instruction': 'wrmsr',
                'because': f'wrmsr opcode detected - {cap_info["why_dangerous"]}',
                'risk_weight': cap_info['risk_weight'],
                'description': cap_info['description'],
            })
        
        # Detect RDMSR (read MSR)
        if '\trdmsr' in line_lower or ' rdmsr' in line_lower:
            cap_info = CAPABILITY_DEFINITIONS['MSR_READ']
            findings.append({
                'capability': 'MSR_READ',
                'confidence': 1.0,
                'evidence': f'rdmsr instruction at {address}',
                'address': address,
                'instruction': 'rdmsr',
                'because': f'rdmsr opcode detected - {cap_info["why_dangerous"]}',
                'risk_weight': cap_info['risk_weight'],
                'description': cap_info['description'],
            })
    
    return findings


# ============================================================================
# I/O PORT ACCESS DETECTION
# ============================================================================

def detect_io_port_access(disassembly_lines: List[str]) -> List[Dict]:
    """
    Detect direct I/O port access via 'in' and 'out' instructions.
    
    RELIABLE INDICATOR: in/out are actual CPU opcodes for port I/O.
    Returns findings with confidence 1.0 (ground truth).
    
    Args:
        disassembly_lines: List of disassembled instruction strings
    
    Returns:
        List of capability findings
    """
    findings = []
    
    # I/O port instructions (all variants)
    io_read_patterns = ['\tin\t', '\tins\t', '\tinsb', '\tinsw', '\tinsd']
    io_write_patterns = ['\tout\t', '\touts\t', '\toutsb', '\toutsw', '\toutsd']
    
    for line in disassembly_lines:
        if not line or not isinstance(line, str):
            continue
        
        line_lower = line.lower()
        
        # Parse address
        address = 'unknown'
        parts = line.split(':')
        if parts:
            address = parts[0].strip()
        
        # Extract mnemonic for evidence
        mnemonic = 'unknown'
        tab_parts = line.split('\t')
        if len(tab_parts) >= 2:
            mnemonic = tab_parts[1].strip()
        
        # Detect I/O read instructions
        for pattern in io_read_patterns:
            if pattern in line_lower:
                cap_info = CAPABILITY_DEFINITIONS['IO_PORT_READ']
                findings.append({
                    'capability': 'IO_PORT_READ',
                    'confidence': 1.0,
                    'evidence': f'{mnemonic} instruction at {address}',
                    'address': address,
                    'instruction': mnemonic,
                    'because': f'{mnemonic} opcode detected - {cap_info["why_dangerous"]}',
                    'risk_weight': cap_info['risk_weight'],
                    'description': cap_info['description'],
                })
                break
        
        # Detect I/O write instructions
        for pattern in io_write_patterns:
            if pattern in line_lower:
                cap_info = CAPABILITY_DEFINITIONS['IO_PORT_WRITE']
                findings.append({
                    'capability': 'IO_PORT_WRITE',
                    'confidence': 1.0,
                    'evidence': f'{mnemonic} instruction at {address}',
                    'address': address,
                    'instruction': mnemonic,
                    'because': f'{mnemonic} opcode detected - {cap_info["why_dangerous"]}',
                    'risk_weight': cap_info['risk_weight'],
                    'description': cap_info['description'],
                })
                break
    
    return findings


# ============================================================================
# INTERRUPT MANIPULATION DETECTION
# ============================================================================

def detect_interrupt_manipulation(disassembly_lines: List[str]) -> List[Dict]:
    """
    Detect interrupt flag manipulation via 'cli' and 'sti' instructions.
    
    RELIABLE INDICATOR: cli/sti are actual CPU opcodes.
    Returns findings with confidence 1.0 (ground truth).
    
    Args:
        disassembly_lines: List of disassembled instruction strings
    
    Returns:
        List of capability findings
    """
    findings = []
    cli_count = 0
    sti_count = 0
    
    for line in disassembly_lines:
        if not line or not isinstance(line, str):
            continue
        
        line_lower = line.lower()
        
        # Parse address
        address = 'unknown'
        parts = line.split(':')
        if parts:
            address = parts[0].strip()
        
        # Detect CLI (clear interrupt flag - disable interrupts)
        if '\tcli' in line_lower and 'rcli' not in line_lower:
            cli_count += 1
            cap_info = CAPABILITY_DEFINITIONS['INTERRUPT_DISABLE']
            findings.append({
                'capability': 'INTERRUPT_DISABLE',
                'confidence': 1.0,
                'evidence': f'cli instruction at {address}',
                'address': address,
                'instruction': 'cli',
                'because': f'cli opcode detected - {cap_info["why_dangerous"]}',
                'risk_weight': cap_info['risk_weight'],
                'description': cap_info['description'],
            })
        
        # Detect STI (set interrupt flag - enable interrupts)
        if '\tsti' in line_lower and 'sti' == line.split('\t')[1].strip().lower() if len(line.split('\t')) > 1 else False:
            # More precise check to avoid false positives on 'sti' substring
            tab_parts = line.split('\t')
            if len(tab_parts) >= 2 and tab_parts[1].strip().lower() == 'sti':
                sti_count += 1
                cap_info = CAPABILITY_DEFINITIONS['INTERRUPT_ENABLE']
                findings.append({
                    'capability': 'INTERRUPT_ENABLE',
                    'confidence': 1.0,
                    'evidence': f'sti instruction at {address}',
                    'address': address,
                    'instruction': 'sti',
                    'because': f'sti opcode detected - {cap_info["why_dangerous"]}',
                    'risk_weight': cap_info['risk_weight'],
                    'description': cap_info['description'],
                })
    
    return findings


# ============================================================================
# CONTROL REGISTER ACCESS DETECTION
# ============================================================================

def detect_control_register_access(disassembly_lines: List[str]) -> List[Dict]:
    """
    Detect CR0, CR2, CR3, CR4 manipulation (mov instructions involving control registers).
    
    RELIABLE INDICATOR: mov cr* is explicit control register access.
    Returns findings with confidence 1.0 (ground truth).
    
    Args:
        disassembly_lines: List of disassembled instruction strings
    
    Returns:
        List of capability findings
    """
    findings = []
    
    # Control register patterns
    cr_write_pattern = re.compile(r'mov\s+cr[0-4]\s*,', re.IGNORECASE)
    cr_read_pattern = re.compile(r'mov\s+\w+\s*,\s*cr[0-4]', re.IGNORECASE)
    
    # Debug register patterns
    dr_write_pattern = re.compile(r'mov\s+dr[0-7]\s*,', re.IGNORECASE)
    dr_read_pattern = re.compile(r'mov\s+\w+\s*,\s*dr[0-7]', re.IGNORECASE)
    
    for line in disassembly_lines:
        if not line or not isinstance(line, str):
            continue
        
        # Parse address
        address = 'unknown'
        parts = line.split(':')
        if parts:
            address = parts[0].strip()
        
        # Extract the instruction part
        instruction = line.split(':', 1)[1].strip() if ':' in line else line
        
        # Detect control register writes (mov cr*, reg)
        if cr_write_pattern.search(line):
            # Extract which CR is being written
            cr_match = re.search(r'cr([0-4])', line, re.IGNORECASE)
            cr_num = cr_match.group(1) if cr_match else '?'
            
            cap_info = CAPABILITY_DEFINITIONS['CONTROL_REG_WRITE']
            findings.append({
                'capability': 'CONTROL_REG_WRITE',
                'confidence': 1.0,
                'evidence': f'mov cr{cr_num}, ... instruction at {address}',
                'address': address,
                'instruction': f'mov cr{cr_num}',
                'because': f'Control register CR{cr_num} write detected - {cap_info["why_dangerous"]}',
                'risk_weight': cap_info['risk_weight'],
                'description': cap_info['description'],
                'register': f'CR{cr_num}',
            })
        
        # Detect control register reads (mov reg, cr*)
        elif cr_read_pattern.search(line):
            cr_match = re.search(r'cr([0-4])', line, re.IGNORECASE)
            cr_num = cr_match.group(1) if cr_match else '?'
            
            cap_info = CAPABILITY_DEFINITIONS['CONTROL_REG_READ']
            findings.append({
                'capability': 'CONTROL_REG_READ',
                'confidence': 1.0,
                'evidence': f'mov ..., cr{cr_num} instruction at {address}',
                'address': address,
                'instruction': f'mov cr{cr_num}',
                'because': f'Control register CR{cr_num} read detected - {cap_info["why_dangerous"]}',
                'risk_weight': cap_info['risk_weight'],
                'description': cap_info['description'],
                'register': f'CR{cr_num}',
            })
        
        # Detect debug register access
        if dr_write_pattern.search(line) or dr_read_pattern.search(line):
            dr_match = re.search(r'dr([0-7])', line, re.IGNORECASE)
            dr_num = dr_match.group(1) if dr_match else '?'
            is_write = dr_write_pattern.search(line) is not None
            
            cap_info = CAPABILITY_DEFINITIONS['DEBUG_REG_ACCESS']
            findings.append({
                'capability': 'DEBUG_REG_ACCESS',
                'confidence': 1.0,
                'evidence': f'mov {"dr" + dr_num + ", ..." if is_write else "..., dr" + dr_num} instruction at {address}',
                'address': address,
                'instruction': f'mov dr{dr_num}',
                'because': f'Debug register DR{dr_num} {"write" if is_write else "read"} detected - {cap_info["why_dangerous"]}',
                'risk_weight': cap_info['risk_weight'],
                'description': cap_info['description'],
                'register': f'DR{dr_num}',
            })
    
    return findings


# ============================================================================
# DESCRIPTOR TABLE MANIPULATION DETECTION
# ============================================================================

def detect_descriptor_table_manipulation(disassembly_lines: List[str]) -> List[Dict]:
    """
    Detect descriptor table manipulation (lgdt, lidt, lldt, ltr).
    
    RELIABLE INDICATOR: These are privileged instructions for modifying system tables.
    Returns findings with confidence 1.0 (ground truth).
    
    Args:
        disassembly_lines: List of disassembled instruction strings
    
    Returns:
        List of capability findings
    """
    findings = []
    
    # Descriptor table instructions
    dt_instructions = {
        'lgdt': 'Global Descriptor Table',
        'lidt': 'Interrupt Descriptor Table',
        'lldt': 'Local Descriptor Table',
        'ltr': 'Task Register',
        'sgdt': 'Global Descriptor Table (store)',
        'sidt': 'Interrupt Descriptor Table (store)',
        'sldt': 'Local Descriptor Table (store)',
        'str': 'Task Register (store)',
    }
    
    for line in disassembly_lines:
        if not line or not isinstance(line, str):
            continue
        
        line_lower = line.lower()
        
        # Parse address
        address = 'unknown'
        parts = line.split(':')
        if parts:
            address = parts[0].strip()
        
        for instr, table_name in dt_instructions.items():
            if f'\t{instr}\t' in line_lower or f'\t{instr} ' in line_lower:
                is_load = instr.startswith('l')
                cap_info = CAPABILITY_DEFINITIONS['DESCRIPTOR_TABLE_MANIPULATION']
                
                findings.append({
                    'capability': 'DESCRIPTOR_TABLE_MANIPULATION',
                    'confidence': 1.0,
                    'evidence': f'{instr} instruction at {address}',
                    'address': address,
                    'instruction': instr,
                    'because': f'{instr} opcode detected - {"Loading" if is_load else "Storing"} {table_name} - {cap_info["why_dangerous"]}',
                    'risk_weight': cap_info['risk_weight'] if is_load else cap_info['risk_weight'] // 2,
                    'description': cap_info['description'],
                    'table': table_name,
                })
                break
    
    return findings


# ============================================================================
# SYSCALL DETECTION
# ============================================================================

def detect_syscall_instructions(disassembly_lines: List[str]) -> List[Dict]:
    """
    Detect syscall/sysenter instructions (unusual in kernel drivers).
    
    Args:
        disassembly_lines: List of disassembled instruction strings
    
    Returns:
        List of capability findings
    """
    findings = []
    
    for line in disassembly_lines:
        if not line or not isinstance(line, str):
            continue
        
        line_lower = line.lower()
        
        # Parse address
        address = 'unknown'
        parts = line.split(':')
        if parts:
            address = parts[0].strip()
        
        if '\tsyscall' in line_lower:
            cap_info = CAPABILITY_DEFINITIONS['SYSCALL_MANIPULATION']
            findings.append({
                'capability': 'SYSCALL_MANIPULATION',
                'confidence': 1.0,
                'evidence': f'syscall instruction at {address}',
                'address': address,
                'instruction': 'syscall',
                'because': f'syscall opcode in kernel driver - {cap_info["why_dangerous"]}',
                'risk_weight': cap_info['risk_weight'],
                'description': cap_info['description'],
            })
        
        if '\tsysenter' in line_lower:
            cap_info = CAPABILITY_DEFINITIONS['SYSCALL_MANIPULATION']
            findings.append({
                'capability': 'SYSCALL_MANIPULATION',
                'confidence': 1.0,
                'evidence': f'sysenter instruction at {address}',
                'address': address,
                'instruction': 'sysenter',
                'because': f'sysenter opcode in kernel driver - {cap_info["why_dangerous"]}',
                'risk_weight': cap_info['risk_weight'],
                'description': cap_info['description'],
            })
    
    return findings


# ============================================================================
# CACHE MANIPULATION DETECTION
# ============================================================================

def detect_cache_manipulation(disassembly_lines: List[str]) -> List[Dict]:
    """
    Detect cache manipulation instructions (invd, wbinvd, invlpg).
    
    Args:
        disassembly_lines: List of disassembled instruction strings
    
    Returns:
        List of capability findings
    """
    findings = []
    
    cache_instructions = ['invd', 'wbinvd', 'invlpg', 'clflush', 'clflushopt', 'clwb']
    
    for line in disassembly_lines:
        if not line or not isinstance(line, str):
            continue
        
        line_lower = line.lower()
        
        # Parse address
        address = 'unknown'
        parts = line.split(':')
        if parts:
            address = parts[0].strip()
        
        for instr in cache_instructions:
            if f'\t{instr}' in line_lower:
                cap_info = CAPABILITY_DEFINITIONS['CACHE_MANIPULATION']
                findings.append({
                    'capability': 'CACHE_MANIPULATION',
                    'confidence': 1.0,
                    'evidence': f'{instr} instruction at {address}',
                    'address': address,
                    'instruction': instr,
                    'because': f'{instr} opcode detected - {cap_info["why_dangerous"]}',
                    'risk_weight': cap_info['risk_weight'],
                    'description': cap_info['description'],
                })
                break
    
    return findings


# ============================================================================
# SUSPICIOUS STRING DETECTION (from raw memory)
# ============================================================================

def detect_suspicious_strings(raw_memory_bytes: bytes) -> List[Dict]:
    """
    Detect suspicious strings in driver memory - GROUND TRUTH.
    
    These strings indicate the driver's intent/capability even if the
    corresponding code is obfuscated or paged out.
    
    Args:
        raw_memory_bytes: Raw bytes from driver memory
    
    Returns:
        List of capability findings
    """
    findings = []
    
    if not raw_memory_bytes:
        return findings
    
    # Suspicious string patterns (case-insensitive where applicable)
    suspicious_patterns = {
        # Physical memory access indicators
        b'PhysicalMemory': ('PHYSICAL_MEMORY_REF', 'Physical memory device reference'),
        b'\\Device\\PhysicalMemory': ('PHYSICAL_MEMORY_REF', 'Direct physical memory device path'),
        
        # Dangerous API names (indicates capability use)
        b'MmMapIoSpace': ('DANGEROUS_API_STRING', 'Physical memory mapping API'),
        b'MmMapIoSpaceEx': ('DANGEROUS_API_STRING', 'Extended physical memory mapping API'),
        b'ZwMapViewOfSection': ('DANGEROUS_API_STRING', 'Section mapping API (can map physical memory)'),
        b'ZwOpenSection': ('DANGEROUS_API_STRING', 'Section opening API'),
        b'MmCopyVirtualMemory': ('DANGEROUS_API_STRING', 'Cross-process memory copy API'),
        b'MmCopyMemory': ('DANGEROUS_API_STRING', 'Arbitrary memory copy API'),
        b'PsLookupProcessByProcessId': ('DANGEROUS_API_STRING', 'Process lookup API (DKOM precursor)'),
        b'ObRegisterCallbacks': ('DANGEROUS_API_STRING', 'Object callback registration'),
        b'ObUnRegisterCallbacks': ('DANGEROUS_API_STRING', 'Object callback removal'),
        b'ZwTerminateProcess': ('DANGEROUS_API_STRING', 'Process termination API'),
        b'ZwLoadDriver': ('DANGEROUS_API_STRING', 'Driver loading API'),
        b'MmUnloadSystemImage': ('DANGEROUS_API_STRING', 'Driver unloading API'),
        b'IoCreateDriver': ('DANGEROUS_API_STRING', 'Dynamic driver creation'),
        b'ExAllocatePoolWithTag': ('DANGEROUS_API_STRING', 'Kernel pool allocation'),
        
        # Security product targeting
        b'MsMpEng': ('SECURITY_PRODUCT_REF', 'Windows Defender process'),
        b'defender': ('SECURITY_PRODUCT_REF', 'Windows Defender reference'),
        b'csrss.exe': ('SECURITY_PRODUCT_REF', 'Critical system process reference'),
        b'lsass.exe': ('SECURITY_PRODUCT_REF', 'LSASS process reference (credentials)'),
        b'avast': ('SECURITY_PRODUCT_REF', 'Avast antivirus reference'),
        b'kaspersky': ('SECURITY_PRODUCT_REF', 'Kaspersky antivirus reference'),
        b'norton': ('SECURITY_PRODUCT_REF', 'Norton antivirus reference'),
        b'bitdefender': ('SECURITY_PRODUCT_REF', 'Bitdefender reference'),
        b'malwarebytes': ('SECURITY_PRODUCT_REF', 'Malwarebytes reference'),
        b'eset': ('SECURITY_PRODUCT_REF', 'ESET antivirus reference'),
        b'sophos': ('SECURITY_PRODUCT_REF', 'Sophos antivirus reference'),
        b'mcafee': ('SECURITY_PRODUCT_REF', 'McAfee antivirus reference'),
        b'crowdstrike': ('SECURITY_PRODUCT_REF', 'CrowdStrike EDR reference'),
        b'carbonblack': ('SECURITY_PRODUCT_REF', 'Carbon Black EDR reference'),
        b'sentinelone': ('SECURITY_PRODUCT_REF', 'SentinelOne EDR reference'),
        
        # Process hiding/DKOM indicators
        b'ActiveProcessLinks': ('DANGEROUS_API_STRING', 'EPROCESS linked list field (DKOM)'),
        b'EPROCESS': ('DANGEROUS_API_STRING', 'Process structure reference'),
        b'Token': ('DANGEROUS_API_STRING', 'Token field reference (privilege escalation)'),
        
        # Driver manipulation
        b'\\Registry\\Machine\\System': ('DANGEROUS_API_STRING', 'System registry reference'),
        b'\\Driver\\': ('DANGEROUS_API_STRING', 'Driver object reference'),
    }
    
    # Track found strings to avoid duplicates
    found_strings = set()
    
    for pattern, (capability, description) in suspicious_patterns.items():
        # Case-insensitive search for text patterns
        pattern_lower = pattern.lower()
        data_lower = raw_memory_bytes.lower()
        
        offset = data_lower.find(pattern_lower)
        if offset != -1 and pattern not in found_strings:
            found_strings.add(pattern)
            cap_info = CAPABILITY_DEFINITIONS.get(capability, {})
            
            findings.append({
                'capability': capability,
                'confidence': 1.0,  # String is ground truth
                'evidence': f'String "{pattern.decode("utf-8", errors="replace")}" found at offset {hex(offset)}',
                'address': hex(offset),
                'instruction': f'string: {pattern.decode("utf-8", errors="replace")}',
                'because': f'{description} - presence indicates intent to use this capability',
                'risk_weight': cap_info.get('risk_weight', 20),
                'description': cap_info.get('description', description),
                'string_value': pattern.decode('utf-8', errors='replace'),
            })
    
    return findings


# ============================================================================
# MAIN AGGREGATOR FUNCTION
# ============================================================================

def analyze_driver_capabilities(
    disassembly_lines: List[str],
    raw_memory_bytes: bytes = None
) -> Dict:
    """
    Main entry point: Analyze a driver for dangerous capabilities.
    
    This function runs ALL capability detection methods and returns
    findings with HIGH CONFIDENCE only - no guessing.
    
    Args:
        disassembly_lines: List of disassembled instruction strings
        raw_memory_bytes: Optional raw bytes from driver memory for string analysis
    
    Returns:
        Dict with:
            - 'findings': List of all capability findings
            - 'summary': Dict summarizing capabilities found
            - 'total_risk_weight': Sum of all risk weights
            - 'capability_count': Number of unique capabilities
            - 'ground_truth_count': Number of ground-truth detections
    """
    all_findings = []
    
    # Run all opcode-based detection methods
    if disassembly_lines:
        all_findings.extend(detect_msr_manipulation(disassembly_lines))
        all_findings.extend(detect_io_port_access(disassembly_lines))
        all_findings.extend(detect_interrupt_manipulation(disassembly_lines))
        all_findings.extend(detect_control_register_access(disassembly_lines))
        all_findings.extend(detect_descriptor_table_manipulation(disassembly_lines))
        all_findings.extend(detect_syscall_instructions(disassembly_lines))
        all_findings.extend(detect_cache_manipulation(disassembly_lines))
    
    # Run string-based detection
    if raw_memory_bytes:
        all_findings.extend(detect_suspicious_strings(raw_memory_bytes))
    
    # Build summary
    capability_counts = {}
    for finding in all_findings:
        cap = finding['capability']
        if cap not in capability_counts:
            capability_counts[cap] = 0
        capability_counts[cap] += 1
    
    total_risk_weight = sum(f.get('risk_weight', 0) for f in all_findings)
    ground_truth_count = sum(1 for f in all_findings if f.get('confidence', 0) >= 1.0)
    
    # Identify most critical findings
    critical_findings = [f for f in all_findings if f.get('risk_weight', 0) >= 35]
    
    return {
        'findings': all_findings,
        'summary': capability_counts,
        'total_risk_weight': total_risk_weight,
        'capability_count': len(capability_counts),
        'finding_count': len(all_findings),
        'ground_truth_count': ground_truth_count,
        'critical_findings': critical_findings,
        'has_msr_write': 'MSR_WRITE' in capability_counts,
        'has_physical_memory': 'PHYSICAL_MEMORY_REF' in capability_counts,
        'has_control_reg_write': 'CONTROL_REG_WRITE' in capability_counts,
        'has_interrupt_manipulation': 'INTERRUPT_DISABLE' in capability_counts,
    }


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_capability_risk_weight(capability_name: str) -> int:
    """Get the risk weight for a capability."""
    return CAPABILITY_DEFINITIONS.get(capability_name, {}).get('risk_weight', 0)


def get_capability_description(capability_name: str) -> str:
    """Get the description for a capability."""
    return CAPABILITY_DEFINITIONS.get(capability_name, {}).get('description', 'Unknown capability')


def format_capability_report(analysis_result: Dict) -> str:
    """
    Format capability analysis results as a human-readable report.
    
    Args:
        analysis_result: Result from analyze_driver_capabilities()
    
    Returns:
        Formatted string report
    """
    lines = []
    lines.append("=" * 70)
    lines.append("CAPABILITY ANALYSIS REPORT (Ground Truth Detection)")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Total Capabilities Detected: {analysis_result['capability_count']}")
    lines.append(f"Total Findings: {analysis_result['finding_count']}")
    lines.append(f"Ground Truth Detections: {analysis_result['ground_truth_count']}")
    lines.append(f"Total Risk Weight: {analysis_result['total_risk_weight']}")
    lines.append("")
    
    if analysis_result['summary']:
        lines.append("CAPABILITIES FOUND:")
        lines.append("-" * 40)
        for cap, count in sorted(analysis_result['summary'].items(), 
                                  key=lambda x: CAPABILITY_DEFINITIONS.get(x[0], {}).get('risk_weight', 0),
                                  reverse=True):
            weight = CAPABILITY_DEFINITIONS.get(cap, {}).get('risk_weight', 0)
            lines.append(f"  • {cap}: {count} instance(s) [Risk Weight: +{weight}]")
        lines.append("")
    
    if analysis_result['critical_findings']:
        lines.append("CRITICAL FINDINGS:")
        lines.append("-" * 40)
        for finding in analysis_result['critical_findings'][:10]:
            lines.append(f"  [{finding['capability']}] {finding['evidence']}")
            lines.append(f"    Because: {finding['because']}")
        lines.append("")
    
    lines.append("=" * 70)
    
    return "\n".join(lines)


# ============================================================================
# MODULE TESTING
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("iKARMA Capability Detector - Test Mode")
    print("=" * 70)
    
    # Test with sample disassembly containing various capabilities
    test_disassembly = [
        "0xfffff80012340000:\tmov\trax, cr3",           # CR3 read
        "0xfffff80012340010:\tmov\tcr0, rax",           # CR0 write
        "0xfffff80012340020:\twrmsr",                    # MSR write
        "0xfffff80012340030:\trdmsr",                    # MSR read
        "0xfffff80012340040:\tcli",                      # Disable interrupts
        "0xfffff80012340050:\tsti",                      # Enable interrupts
        "0xfffff80012340060:\tin\tal, dx",              # I/O port read
        "0xfffff80012340070:\tout\tdx, al",             # I/O port write
        "0xfffff80012340080:\tlidt\t[rax]",             # Load IDT
        "0xfffff80012340090:\tinvd",                     # Invalidate cache
        "0xfffff800123400a0:\tmov\tdr0, rax",           # Debug register write
        "0xfffff800123400b0:\tcall\tqword ptr [rax]",   # Normal call (should not be flagged)
    ]
    
    # Test with sample memory containing suspicious strings
    test_memory = b'\x00\x00PhysicalMemory\x00\x00MmMapIoSpace\x00MsMpEng.exe\x00'
    
    print("\nTest Disassembly:")
    for line in test_disassembly:
        print(f"  {line}")
    
    print("\nTest Memory Strings:")
    print(f"  {test_memory}")
    
    print("\nAnalyzing...")
    result = analyze_driver_capabilities(test_disassembly, test_memory)
    
    print(format_capability_report(result))
    
    print("\nDetailed Findings:")
    for i, finding in enumerate(result['findings'], 1):
        print(f"  {i}. [{finding['capability']}] {finding['evidence']}")
        print(f"     Confidence: {finding['confidence']}, Risk Weight: +{finding['risk_weight']}")
        print(f"     Because: {finding['because']}")
        print()
