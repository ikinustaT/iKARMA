"""
API Signature Database for iKARMA BYOVD Detection

This module contains the comprehensive database of dangerous Windows kernel APIs
commonly used in Bring Your Own Vulnerable Driver (BYOVD) attacks.

Author: Person 2 (API Hunter)
Last Updated: 2025-11-16
"""

# ============================================================================
# DANGEROUS API DATABASE
# ============================================================================

API_DATABASE = {
    # ========================================================================
    # CATEGORY 1: ARBITRARY MEMORY READ/WRITE
    # ========================================================================
    'MEMORY_ACCESS': {
        'MmMapIoSpace': {
            'risk': 9,
            'capability': 'Map arbitrary physical memory to virtual address space',
            'why_dangerous': 'Allows raw physical memory access, bypassing all protections',
            'byovd_usage': 'Read/write arbitrary kernel memory, patch kernel structures',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'PVOID MmMapIoSpace(PHYSICAL_ADDRESS, SIZE_T, MEMORY_CACHING_TYPE)',
            'pattern': 'Call to MmMapIoSpace with user-controlled PhysicalAddress',
        },

        'MmMapIoSpaceEx': {
            'risk': 9,
            'capability': 'Extended physical memory mapping with cache control',
            'why_dangerous': 'Same as MmMapIoSpace with additional control over caching',
            'byovd_usage': 'Read/write arbitrary kernel memory with cache manipulation',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS, SIZE_T, ULONG)',
            'pattern': 'Call to MmMapIoSpaceEx with user-controlled parameters',
        },

        'ZwMapViewOfSection': {
            'risk': 9,
            'capability': 'Map section object (including physical memory) into process',
            'why_dangerous': 'Can map \\Device\\PhysicalMemory for direct physical memory access',
            'byovd_usage': 'Read/write physical memory from user mode',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS ZwMapViewOfSection(HANDLE, HANDLE, PVOID*, ...)',
            'pattern': 'ZwOpenSection("\\Device\\PhysicalMemory") followed by ZwMapViewOfSection',
        },

        'MmCopyVirtualMemory': {
            'risk': 9,
            'capability': 'Copy memory between arbitrary address spaces',
            'why_dangerous': 'Can copy from/to any process without validation',
            'byovd_usage': 'Read credentials, inject code into protected processes',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS MmCopyVirtualMemory(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, ...)',
            'pattern': 'User-controlled source/destination addresses with no validation',
        },

        'MmCopyMemory': {
            'risk': 9,
            'capability': 'Copy memory with MDL-based access',
            'why_dangerous': 'Can access arbitrary physical memory',
            'byovd_usage': 'Read/write kernel memory bypassing protections',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS MmCopyMemory(PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T)',
            'pattern': 'User-controlled addresses without validation',
        },
    },

    # ========================================================================
    # CATEGORY 2: PHYSICAL MEMORY ACCESS
    # ========================================================================
    'PHYSICAL_MEMORY': {
        'ZwOpenSection': {
            'risk': 10,
            'capability': 'Open handle to physical memory section',
            'why_dangerous': 'Opens \\Device\\PhysicalMemory for direct physical memory access',
            'byovd_usage': 'Foundation for memory manipulation attacks',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS ZwOpenSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)',
            'pattern': 'String reference to "\\Device\\PhysicalMemory" passed to ZwOpenSection',
            'string_indicators': ['PhysicalMemory', '\\Device\\PhysicalMemory'],
        },

        '__readmsr': {
            'risk': 8,
            'capability': 'Read Model-Specific Register',
            'why_dangerous': 'Can read CPU control registers including security features',
            'byovd_usage': 'Detect SMEP/SMAP status, read sensitive CPU state',
            'detection_methods': ['opcode', 'string'],
            'signature': 'unsigned __int64 __readmsr(unsigned long)',
            'pattern': 'rdmsr instruction in disassembly',
            'opcode_pattern': 'rdmsr',
        },

        '__writemsr': {
            'risk': 10,
            'capability': 'Write Model-Specific Register',
            'why_dangerous': 'Can disable SMEP/SMAP, modify system behavior',
            'byovd_usage': 'Disable CPU security features, enable kernel exploits',
            'detection_methods': ['opcode', 'string'],
            'signature': 'void __writemsr(unsigned long, unsigned __int64)',
            'pattern': 'wrmsr instruction targeting security-critical MSRs',
            'opcode_pattern': 'wrmsr',
            'critical_msrs': {
                '0xC0000082': 'IA32_LSTAR - SYSCALL handler',
                '0x277': 'IA32_PAT - memory types',
            },
        },
    },

    # ========================================================================
    # CATEGORY 3: PROCESS MANIPULATION
    # ========================================================================
    'PROCESS_MANIPULATION': {
        'ZwTerminateProcess': {
            'risk': 7,
            'capability': 'Terminate arbitrary process',
            'why_dangerous': 'Can kill security products (EDR/AV)',
            'byovd_usage': 'Blind security monitoring',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS ZwTerminateProcess(HANDLE, NTSTATUS)',
            'pattern': 'Call with process handle from user mode',
            'risk_modifier': '+3 if targets security products',
        },

        'PsTerminateSystemThread': {
            'risk': 7,
            'capability': 'Terminate system threads',
            'why_dangerous': 'Can disrupt security monitoring threads',
            'byovd_usage': 'Kill EDR/AV worker threads',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS PsTerminateSystemThread(NTSTATUS)',
            'pattern': 'Terminate threads not owned by driver',
        },

        'PsLookupProcessByProcessId': {
            'risk': 8,
            'capability': 'Locate EPROCESS structure by PID',
            'why_dangerous': 'Enables direct EPROCESS manipulation (DKOM)',
            'byovd_usage': 'Token stealing, process hiding, privilege escalation',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS PsLookupProcessByProcessId(HANDLE, PEPROCESS*)',
            'pattern': 'Followed by writes to EPROCESS offsets (Token, ActiveProcessLinks)',
            'suspicious_offsets': {
                '0x360': 'Token field (Windows 10)',
                '0x4B8': 'Token field (Windows 11)',
                '0x448': 'ActiveProcessLinks (process hiding)',
            },
        },

        'PsCreateSystemThread': {
            'risk': 7,
            'capability': 'Create kernel-mode thread',
            'why_dangerous': 'Execute arbitrary kernel code persistently',
            'byovd_usage': 'Persistent kernel execution, rootkit behavior',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS PsCreateSystemThread(PHANDLE, ULONG, ..., PKSTART_ROUTINE, PVOID)',
            'pattern': 'Call with user-controlled start routine, no validation',
        },
    },

    # ========================================================================
    # CATEGORY 4: CALLBACK/HOOK MANIPULATION
    # ========================================================================
    'CALLBACK_MANIPULATION': {
        'ObRegisterCallbacks': {
            'risk': 6,
            'capability': 'Register object callbacks (process/thread protection)',
            'why_dangerous': 'Can block access to processes, hide objects',
            'byovd_usage': 'Protect malware from termination',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS ObRegisterCallbacks(POB_CALLBACK_REGISTRATION, PVOID*)',
            'pattern': 'Callback that returns STATUS_ACCESS_DENIED selectively',
            'risk_modifier': '+2 if protects suspicious processes',
        },

        'ObUnRegisterCallbacks': {
            'risk': 8,
            'capability': 'Unregister object callbacks',
            'why_dangerous': 'Can remove security product callbacks',
            'byovd_usage': 'Blind EDR monitoring',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'void ObUnRegisterCallbacks(PVOID)',
            'pattern': 'Unregister callbacks not owned by driver',
            'risk_modifier': '+2 if callback handle from user mode',
        },

        'CmUnRegisterCallback': {
            'risk': 7,
            'capability': 'Unregister registry callbacks',
            'why_dangerous': 'Disable registry monitoring by security products',
            'byovd_usage': 'Evade registry-based detection',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS CmUnRegisterCallback(LARGE_INTEGER)',
            'pattern': 'Remove callbacks not owned by driver',
        },
    },

    # ========================================================================
    # CATEGORY 5: DRIVER/MODULE LOADING
    # ========================================================================
    'DRIVER_LOADING': {
        'ZwLoadDriver': {
            'risk': 6,
            'capability': 'Load kernel driver',
            'why_dangerous': 'Load additional malicious drivers',
            'byovd_usage': 'Multi-stage attacks, load unsigned drivers',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS ZwLoadDriver(PUNICODE_STRING)',
            'pattern': 'User-controlled driver path, registry key manipulation',
            'risk_modifier': '+3 if loading unsigned driver',
        },

        'MmLoadSystemImage': {
            'risk': 8,
            'capability': 'Load kernel module',
            'why_dangerous': 'Bypass driver signature enforcement',
            'byovd_usage': 'Load unsigned code into kernel',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS MmLoadSystemImage(PUNICODE_STRING, ...)',
            'pattern': 'Non-standard module loading path, user-controlled image name',
        },

        'MmUnloadSystemImage': {
            'risk': 7,
            'capability': 'Unload kernel module',
            'why_dangerous': 'Unload security product drivers',
            'byovd_usage': 'Disable EDR/AV kernel components',
            'detection_methods': ['string', 'call', 'import'],
            'signature': 'NTSTATUS MmUnloadSystemImage(PVOID)',
            'pattern': 'Unload drivers not owned by current driver',
        },
    },
}


# ============================================================================
# API CALL CHAINS - Multi-step attack patterns
# ============================================================================

API_CALL_CHAINS = [
    {
        'name': 'Physical Memory Read/Write',
        'risk': 10,
        'sequence': ['ZwOpenSection', 'ZwMapViewOfSection'],
        'description': 'Opens physical memory section and maps it for R/W access',
        'indicators': ['String "PhysicalMemory"', 'Sequential calls'],
    },
    {
        'name': 'Process Token Theft',
        'risk': 10,
        'sequence': ['PsLookupProcessByProcessId', 'PsLookupProcessByProcessId'],
        'description': 'Lookup two processes (System + target) and copy token',
        'indicators': ['Two consecutive PsLookup calls', 'EPROCESS offset 0x360 access'],
    },
    {
        'name': 'Driver Tampering',
        'risk': 8,
        'sequence': ['Enumerate modules', 'MmUnloadSystemImage'],
        'description': 'Find and unload security product drivers',
        'indicators': ['Module enumeration', 'Unload calls'],
    },
]


# ============================================================================
# OPCODE PATTERNS - Assembly instruction patterns
# ============================================================================

OPCODE_PATTERNS = {
    'memory_mapping': {
        'pattern': ['lea', 'mov', 'call'],
        'description': 'Memory mapping operation',
        'example': 'lea rcx, [user_address] ; mov rdx, [user_size] ; call MmMapIoSpace',
        'risk': 9,
    },
    'process_lookup': {
        'pattern': ['mov', 'call', 'mov'],
        'description': 'Process lookup and EPROCESS save',
        'example': 'mov rcx, [user_pid] ; call PsLookupProcessByProcessId ; mov [rbp+var], rax',
        'risk': 8,
    },
    'token_manipulation': {
        'pattern': ['mov', 'add', 'mov', 'mov'],
        'description': 'EPROCESS token field manipulation',
        'example': 'mov rax, [eprocess] ; add rax, 360h ; mov rcx, [rax] ; mov [target+360h], rcx',
        'risk': 10,
    },
    'msr_instructions': {
        'pattern': ['rdmsr', 'wrmsr'],
        'description': 'Model-Specific Register manipulation',
        'example': 'mov ecx, 0C0000082h ; rdmsr ; <modify> ; wrmsr',
        'risk': 10,
    },
}


# ============================================================================
# STRING INDICATORS - Suspicious strings that indicate dangerous capabilities
# ============================================================================

STRING_INDICATORS = {
    'PhysicalMemory': {
        'risk': 10,
        'category': 'PHYSICAL_MEMORY',
        'description': 'Reference to physical memory device object',
    },
    '\\Device\\PhysicalMemory': {
        'risk': 10,
        'category': 'PHYSICAL_MEMORY',
        'description': 'Full path to physical memory section',
    },
    'MsMpEng': {
        'risk': 7,
        'category': 'PROCESS_MANIPULATION',
        'description': 'Windows Defender process name - likely targeted for termination',
    },
    'avp.exe': {
        'risk': 7,
        'category': 'PROCESS_MANIPULATION',
        'description': 'Kaspersky process - security product targeting',
    },
}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_all_api_names():
    """
    Returns a flat list of all API names across all categories.

    Returns:
        list: List of API name strings
    """
    api_names = []
    for category in API_DATABASE.values():
        api_names.extend(category.keys())
    return api_names


def get_api_info(api_name):
    """
    Retrieve information about a specific API.

    Args:
        api_name (str): Name of the API (e.g., 'MmMapIoSpace')

    Returns:
        tuple: (category_name, api_info_dict) or (None, None) if not found
    """
    for category_name, category_apis in API_DATABASE.items():
        if api_name in category_apis:
            return category_name, category_apis[api_name]
    return None, None


def get_apis_by_risk(min_risk=7):
    """
    Get all APIs with risk score >= min_risk.

    Args:
        min_risk (int): Minimum risk threshold (default: 7)

    Returns:
        list: List of tuples (api_name, category, risk_score)
    """
    high_risk_apis = []
    for category_name, category_apis in API_DATABASE.items():
        for api_name, api_info in category_apis.items():
            if api_info['risk'] >= min_risk:
                high_risk_apis.append((api_name, category_name, api_info['risk']))

    # Sort by risk score descending
    return sorted(high_risk_apis, key=lambda x: x[2], reverse=True)


def get_apis_by_category(category):
    """
    Get all APIs in a specific category.

    Args:
        category (str): Category name (e.g., 'MEMORY_ACCESS')

    Returns:
        dict: APIs in that category, or empty dict if category not found
    """
    return API_DATABASE.get(category, {})


# ============================================================================
# MODULE TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("iKARMA API Signature Database - Test Mode")
    print("=" * 70)

    # Test 1: Count total APIs
    total_apis = sum(len(category) for category in API_DATABASE.values())
    print(f"\n[OK] Total APIs in database: {total_apis}")

    # Test 2: List all API names
    print("\n[OK] All monitored APIs:")
    for api in get_all_api_names():
        print(f"    - {api}")

    # Test 3: Show critical APIs (risk >= 9)
    print("\n[OK] Critical APIs (risk >= 9):")
    for api_name, category, risk in get_apis_by_risk(min_risk=9):
        print(f"    - {api_name} [{category}] Risk: {risk}")

    # Test 4: Demonstrate API lookup
    print("\n[OK] Example API lookup: MmMapIoSpace")
    category, info = get_api_info('MmMapIoSpace')
    if info:
        print(f"    Category: {category}")
        print(f"    Risk: {info['risk']}")
        print(f"    Why dangerous: {info['why_dangerous']}")
        print(f"    Detection methods: {info['detection_methods']}")

    # Test 5: Show categories
    print("\n[OK] API Categories:")
    for category in API_DATABASE.keys():
        count = len(API_DATABASE[category])
        print(f"    - {category}: {count} APIs")

    print("\n" + "=" * 70)
    print("Database ready for integration with api_scanner.py")
    print("=" * 70)
