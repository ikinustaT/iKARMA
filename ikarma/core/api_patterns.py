"""
Dangerous API pattern database for BYOVD / Dangerous API detection.
"""

from typing import Dict, List, Tuple, Optional

API_DATABASE: Dict[str, Dict[str, object]] = {
    # Physical memory access
    "MmMapIoSpace": {
        "category": "MEMORY_ACCESS",
        "risk": 9,
        "why_dangerous": "Maps arbitrary physical memory into kernel virtual address space",
        "byovd_usage": "Map physical memory to read/write hardware or kernel structures",
    },
    "MmMapIoSpaceEx": {
        "category": "MEMORY_ACCESS",
        "risk": 9,
        "why_dangerous": "Extended physical memory mapping with caching control",
        "byovd_usage": "Fine-grained physical memory access for patching or DMA staging",
    },
    "MmUnmapIoSpace": {
        "category": "MEMORY_ACCESS",
        "risk": 7,
        "why_dangerous": "Unmaps previously mapped physical memory",
        "byovd_usage": "Cleanup after physical memory mapping primitives",
    },
    "MmMapLockedPagesSpecifyCache": {
        "category": "MEMORY_ACCESS",
        "risk": 8,
        "why_dangerous": "Maps locked MDL pages with chosen caching attributes",
        "byovd_usage": "Create stable mappings for physical/virtual RW primitives",
    },
    "MmProbeAndLockPages": {
        "category": "MEMORY_ACCESS",
        "risk": 7,
        "why_dangerous": "Pins user pages into memory for kernel access",
        "byovd_usage": "Lock attacker-controlled buffers for DMA or kernel writes",
    },
    "MmUnlockPages": {
        "category": "MEMORY_ACCESS",
        "risk": 5,
        "why_dangerous": "Unlocks previously pinned pages",
        "byovd_usage": "Cleanup after mapping pinned buffers used for IOCTL payloads",
    },
    # Process memory manipulation
    "ZwWriteVirtualMemory": {
        "category": "PROCESS_MEMORY",
        "risk": 9,
        "why_dangerous": "Writes to arbitrary process memory from kernel mode",
        "byovd_usage": "Inject code or tamper with security tools",
    },
    "MmCopyVirtualMemory": {
        "category": "PROCESS_MEMORY",
        "risk": 8,
        "why_dangerous": "Copies memory between processes, enabling arbitrary read/write",
        "byovd_usage": "Cross-process memory copy for injection or credential theft",
    },
    "ZwReadVirtualMemory": {
        "category": "PROCESS_MEMORY",
        "risk": 8,
        "why_dangerous": "Reads arbitrary process memory from kernel mode",
        "byovd_usage": "Exfiltrate secrets or bypass user-mode protections",
    },
    "ZwProtectVirtualMemory": {
        "category": "PROCESS_MEMORY",
        "risk": 7,
        "why_dangerous": "Changes memory protections on arbitrary process regions",
        "byovd_usage": "Make shellcode pages executable or writable",
    },
    "ZwAllocateVirtualMemory": {
        "category": "PROCESS_MEMORY",
        "risk": 7,
        "why_dangerous": "Allocates memory in arbitrary processes with chosen protections",
        "byovd_usage": "Stage userland payload buffers for injection",
    },
    "ZwFreeVirtualMemory": {
        "category": "PROCESS_MEMORY",
        "risk": 5,
        "why_dangerous": "Frees arbitrary process memory regions",
        "byovd_usage": "Tear down evidence of injected buffers",
    },
    # Process handle manipulation
    "ZwOpenProcess": {
        "category": "PROCESS_HANDLE",
        "risk": 6,
        "why_dangerous": "Obtains handles with controllable access masks to target processes",
        "byovd_usage": "Open protected processes for later memory or handle tampering",
    },
    "PsLookupProcessByProcessId": {
        "category": "PROCESS_HANDLE",
        "risk": 6,
        "why_dangerous": "Resolves arbitrary PIDs to EPROCESS pointers",
        "byovd_usage": "Locate targets before performing memory operations",
    },
    # Kernel memory allocation
    "ExAllocatePool": {
        "category": "KERNEL_MEMORY",
        "risk": 5,
        "why_dangerous": "Allocates kernel pool memory without tagging discipline",
        "byovd_usage": "Allocate buffers for shellcode or staging hooks",
    },
    "ExAllocatePoolWithTag": {
        "category": "KERNEL_MEMORY",
        "risk": 5,
        "why_dangerous": "Allocates tagged kernel pool memory",
        "byovd_usage": "Allocate controlled buffers for implants with identifiable tag",
    },
    # Section mapping
    "ZwMapViewOfSection": {
        "category": "MEMORY_ACCESS",
        "risk": 7,
        "why_dangerous": "Maps sections into process address spaces with chosen protections",
        "byovd_usage": "Shared memory or stealth code mapping across processes",
    },
    "ZwUnmapViewOfSection": {
        "category": "MEMORY_ACCESS",
        "risk": 6,
        "why_dangerous": "Unmaps sections, enabling cleanup of mapped payloads",
        "byovd_usage": "Tear down mapped payloads to reduce forensic footprint",
    },
    # Device creation
    "IoCreateDevice": {
        "category": "DEVICE",
        "risk": 5,
        "why_dangerous": "Creates device objects that expose IOCTL surfaces",
        "byovd_usage": "Expose attacker-controlled IOCTLs for userland control",
    },
    "IoCreateSymbolicLink": {
        "category": "DEVICE",
        "risk": 5,
        "why_dangerous": "Links device objects into user-visible namespaces",
        "byovd_usage": "Expose backdoor device interfaces to user mode",
    },
    "IoDeleteDevice": {
        "category": "DEVICE",
        "risk": 4,
        "why_dangerous": "Removes device objects, sometimes used to hide presence",
        "byovd_usage": "Tear down exposed devices after use to reduce artifacts",
    },
    # Security weakening
    "ZwAdjustPrivilegesToken": {
        "category": "PRIVILEGE",
        "risk": 6,
        "why_dangerous": "Enables or disables privileges on tokens",
        "byovd_usage": "Enable SeDebugPrivilege or similar for follow-on attacks",
    },
    "RtlAddVectoredExceptionHandler": {
        "category": "HOOKING",
        "risk": 6,
        "why_dangerous": "Installs vectored exception handlers",
        "byovd_usage": "Implement stealthy hooks or exploit primitives",
    },
    # Driver/service management
    "ZwLoadDriver": {
        "category": "DRIVER_MGMT",
        "risk": 7,
        "why_dangerous": "Loads arbitrary kernel drivers given a registry path",
        "byovd_usage": "Stage additional BYOVD payloads or helpers",
    },
    "ZwUnloadDriver": {
        "category": "DRIVER_MGMT",
        "risk": 6,
        "why_dangerous": "Unloads kernel drivers",
        "byovd_usage": "Remove evidence after using a malicious driver",
    },
    "ZwSetSystemInformation": {
        "category": "SYSTEM_CONTROL",
        "risk": 7,
        "why_dangerous": "Controls system-wide settings including callbacks and mitigations",
        "byovd_usage": "Disable protections or register stealthy callbacks",
    },
    "ZwQuerySystemInformation": {
        "category": "RECON",
        "risk": 5,
        "why_dangerous": "Enumerates processes/modules/handles and mitigation state",
        "byovd_usage": "Target selection and environment awareness before attack",
    },
    # Callback registration
    "PsSetCreateProcessNotifyRoutine": {
        "category": "CALLBACK",
        "risk": 6,
        "why_dangerous": "Registers callbacks on process creation",
        "byovd_usage": "Monitor or block security tools and inject early",
    },
    "PsSetCreateThreadNotifyRoutine": {
        "category": "CALLBACK",
        "risk": 6,
        "why_dangerous": "Registers callbacks on thread creation",
        "byovd_usage": "Watch for defensive threads or spawn-time injection",
    },
    "PsSetLoadImageNotifyRoutine": {
        "category": "CALLBACK",
        "risk": 6,
        "why_dangerous": "Registers callbacks on module load",
        "byovd_usage": "Hook security DLL loads or tamper with AV/EDR drivers",
    },
    # Object callbacks
    "ObRegisterCallbacks": {
        "category": "CALLBACK",
        "risk": 7,
        "why_dangerous": "Registers object callbacks to filter/alter handle operations",
        "byovd_usage": "Block security processes from opening handles or inject on access",
    },
    # Token/privilege
    "PsReferencePrimaryToken": {
        "category": "PRIVILEGE",
        "risk": 6,
        "why_dangerous": "Obtains process primary token for manipulation",
        "byovd_usage": "Steal/duplicate tokens for privilege escalation or hiding",
    },
    "SeAccessCheck": {
        "category": "PRIVILEGE",
        "risk": 5,
        "why_dangerous": "Evaluates security descriptors to gate access",
        "byovd_usage": "Custom access control bypass or tampering with ACL enforcement",
    },
    # Device/control IO
    "ZwDeviceIoControlFile": {
        "category": "IOCTL",
        "risk": 5,
        "why_dangerous": "Sends IOCTLs to arbitrary device objects",
        "byovd_usage": "Drive other vulnerable drivers or chain exploits",
    },
    # Timing/CPU control
    "KeSetSystemGroupAffinityThread": {
        "category": "CPU_CONTROL",
        "risk": 4,
        "why_dangerous": "Pins execution to chosen NUMA group/CPU set",
        "byovd_usage": "Stabilize ROP/Shellcode on specific cores, evade some hooks",
    },
}

# Additional strings that often correlate with dangerous capabilities.
STRING_INDICATORS: List[str] = [
    "PhysicalMemory",
    "\\Device\\PhysicalMemory",
    "SeDebugPrivilege",
    "KdCopyDataBlock",
    "MmMapIoSpace",
    "MmMapIoSpaceEx",
    "MmUnmapIoSpace",
    "MmMapLockedPagesSpecifyCache",
    "MmProbeAndLockPages",
    "ZwProtectVirtualMemory",
    "ZwAllocateVirtualMemory",
    "ZwFreeVirtualMemory",
    "ZwWriteVirtualMemory",
    "ZwReadVirtualMemory",
    "MmCopyVirtualMemory",
    "ZwOpenProcess",
    "PsLookupProcessByProcessId",
    "ZwLoadDriver",
    "ZwUnloadDriver",
    "ZwSetSystemInformation",
    "ZwQuerySystemInformation",
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
    "ObRegisterCallbacks",
]


def get_all_api_names() -> List[str]:
    """Return list of all API names in the database."""
    return list(API_DATABASE.keys())


def get_api_info(api_name: str) -> Tuple[Optional[str], Optional[Dict[str, object]]]:
    """
    Return (category, info dict) for an API name.
    """
    info = API_DATABASE.get(api_name)
    if not info:
        return (None, None)
    return (info.get("category"), info)
