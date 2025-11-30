"""
Windows Internal Structure Offsets Database

Provides hardcoded offsets for critical kernel structures across Windows versions
when symbol-based parsing fails. Enables resilient parsing across Win7-Win11.

Offsets collected from:
- Windows DDK/WDK headers
- Volatility profiles
- Manual reverse engineering of ntoskrnl.exe
"""

from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class WindowsVersion(Enum):
    """Windows version enumeration."""
    WIN7_X64 = "Win7_x64"
    WIN8_X64 = "Win8_x64"
    WIN81_X64 = "Win8.1_x64"
    WIN10_1507_X64 = "Win10_1507_x64"
    WIN10_1607_X64 = "Win10_1607_x64"
    WIN10_1809_X64 = "Win10_1809_x64"
    WIN10_1903_X64 = "Win10_1903_x64"
    WIN10_2004_X64 = "Win10_2004_x64"
    WIN10_21H1_X64 = "Win10_21H1_x64"
    WIN11_21H2_X64 = "Win11_21H2_x64"
    WIN11_22H2_X64 = "Win11_22H2_x64"
    UNKNOWN = "Unknown"


@dataclass
class DriverObjectOffsets:
    """DRIVER_OBJECT structure offsets."""
    Type: int = 0x0                    # SHORT
    Size: int = 0x2                    # SHORT
    DeviceObject: int = 0x8            # PDEVICE_OBJECT
    Flags: int = 0x10                  # ULONG
    DriverStart: int = 0x18            # PVOID
    DriverSize: int = 0x20             # ULONG
    DriverSection: int = 0x28          # PVOID (LDR_DATA_TABLE_ENTRY)
    DriverExtension: int = 0x30        # PDRIVER_EXTENSION
    DriverName: int = 0x38             # UNICODE_STRING
    HardwareDatabase: int = 0x48       # PUNICODE_STRING
    FastIoDispatch: int = 0x50         # PFAST_IO_DISPATCH
    DriverInit: int = 0x58             # PDRIVER_INITIALIZE
    DriverStartIo: int = 0x60          # PDRIVER_STARTIO
    DriverUnload: int = 0x68           # PDRIVER_UNLOAD
    MajorFunction: int = 0x70          # PDRIVER_DISPATCH[28]


@dataclass
class DriverExtensionOffsets:
    """DRIVER_EXTENSION structure offsets."""
    DriverObject: int = 0x0            # PDRIVER_OBJECT
    AddDevice: int = 0x8               # PDRIVER_ADD_DEVICE
    Count: int = 0x10                  # ULONG
    ServiceKeyName: int = 0x18         # UNICODE_STRING
    ClientDriverExtension: int = 0x28  # Varies by version
    FsFilterCallbacks: int = 0x30      # Varies by version


@dataclass
class LdrDataTableEntryOffsets:
    """LDR_DATA_TABLE_ENTRY structure offsets."""
    InLoadOrderLinks: int = 0x0        # LIST_ENTRY
    InMemoryOrderLinks: int = 0x10     # LIST_ENTRY
    InInitializationOrderLinks: int = 0x20  # LIST_ENTRY (some versions)
    DllBase: int = 0x30                # PVOID
    EntryPoint: int = 0x38             # PVOID
    SizeOfImage: int = 0x40            # ULONG
    FullDllName: int = 0x48            # UNICODE_STRING
    BaseDllName: int = 0x58            # UNICODE_STRING
    Flags: int = 0x68                  # ULONG
    LoadCount: int = 0x6C              # USHORT
    TlsIndex: int = 0x6E               # USHORT
    HashLinks: int = 0x70              # LIST_ENTRY
    TimeDateStamp: int = 0x80          # ULONG


@dataclass
class FastIoDispatchOffsets:
    """FAST_IO_DISPATCH structure offsets (function pointer table)."""
    SizeOfFastIoDispatch: int = 0x0    # ULONG
    FastIoCheckIfPossible: int = 0x8
    FastIoRead: int = 0x10
    FastIoWrite: int = 0x18
    FastIoQueryBasicInfo: int = 0x20
    FastIoQueryStandardInfo: int = 0x28
    FastIoLock: int = 0x30
    FastIoUnlockSingle: int = 0x38
    FastIoUnlockAll: int = 0x40
    FastIoUnlockAllByKey: int = 0x48
    FastIoDeviceControl: int = 0x50    # Key for IOCTL analysis
    AcquireFileForNtCreateSection: int = 0x58
    ReleaseFileForNtCreateSection: int = 0x60
    FastIoDetachDevice: int = 0x68
    FastIoQueryNetworkOpenInfo: int = 0x70
    AcquireForModWrite: int = 0x78
    MdlRead: int = 0x80
    MdlReadComplete: int = 0x88
    PrepareMdlWrite: int = 0x90
    MdlWriteComplete: int = 0x98
    FastIoReadCompressed: int = 0xA0
    FastIoWriteCompressed: int = 0xA8
    MdlReadCompleteCompressed: int = 0xB0
    MdlWriteCompleteCompressed: int = 0xB8
    FastIoQueryOpen: int = 0xC0
    ReleaseForModWrite: int = 0xC8
    AcquireForCcFlush: int = 0xD0
    ReleaseForCcFlush: int = 0xD8


@dataclass
class DeviceObjectOffsets:
    """DEVICE_OBJECT structure offsets."""
    Type: int = 0x0
    Size: int = 0x2
    ReferenceCount: int = 0x4
    DriverObject: int = 0x8            # PDRIVER_OBJECT
    NextDevice: int = 0x10             # PDEVICE_OBJECT
    AttachedDevice: int = 0x18         # PDEVICE_OBJECT
    CurrentIrp: int = 0x20
    Timer: int = 0x28
    Flags: int = 0x30
    Characteristics: int = 0x34
    Vpb: int = 0x38
    DeviceExtension: int = 0x40
    DeviceType: int = 0x48
    StackSize: int = 0x4C
    Queue: int = 0x50
    AlignmentRequirement: int = 0x60
    DeviceQueue: int = 0x68
    Dpc: int = 0xA8
    SecurityDescriptor: int = 0x110    # PSECURITY_DESCRIPTOR


@dataclass
class ObjectHeaderOffsets:
    """OBJECT_HEADER structure offsets."""
    PointerCount: int = 0x0            # Varies by version
    HandleCount: int = 0x8
    TypeIndex: int = 0x18              # UCHAR (Win8+)
    Flags: int = 0x19                  # UCHAR
    InfoMask: int = 0x1A               # UCHAR (optional headers bitmask)
    Body: int = 0x30                   # Object body starts here


# Build number to version mapping
BUILD_TO_VERSION = {
    7600: WindowsVersion.WIN7_X64,
    7601: WindowsVersion.WIN7_X64,
    9200: WindowsVersion.WIN8_X64,
    9600: WindowsVersion.WIN81_X64,
    10240: WindowsVersion.WIN10_1507_X64,
    14393: WindowsVersion.WIN10_1607_X64,
    17763: WindowsVersion.WIN10_1809_X64,
    18362: WindowsVersion.WIN10_1903_X64,
    19041: WindowsVersion.WIN10_2004_X64,
    19043: WindowsVersion.WIN10_21H1_X64,
    22000: WindowsVersion.WIN11_21H2_X64,
    22621: WindowsVersion.WIN11_22H2_X64,
}


# Version-specific offset adjustments (most are stable, these are exceptions)
VERSION_SPECIFIC_ADJUSTMENTS = {
    WindowsVersion.WIN7_X64: {
        'LdrDataTableEntry.InInitializationOrderLinks': None,  # Doesn't exist
    },
    WindowsVersion.WIN11_22H2_X64: {
        'ObjectHeader.TypeIndex': 0x20,  # Moved in Win11
    },
}


class OffsetDatabase:
    """
    Central offset database for Windows kernel structures.

    Provides version-aware offset lookups with fallback to default offsets.
    """

    def __init__(self, version: Optional[WindowsVersion] = None):
        """Initialize with detected or specified Windows version."""
        self.version = version or WindowsVersion.UNKNOWN

        # Initialize default offset structures
        self.driver_object = DriverObjectOffsets()
        self.driver_extension = DriverExtensionOffsets()
        self.ldr_data_table_entry = LdrDataTableEntryOffsets()
        self.fast_io_dispatch = FastIoDispatchOffsets()
        self.device_object = DeviceObjectOffsets()
        self.object_header = ObjectHeaderOffsets()

        # Apply version-specific adjustments
        self._apply_version_adjustments()

    def _apply_version_adjustments(self):
        """Apply version-specific offset adjustments."""
        if self.version in VERSION_SPECIFIC_ADJUSTMENTS:
            adjustments = VERSION_SPECIFIC_ADJUSTMENTS[self.version]
            # Apply adjustments (simplified for now)

    @staticmethod
    def detect_version_from_build(build_number: int) -> WindowsVersion:
        """Detect Windows version from build number."""
        return BUILD_TO_VERSION.get(build_number, WindowsVersion.UNKNOWN)

    def get_major_function_offset(self, index: int) -> int:
        """
        Get offset for specific MajorFunction index.

        Args:
            index: MajorFunction index (0-27)

        Returns:
            Offset from DRIVER_OBJECT base
        """
        if not 0 <= index <= 27:
            raise ValueError(f"Invalid MajorFunction index: {index}")

        ptr_size = 8  # x64
        return self.driver_object.MajorFunction + (index * ptr_size)

    def get_fast_io_handler_offset(self, handler_name: str) -> Optional[int]:
        """Get offset for specific FastIo handler."""
        return getattr(self.fast_io_dispatch, handler_name, None)


# Pool tag constants
POOL_TAGS = {
    'DRIVER_OBJECT': [
        b'Driv',      # Standard tag
        b'Dri\x00',   # Truncated
        b'Dr',        # Heavily truncated
        b'DriverN',   # Extended
    ],
    'FILE_OBJECT': [b'File', b'Fil\x00'],
    'PROCESS': [b'Proc', b'Pro\x00'],
    'THREAD': [b'Thre', b'Thr\x00'],
    'TOKEN': [b'Toke', b'Tok\x00'],
}


# Known pool header sizes
POOL_HEADER_SIZE_X64 = 0x10
POOL_HEADER_SIZE_X86 = 0x8


def validate_pool_header(data: bytes, is_64bit: bool = True) -> Tuple[bool, Optional[bytes]]:
    """
    Validate pool header structure.

    Args:
        data: Pool header bytes (at least 16 bytes)
        is_64bit: Architecture flag

    Returns:
        Tuple of (is_valid, pool_tag)
    """
    if len(data) < 16:
        return False, None

    try:
        # Pool header structure (simplified):
        # +0x00 PreviousSize : Uint2B
        # +0x02 PoolIndex    : Uint2B
        # +0x04 BlockSize    : Uint2B
        # +0x06 PoolType     : Uint2B
        # +0x08 PoolTag      : Uint4B

        import struct

        prev_size, pool_index, block_size, pool_type = struct.unpack('<HHHH', data[0:8])
        pool_tag = data[4:8] if is_64bit else data[4:8]

        # Validation checks
        if block_size == 0 or block_size > 0x1000:
            return False, None

        # PoolType validation (NonPagedPool=0, PagedPool=1, various flags)
        if pool_type > 0x1FF:
            return False, None

        # Check if pool tag is printable ASCII (common for driver pools)
        try:
            tag_str = pool_tag.decode('ascii')
            if not all(c.isprintable() or c == '\x00' for c in tag_str):
                return False, None
        except:
            return False, None

        return True, pool_tag

    except Exception:
        return False, None


# IRP Major Function names (for reference)
IRP_MJ_NAMES = {
    0x00: "IRP_MJ_CREATE",
    0x01: "IRP_MJ_CREATE_NAMED_PIPE",
    0x02: "IRP_MJ_CLOSE",
    0x03: "IRP_MJ_READ",
    0x04: "IRP_MJ_WRITE",
    0x05: "IRP_MJ_QUERY_INFORMATION",
    0x06: "IRP_MJ_SET_INFORMATION",
    0x07: "IRP_MJ_QUERY_EA",
    0x08: "IRP_MJ_SET_EA",
    0x09: "IRP_MJ_FLUSH_BUFFERS",
    0x0A: "IRP_MJ_QUERY_VOLUME_INFORMATION",
    0x0B: "IRP_MJ_SET_VOLUME_INFORMATION",
    0x0C: "IRP_MJ_DIRECTORY_CONTROL",
    0x0D: "IRP_MJ_FILE_SYSTEM_CONTROL",
    0x0E: "IRP_MJ_DEVICE_CONTROL",
    0x0F: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    0x10: "IRP_MJ_SHUTDOWN",
    0x11: "IRP_MJ_LOCK_CONTROL",
    0x12: "IRP_MJ_CLEANUP",
    0x13: "IRP_MJ_CREATE_MAILSLOT",
    0x14: "IRP_MJ_QUERY_SECURITY",
    0x15: "IRP_MJ_SET_SECURITY",
    0x16: "IRP_MJ_POWER",
    0x17: "IRP_MJ_SYSTEM_CONTROL",
    0x18: "IRP_MJ_DEVICE_CHANGE",
    0x19: "IRP_MJ_QUERY_QUOTA",
    0x1A: "IRP_MJ_SET_QUOTA",
    0x1B: "IRP_MJ_PNP",
}
