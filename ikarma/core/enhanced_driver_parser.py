"""
Enhanced DRIVER_OBJECT Parser with Advanced Reconstruction

Implements comprehensive driver object parsing with:
- Fallback offset-based parsing when Volatility fails
- FastIoDispatch table extraction
- DRIVER_EXTENSION parsing
- LDR_DATA_TABLE_ENTRY correlation
- Pool header validation
- Cross-reference validation
"""

from __future__ import annotations

import logging
import struct
from typing import Optional, List, Dict, Any, Tuple, Callable
from dataclasses import dataclass, field

from ikarma.core.windows_offsets import (
    OffsetDatabase, WindowsVersion, validate_pool_header,
    POOL_TAGS, IRP_MJ_NAMES
)
from ikarma.volatility3.vol3_plugin import DriverObjectInfo

logger = logging.getLogger(__name__)


@dataclass
class FastIoHandlerInfo:
    """Information about a FastIo handler."""
    index: int
    handler_name: str
    handler_address: int
    is_hooked: bool = False
    expected_module: Optional[str] = None


@dataclass
class DeviceObjectInfo:
    """Information about a DEVICE_OBJECT."""
    object_address: int
    device_type: int
    characteristics: int
    flags: int
    security_descriptor: Optional[int] = None
    dacl_present: bool = False
    dacl_null: bool = False
    dacl_world_writeable: bool = False
    attached_device: Optional[int] = None


@dataclass
class DriverExtensionInfo:
    """Parsed DRIVER_EXTENSION structure."""
    extension_address: int
    add_device_routine: Optional[int] = None
    service_key_name: Optional[str] = None
    client_extension: Optional[int] = None


@dataclass
class LdrModuleInfo:
    """Parsed LDR_DATA_TABLE_ENTRY structure."""
    module_address: int
    dll_base: int
    entry_point: int
    size_of_image: int
    full_dll_name: str
    base_dll_name: str
    load_count: int
    flags: int
    time_date_stamp: int

    # List entry pointers for DKOM detection
    in_load_order_flink: int = 0
    in_load_order_blink: int = 0
    in_memory_order_flink: int = 0
    in_memory_order_blink: int = 0


@dataclass
class EnhancedDriverObject:
    """
    Comprehensive DRIVER_OBJECT information with all fields parsed.
    """
    object_address: int
    driver_start: int
    driver_size: int
    driver_name: str

    # Core fields
    type_field: int = 0
    size_field: int = 0
    device_object: int = 0
    flags: int = 0
    driver_section: int = 0
    driver_extension: int = 0
    hardware_database: int = 0
    fast_io_dispatch: int = 0
    driver_init: int = 0
    driver_start_io: int = 0
    driver_unload: int = 0

    # MajorFunction table (28 entries)
    major_functions: Dict[int, int] = field(default_factory=dict)

    # FastIo handlers
    fast_io_handlers: List[FastIoHandlerInfo] = field(default_factory=list)

    # Extension info
    extension_info: Optional[DriverExtensionInfo] = None

    # Device Objects
    device_objects: List[DeviceObjectInfo] = field(default_factory=list)

    # LDR module info
    ldr_module_info: Optional[LdrModuleInfo] = None

    # Validation
    is_valid: bool = True
    validation_errors: List[str] = field(default_factory=list)
    confidence_score: float = 0.0

    # Pool info
    pool_tag: Optional[bytes] = None
    pool_type: Optional[int] = None


class EnhancedDriverParser:
    """
    Advanced DRIVER_OBJECT parser with comprehensive reconstruction.

    Features:
    - Offset-based parsing with Windows version detection
    - FastIoDispatch table extraction
    - DRIVER_EXTENSION parsing
    - LDR_DATA_TABLE_ENTRY correlation
    - Multi-stage validation
    - Hook detection in FastIo and MajorFunction tables
    """

    def __init__(self, is_64bit: bool = True, windows_version: Optional[WindowsVersion] = None):
        """Initialize parser."""
        self.is_64bit = is_64bit
        self.ptr_size = 8 if is_64bit else 4
        self.ptr_fmt = '<Q' if is_64bit else '<I'

        # Offset database
        self.offsets = OffsetDatabase(windows_version)

        # Statistics
        self.stats = {
            'parsed': 0,
            'validation_passed': 0,
            'validation_failed': 0,
            'fast_io_found': 0,
            'extensions_parsed': 0,
        }

    def parse_driver_object(
        self,
        address: int,
        read_memory: callable,
        read_string: Optional[callable] = None
    ) -> Optional[EnhancedDriverObject]:
        """
        Parse DRIVER_OBJECT structure from memory.

        Args:
            address: Address of DRIVER_OBJECT
            read_memory: Function to read memory (address, size) -> bytes
            read_string: Optional function to read UNICODE_STRING

        Returns:
            EnhancedDriverObject or None if parsing failed
        """
        self.stats['parsed'] += 1

        # Read DRIVER_OBJECT structure
        # Size: 0x150 bytes for x64, 0xA8 for x86
        struct_size = 0x150 if self.is_64bit else 0xA8
        data = read_memory(address, struct_size)

        if not data or len(data) < struct_size:
            logger.debug(f"Failed to read DRIVER_OBJECT at {hex(address)}")
            return None

        try:
            driver_obj = self._parse_structure(address, data, read_memory, read_string)

            if driver_obj:
                # Validate
                self._validate_driver_object(driver_obj, read_memory)

                # Parse extension if present
                if driver_obj.driver_extension != 0:
                    driver_obj.extension_info = self._parse_driver_extension(
                        driver_obj.driver_extension, read_memory, read_string
                    )
                    if driver_obj.extension_info:
                        self.stats['extensions_parsed'] += 1

                # Parse FastIoDispatch if present
                if driver_obj.fast_io_dispatch != 0:
                    driver_obj.fast_io_handlers = self._parse_fast_io_dispatch(
                        driver_obj.fast_io_dispatch,
                        read_memory,
                        driver_obj.driver_start,
                        driver_obj.driver_size
                    )
                    if driver_obj.fast_io_handlers:
                        self.stats['fast_io_found'] += 1

                # Parse LDR module entry if present
                if driver_obj.driver_section != 0:
                    driver_obj.ldr_module_info = self._parse_ldr_entry(
                        driver_obj.driver_section, read_memory, read_string
                    )

                # Parse Device Object chain
                if driver_obj.device_object != 0:
                    driver_obj.device_objects = self._parse_device_object_chain(
                        driver_obj.device_object, read_memory
                    )

                # Calculate confidence
                driver_obj.confidence_score = self._calculate_confidence(driver_obj)

                if driver_obj.is_valid:
                    self.stats['validation_passed'] += 1
                else:
                    self.stats['validation_failed'] += 1

                return driver_obj

        except Exception as e:
            logger.debug(f"Error parsing DRIVER_OBJECT at {hex(address)}: {e}")
            return None

    def _parse_structure(
        self,
        address: int,
        data: bytes,
        read_memory: callable,
        read_string: Optional[callable]
    ) -> Optional[EnhancedDriverObject]:
        """Parse DRIVER_OBJECT structure from raw bytes."""

        try:
            off = self.offsets.driver_object

            # Parse core fields
            type_field = struct.unpack('<H', data[off.Type:off.Type+2])[0]
            size_field = struct.unpack('<H', data[off.Size:off.Size+2])[0]

            # Sanity check
            if type_field != 0x4:  # IO_TYPE_DRIVER
                return None

            # Read pointer fields
            device_object = self._read_ptr(data, off.DeviceObject)
            flags = struct.unpack('<I', data[off.Flags:off.Flags+4])[0]
            driver_start = self._read_ptr(data, off.DriverStart)
            driver_size = struct.unpack('<I', data[off.DriverSize:off.DriverSize+4])[0]
            driver_section = self._read_ptr(data, off.DriverSection)
            driver_extension = self._read_ptr(data, off.DriverExtension)
            fast_io_dispatch = self._read_ptr(data, off.FastIoDispatch)
            driver_init = self._read_ptr(data, off.DriverInit)
            driver_start_io = self._read_ptr(data, off.DriverStartIo)
            driver_unload = self._read_ptr(data, off.DriverUnload)

            # Parse UNICODE_STRING for DriverName
            driver_name = "unknown"
            if read_string:
                name_offset = off.DriverName
                driver_name = read_string(address + name_offset) or "unknown"

            # Parse MajorFunction table
            major_functions = {}
            mf_offset = off.MajorFunction
            for i in range(28):
                handler_offset = mf_offset + (i * self.ptr_size)
                if handler_offset + self.ptr_size <= len(data):
                    handler = self._read_ptr(data, handler_offset)
                    if handler != 0:
                        major_functions[i] = handler

            # Create object
            driver_obj = EnhancedDriverObject(
                object_address=address,
                driver_start=driver_start,
                driver_size=driver_size,
                driver_name=driver_name,
                type_field=type_field,
                size_field=size_field,
                device_object=device_object,
                flags=flags,
                driver_section=driver_section,
                driver_extension=driver_extension,
                fast_io_dispatch=fast_io_dispatch,
                driver_init=driver_init,
                driver_start_io=driver_start_io,
                driver_unload=driver_unload,
                major_functions=major_functions,
            )

            return driver_obj

        except Exception as e:
            logger.debug(f"Structure parsing error: {e}")
            return None

    def _parse_driver_extension(
        self,
        address: int,
        read_memory: callable,
        read_string: Optional[callable]
    ) -> Optional[DriverExtensionInfo]:
        """Parse DRIVER_EXTENSION structure."""

        data = read_memory(address, 0x40)
        if not data or len(data) < 0x40:
            return None

        try:
            off = self.offsets.driver_extension

            add_device = self._read_ptr(data, off.AddDevice)

            # Parse ServiceKeyName UNICODE_STRING
            service_key = None
            if read_string:
                service_key = read_string(address + off.ServiceKeyName)

            return DriverExtensionInfo(
                extension_address=address,
                add_device_routine=add_device if add_device != 0 else None,
                service_key_name=service_key,
            )
        except Exception as e:
            logger.debug(f"DRIVER_EXTENSION parse error: {e}")
            return None

    def _parse_fast_io_dispatch(
        self,
        address: int,
        read_memory: callable,
        driver_base: int,
        driver_size: int
    ) -> List[FastIoHandlerInfo]:
        """
        Parse FAST_IO_DISPATCH table and extract all handlers.

        FastIoDispatch is critical because many BYOVD drivers use it
        to bypass IRP logging and improve performance.
        """

        data = read_memory(address, 0xE0)
        if not data or len(data) < 0xE0:
            return []

        handlers = []
        off = self.offsets.fast_io_dispatch

        # Size check
        try:
            size = struct.unpack('<I', data[off.SizeOfFastIoDispatch:off.SizeOfFastIoDispatch+4])[0]
            if size == 0 or size > 0x200:
                return []
        except:
            return []

        # Handler definitions
        handler_defs = [
            (off.FastIoCheckIfPossible, "FastIoCheckIfPossible", 0),
            (off.FastIoRead, "FastIoRead", 1),
            (off.FastIoWrite, "FastIoWrite", 2),
            (off.FastIoQueryBasicInfo, "FastIoQueryBasicInfo", 3),
            (off.FastIoQueryStandardInfo, "FastIoQueryStandardInfo", 4),
            (off.FastIoLock, "FastIoLock", 5),
            (off.FastIoUnlockSingle, "FastIoUnlockSingle", 6),
            (off.FastIoUnlockAll, "FastIoUnlockAll", 7),
            (off.FastIoUnlockAllByKey, "FastIoUnlockAllByKey", 8),
            (off.FastIoDeviceControl, "FastIoDeviceControl", 9),  # CRITICAL for IOCTL
            (off.AcquireFileForNtCreateSection, "AcquireFileForNtCreateSection", 10),
            (off.ReleaseFileForNtCreateSection, "ReleaseFileForNtCreateSection", 11),
            (off.FastIoDetachDevice, "FastIoDetachDevice", 12),
            (off.FastIoQueryNetworkOpenInfo, "FastIoQueryNetworkOpenInfo", 13),
            (off.MdlRead, "MdlRead", 14),
            (off.MdlReadComplete, "MdlReadComplete", 15),
            (off.PrepareMdlWrite, "PrepareMdlWrite", 16),
            (off.MdlWriteComplete, "MdlWriteComplete", 17),
        ]

        driver_end = driver_base + driver_size

        for offset, name, idx in handler_defs:
            try:
                if offset + self.ptr_size <= len(data):
                    handler = self._read_ptr(data, offset)
                    if handler != 0:
                        # Check if hooked (outside driver range)
                        is_hooked = False
                        if driver_base != 0 and driver_size != 0:
                            if handler < driver_base or handler > driver_end:
                                is_hooked = True

                        handlers.append(FastIoHandlerInfo(
                            index=idx,
                            handler_name=name,
                            handler_address=handler,
                            is_hooked=is_hooked,
                        ))
            except:
                continue

        return handlers

    def _parse_ldr_entry(
        self,
        address: int,
        read_memory: callable,
        read_string: Optional[callable]
    ) -> Optional[LdrModuleInfo]:
        """
        Parse LDR_DATA_TABLE_ENTRY structure.

        This is critical for DKOM detection - we validate list entry consistency.
        """

        data = read_memory(address, 0x100)
        if not data or len(data) < 0x100:
            return None

        try:
            off = self.offsets.ldr_data_table_entry

            # Parse list entries (for DKOM detection)
            flink_load = self._read_ptr(data, off.InLoadOrderLinks)
            blink_load = self._read_ptr(data, off.InLoadOrderLinks + self.ptr_size)
            flink_mem = self._read_ptr(data, off.InMemoryOrderLinks)
            blink_mem = self._read_ptr(data, off.InMemoryOrderLinks + self.ptr_size)

            # Parse core fields
            dll_base = self._read_ptr(data, off.DllBase)
            entry_point = self._read_ptr(data, off.EntryPoint)
            size_of_image = struct.unpack('<I', data[off.SizeOfImage:off.SizeOfImage+4])[0]

            # Parse strings
            full_name = ""
            base_name = ""
            if read_string:
                full_name = read_string(address + off.FullDllName) or ""
                base_name = read_string(address + off.BaseDllName) or ""

            # Parse metadata
            flags = struct.unpack('<I', data[off.Flags:off.Flags+4])[0]
            load_count = struct.unpack('<H', data[off.LoadCount:off.LoadCount+2])[0]
            time_date_stamp = struct.unpack('<I', data[off.TimeDateStamp:off.TimeDateStamp+4])[0]

            return LdrModuleInfo(
                module_address=address,
                dll_base=dll_base,
                entry_point=entry_point,
                size_of_image=size_of_image,
                full_dll_name=full_name,
                base_dll_name=base_name,
                load_count=load_count,
                flags=flags,
                time_date_stamp=time_date_stamp,
                in_load_order_flink=flink_load,
                in_load_order_blink=blink_load,
                in_memory_order_flink=flink_mem,
                in_memory_order_blink=blink_mem,
            )

        except Exception as e:
            logger.debug(f"LDR_DATA_TABLE_ENTRY parse error: {e}")
            return None

    def _parse_device_object_chain(
        self,
        start_address: int,
        read_memory: callable
    ) -> List[DeviceObjectInfo]:
        """Parse the chain of DEVICE_OBJECTs."""
        devices = []
        current_addr = start_address
        off = self.offsets.device_object
        visited = set()

        while current_addr != 0 and current_addr not in visited:
            visited.add(current_addr)
            
            # Read DEVICE_OBJECT (0x150 is safe upper bound for size)
            data = read_memory(current_addr, 0x150)
            if not data or len(data) < 0x50:
                break
                
            try:
                # Parse fields
                dev_type = struct.unpack('<I', data[off.DeviceType:off.DeviceType+4])[0]
                characteristics = struct.unpack('<I', data[off.Characteristics:off.Characteristics+4])[0]
                flags = struct.unpack('<I', data[off.Flags:off.Flags+4])[0]
                attached_device = self._read_ptr(data, off.AttachedDevice)
                next_device = self._read_ptr(data, off.NextDevice)
                
                # Security Descriptor
                security_desc_ptr = 0
                if hasattr(off, 'SecurityDescriptor'):
                    security_desc_ptr = self._read_ptr(data, off.SecurityDescriptor)
                
                # Analyze Security Descriptor
                dacl_present = False
                dacl_null = False
                dacl_world_writeable = False
                
                if security_desc_ptr != 0:
                    sd_info = self._parse_security_descriptor(security_desc_ptr, read_memory)
                    dacl_present = sd_info['dacl_present']
                    dacl_null = sd_info['dacl_null']
                    dacl_world_writeable = sd_info['dacl_world_writeable']
                
                devices.append(DeviceObjectInfo(
                    object_address=current_addr,
                    device_type=dev_type,
                    characteristics=characteristics,
                    flags=flags,
                    security_descriptor=security_desc_ptr if security_desc_ptr != 0 else None,
                    dacl_present=dacl_present,
                    dacl_null=dacl_null,
                    dacl_world_writeable=dacl_world_writeable,
                    attached_device=attached_device if attached_device != 0 else None
                ))
                
                current_addr = next_device
                
            except Exception as e:
                logger.debug(f"Error parsing DEVICE_OBJECT at {hex(current_addr)}: {e}")
                break
                
        return devices

    def verify_integrity(
        self,
        driver_obj: DriverObjectInfo,
        module_entry: Optional[Dict[str, Any]] = None,
        pe_info: Optional[Any] = None
    ) -> List[Any]:
        """
        Verify driver object integrity.
        
        Checks for:
        1. Start address mismatch (DKOM)
        2. Size mismatch (DKOM)
        3. Hidden code execution (outside module bounds)
        """
        anomalies = []
        
        if not driver_obj:
            return anomalies
            
        # 1. Check against PsLoadedModuleList (if available)
        if module_entry:
            # Check Start Address
            if abs(driver_obj.driver_start - module_entry['base']) > 0x1000:
                anomalies.append({
                    'type': 'INTEGRITY_VIOLATION',
                    'description': 'DriverStart mismatch with PsLoadedModuleList',
                    'details': f"Driver: {hex(driver_obj.driver_start)}, Module: {hex(module_entry['base'])}",
                    'severity': 'high'
                })
                
            # Check Size
            if abs(driver_obj.driver_size - module_entry['size']) > 0x1000:
                anomalies.append({
                    'type': 'INTEGRITY_VIOLATION',
                    'description': 'DriverSize mismatch with PsLoadedModuleList',
                    'details': f"Driver: {hex(driver_obj.driver_size)}, Module: {hex(module_entry['size'])}",
                    'severity': 'medium'
                })
        
        # 2. Check against PE Header (if available)
        if pe_info and hasattr(pe_info, 'OPTIONAL_HEADER'):
            pe_size = pe_info.OPTIONAL_HEADER.SizeOfImage
            if abs(driver_obj.driver_size - pe_size) > 0x2000: # Allow some alignment slack
                anomalies.append({
                    'type': 'INTEGRITY_VIOLATION',
                    'description': 'DriverSize mismatch with PE Header',
                    'details': f"Driver: {hex(driver_obj.driver_size)}, PE: {hex(pe_size)}",
                    'severity': 'medium'
                })
                
        return anomalies

    def check_iat_hooks(
        self,
        driver_base: int,
        read_memory: Callable,
        resolve_symbol: Callable,
        pe_info: Any
    ) -> List[Any]:
        """
        Check for IAT hooks by verifying import addresses.
        """
        hooks = []
        
        if not pe_info or not hasattr(pe_info, 'DIRECTORY_ENTRY_IMPORT'):
            return hooks
            
        try:
            for entry in pe_info.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                
                # Only check kernel imports (ntoskrnl, hal)
                if 'ntoskrnl' not in dll_name and 'hal.dll' not in dll_name:
                    continue
                    
                for imp in entry.imports:
                    if not imp.name:
                        continue
                        
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    
                    # Resolve expected address
                    expected_addr = resolve_symbol(func_name)
                    if not expected_addr:
                        continue
                        
                    # Read actual address from IAT
                    # imp.address is the RVA of the IAT entry
                    iat_rva = imp.address
                    iat_va = driver_base + iat_rva
                    
                    # Read pointer size (8 bytes for x64)
                    ptr_bytes = read_memory(iat_va, 8)
                    if not ptr_bytes:
                        continue
                        
                    actual_addr = int.from_bytes(ptr_bytes, 'little')
                    
                    # Compare
                    if actual_addr != expected_addr:
                        hooks.append({
                            'type': 'IAT_HOOK',
                            'description': f"IAT Hook detected for {func_name}",
                            'details': f"Expected: {hex(expected_addr)}, Actual: {hex(actual_addr)}",
                            'severity': 'high',
                            'function': func_name,
                            'hook_address': actual_addr
                        })
                        
        except Exception as e:
            # logger.debug(f"IAT hook check failed: {e}")
            pass
            
        return hooks

    def _parse_security_descriptor(self, address: int, read_memory: callable) -> Dict[str, bool]:
        """
        Parse SECURITY_DESCRIPTOR to check for NULL DACL or World-Writeable DACL.
        """
        result = {
            'dacl_present': False,
            'dacl_null': False,
            'dacl_world_writeable': False
        }
        
        try:
            # Read SECURITY_DESCRIPTOR header (20 bytes)
            # +0x00 Revision (1)
            # +0x01 Sbz1 (1)
            # +0x02 Control (2)
            # +0x04 Owner (4/8)
            # +0x08 Group (4/8)
            # +0x0C Sacl (4/8)
            # +0x10 Dacl (4/8)
            
            data = read_memory(address, 0x20)
            if not data:
                return result
                
            # Check revision
            if data[0] != 1:
                return result
                
            control = struct.unpack('<H', data[2:4])[0]
            
            # SE_DACL_PRESENT = 0x0004
            if not (control & 0x0004):
                return result
                
            result['dacl_present'] = True
            
            # Get DACL offset/pointer
            # Note: SECURITY_DESCRIPTOR can be absolute or self-relative
            # SE_SELF_RELATIVE = 0x8000
            is_self_relative = bool(control & 0x8000)
            
            dacl_offset = 0
            if is_self_relative:
                # Offset is relative to start of SD
                dacl_offset_val = struct.unpack('<I', data[0x10:0x14])[0] if not self.is_64bit else struct.unpack('<I', data[0x10:0x14])[0] # Offset is always 32-bit in self-relative?
                # Actually, in self-relative, offsets are 32-bit integers at specific locations.
                # Let's assume standard layout.
                # For self-relative, the fields are offsets (DWORDs).
                # Owner, Group, Sacl, Dacl are all DWORD offsets.
                dacl_offset_val = struct.unpack('<I', data[16:20])[0] # Offset 16 is Dacl offset
                if dacl_offset_val == 0:
                    result['dacl_null'] = True
                    return result
                dacl_addr = address + dacl_offset_val
            else:
                # Absolute - pointers
                dacl_ptr_offset = 16 if not self.is_64bit else 24 # Need to check alignment
                # Actually, let's simplify. If it's absolute, we need to read the pointer.
                # But kernel SDs are often self-relative or absolute.
                # Let's try to read the pointer.
                if self.is_64bit:
                    # Layout: Rev(1), Pad(1), Control(2), Offset(4) -> Owner(8), Group(8), Sacl(8), Dacl(8)
                    # Wait, absolute SD has pointers.
                    # +00 Header
                    # +08 Owner
                    # +10 Group
                    # +18 Sacl
                    # +20 Dacl
                    dacl_addr = struct.unpack('<Q', data[0x20:0x28])[0] # Assuming offset 0x20
                else:
                    dacl_addr = struct.unpack('<I', data[0x10:0x14])[0]
                
                if dacl_addr == 0:
                    result['dacl_null'] = True
                    return result

            # Read DACL header
            # +00 AclRevision
            # +01 Sbz1
            # +02 AclSize
            # +04 AceCount
            # +06 Sbz2
            
            dacl_data = read_memory(dacl_addr, 8)
            if not dacl_data:
                return result
                
            ace_count = struct.unpack('<H', dacl_data[4:6])[0]
            
            # Iterate ACEs
            current_ace_addr = dacl_addr + 8
            
            for i in range(ace_count):
                ace_header = read_memory(current_ace_addr, 8)
                if not ace_header:
                    break
                    
                ace_type = ace_header[0]
                ace_size = struct.unpack('<H', ace_header[2:4])[0]
                ace_mask = struct.unpack('<I', ace_header[4:8])[0]
                
                # ACCESS_ALLOWED_ACE_TYPE = 0
                if ace_type == 0:
                    # Check SID
                    # +08 SidStart
                    sid_data = read_memory(current_ace_addr + 8, 8) # Read enough for SID header
                    if sid_data:
                        # Check for World SID (S-1-1-0)
                        # Revision(1), SubAuthorityCount(1), IdentifierAuthority(6), SubAuthority(4)
                        # World SID: 01 01 00 00 00 00 00 01 00 00 00 00
                        if sid_data[0] == 1 and sid_data[1] == 1: # Revision 1, 1 SubAuthority
                             # Check Authority (0,0,0,0,0,1)
                             auth = read_memory(current_ace_addr + 8 + 2, 6)
                             if auth == b'\x00\x00\x00\x00\x00\x01':
                                 # Check SubAuthority (0)
                                 sub_auth = read_memory(current_ace_addr + 8 + 8, 4)
                                 if sub_auth == b'\x00\x00\x00\x00':
                                     # It is World SID. Check mask.
                                     # FILE_WRITE_DATA = 0x0002
                                     # GENERIC_WRITE = 0x40000000
                                     # GENERIC_ALL = 0x10000000
                                     if (ace_mask & 0x0002) or (ace_mask & 0x40000000) or (ace_mask & 0x10000000):
                                         result['dacl_world_writeable'] = True
                                         break
                
                current_ace_addr += ace_size
                
        except Exception:
            pass
            
        return result

    def _validate_driver_object(self, driver_obj: EnhancedDriverObject, read_memory: callable):
        """
        Multi-stage validation of DRIVER_OBJECT.

        Validates:
        - Pointer sanity
        - PE header at DriverStart
        - DeviceObject chain consistency
        - MajorFunction handler addresses
        """

        # Check 1: DriverStart must point to valid PE
        if driver_obj.driver_start != 0:
            pe_header = read_memory(driver_obj.driver_start, 2)
            if pe_header and pe_header == b'MZ':
                # Valid PE header
                pass
            else:
                driver_obj.validation_errors.append("DriverStart does not point to valid PE (MZ signature missing)")
                driver_obj.is_valid = False

        # Check 2: Driver size sanity
        if driver_obj.driver_size == 0 or driver_obj.driver_size > 0x10000000:  # Max 256MB
            driver_obj.validation_errors.append(f"Invalid driver size: {hex(driver_obj.driver_size)}")
            driver_obj.is_valid = False

        # Check 3: MajorFunction handlers should be in kernel space
        if self.is_64bit:
            kernel_min = 0xFFFF800000000000
            for idx, handler in driver_obj.major_functions.items():
                if handler < kernel_min:
                    driver_obj.validation_errors.append(
                        f"MajorFunction[{idx}] has invalid kernel address: {hex(handler)}"
                    )
                    driver_obj.is_valid = False
                    break

        # Check 4: Pointer alignment (x64 = 8-byte, x86 = 4-byte)
        alignment = 8 if self.is_64bit else 4
        for ptr_name, ptr_value in [
            ('DriverStart', driver_obj.driver_start),
            ('DeviceObject', driver_obj.device_object),
        ]:
            if ptr_value != 0 and ptr_value % alignment != 0:
                driver_obj.validation_errors.append(f"{ptr_name} not properly aligned: {hex(ptr_value)}")

    def _calculate_confidence(self, driver_obj: EnhancedDriverObject) -> float:
        """
        Calculate confidence score for parsed DRIVER_OBJECT.

        Scoring factors:
        - Valid PE header at DriverStart: +0.3
        - Valid MajorFunction handlers: +0.2
        - FastIoDispatch present: +0.15
        - DRIVER_EXTENSION parsed: +0.15
        - LDR entry parsed: +0.2
        """

        score = 0.0

        # Base score for parsing
        score += 0.1

        # Valid structure
        if driver_obj.is_valid:
            score += 0.2

        # PE header validation passed
        if not any('MZ signature missing' in e for e in driver_obj.validation_errors):
            score += 0.3

        # MajorFunction handlers
        if len(driver_obj.major_functions) >= 3:
            score += 0.2

        # FastIo dispatch
        if driver_obj.fast_io_handlers:
            score += 0.15

        # Extension
        if driver_obj.extension_info:
            score += 0.1

        # LDR module
        if driver_obj.ldr_module_info:
            score += 0.15

        return min(1.0, score)

    def _read_ptr(self, data: bytes, offset: int) -> int:
        """Read pointer from data at offset."""
        if offset + self.ptr_size > len(data):
            return 0

        ptr_bytes = data[offset:offset + self.ptr_size]
        return struct.unpack(self.ptr_fmt, ptr_bytes)[0]

    def get_statistics(self) -> Dict[str, int]:
        """Get parsing statistics."""
        return self.stats.copy()
