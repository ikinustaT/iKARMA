"""
iKARMA Memory Parser - Production Release

Provides memory parsing capabilities using Volatility3 framework,
including DRIVER_OBJECT enumeration, MajorFunction table resolution,
and raw memory extraction for capability analysis.

Architecture:
1. Primary: Volatility3 for structured analysis (DRIVER_OBJECT, MajorFunction)
2. Fallback: Direct PE carving when Volatility3 fails
3. Hybrid: Cross-view validation using both methods
"""

import logging
import struct
import os
import hashlib
from typing import Optional, List, Dict, Any, Tuple, Set
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

# PE signature constants
DOS_SIGNATURE = b'MZ'
PE_SIGNATURE = b'PE\x00\x00'
PE_POINTER_OFFSET = 0x3C

# Windows constants
IRP_MJ_MAXIMUM_FUNCTION = 28
IRP_MJ_DEVICE_CONTROL = 14


# =============================================================================
# IMPORTS - Volatility3, Capstone, pefile
# =============================================================================

from ikarma.volatility3.vol3_plugin import (
    HAS_VOLATILITY,
    VolatilityBridge,
    DriverObjectInfo,
    is_volatility_available,
    get_volatility_version,
)

HAS_CAPSTONE = False
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    HAS_CAPSTONE = True
except ImportError:
    pass

HAS_PEFILE = False
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    pass

from ikarma.core.driver import (
    DriverInfo, IOCTLHandler, MajorFunctionInfo, SignatureInfo,
    EnumerationSource,
)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class MemoryRegion:
    """Represents a memory region extracted from the dump."""
    virtual_address: int
    physical_address: Optional[int]
    size: int
    data: bytes
    is_valid: bool = True
    protection: str = "unknown"


# =============================================================================
# MEMORY PARSER CLASS
# =============================================================================

class MemoryParser:
    """
    Core memory parsing engine for iKARMA.
    
    Integrates with Volatility3 for structured memory analysis while
    providing direct memory access for fallback and validation.
    
    Key Features:
    - Volatility3 integration for DRIVER_OBJECT enumeration
    - MajorFunction table extraction (source of truth)
    - PE carving fallback for reliability
    - Cross-view validation support
    """
    
    def __init__(self, memory_path: str, profile: Optional[str] = None):
        """Initialize the memory parser."""
        self.memory_path = Path(memory_path).resolve()
        self.profile = profile
        
        # Volatility3 bridge
        self._vol_bridge: Optional[VolatilityBridge] = None
        self._volatility_working = False
        
        # State
        self._is_initialized = False
        self._fallback_mode = False
        self._arch = "x64"
        self._pointer_size = 8
        
        # Disassembler
        self._disassembler = None
        if HAS_CAPSTONE:
            self._disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
            self._disassembler.detail = True
        
        # Cache
        self._memory_cache: Dict[Tuple[int, int], bytes] = {}
        self._file_handle = None
        self._file_size = 0
        
        logger.info(f"MemoryParser initialized for: {self.memory_path}")
    
    def initialize(self) -> bool:
        """
        Initialize memory parsing.
        
        Tries Volatility3 first for structured analysis,
        falls back to direct PE carving if needed.
        
        Returns:
            True if initialization successful
        """
        if not self.memory_path.exists():
            logger.error(f"Memory file not found: {self.memory_path}")
            return False
        
        # Get file size
        self._file_size = self.memory_path.stat().st_size
        
        # Try Volatility3 initialization
        if HAS_VOLATILITY:
            try:
                self._vol_bridge = VolatilityBridge(str(self.memory_path))
                if self._vol_bridge.initialize():
                    self._volatility_working = True
                    self._arch = "x64" if self._vol_bridge.is_64bit else "x86"
                    self._pointer_size = 8 if self._vol_bridge.is_64bit else 4
                    logger.info("Volatility3 initialized successfully")
                else:
                    error = self._vol_bridge.get_error()
                    logger.warning(f"Volatility3 initialization failed: {error}")
            except Exception as e:
                logger.warning(f"Volatility3 exception: {e}")
        else:
            logger.info("Volatility3 not available - using fallback mode")
        
        # Update disassembler mode
        if HAS_CAPSTONE and self._arch == "x86":
            self._disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
            self._disassembler.detail = True
        
        self._is_initialized = True
        self._fallback_mode = not self._volatility_working
        
        return True
    
    @property
    def volatility_available(self) -> bool:
        """Check if Volatility3 is working."""
        return self._volatility_working
    
    @property
    def is_fallback_mode(self) -> bool:
        """Check if using fallback mode."""
        return self._fallback_mode
    
    # =========================================================================
    # MEMORY ACCESS
    # =========================================================================
    
    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """
        Read memory from the dump.
        
        Tries Volatility3 layer first, falls back to direct read.
        """
        cache_key = (address, size)
        if cache_key in self._memory_cache:
            return self._memory_cache[cache_key]
        
        data = None
        
        # Try Volatility3 first
        if self._volatility_working and self._vol_bridge:
            data = self._vol_bridge.read_memory(address, size)
        
        # Fall back to direct read
        if data is None:
            data = self._read_direct(address, size)
        
        if data:
            # Limit cache size
            if len(self._memory_cache) > 1000:
                self._memory_cache.clear()
            self._memory_cache[cache_key] = data
        
        return data
    
    def _read_direct(self, address: int, size: int) -> Optional[bytes]:
        """Direct file read (treats address as file offset)."""
        try:
            offset = address & 0xFFFFFFFF
            if offset + size > self._file_size:
                return None
            with open(self.memory_path, 'rb') as f:
                f.seek(offset)
                return f.read(size)
        except Exception as e:
            logger.debug(f"Direct read failed at {hex(address)}: {e}")
            return None
    
    def read_pointer(self, address: int) -> Optional[int]:
        """Read a pointer value from memory."""
        data = self.read_memory(address, self._pointer_size)
        if not data or len(data) < self._pointer_size:
            return None
        
        fmt = '<Q' if self._pointer_size == 8 else '<I'
        return struct.unpack(fmt, data)[0]
    
    # =========================================================================
    # DRIVER ENUMERATION - VOLATILITY3
    # =========================================================================
    
    def enumerate_drivers_volatility(self) -> List[DriverInfo]:
        """
        Enumerate drivers using Volatility3's PsLoadedModuleList.
        
        This provides the OS-acknowledged view of loaded drivers.
        """
        if not self._volatility_working or not self._vol_bridge:
            return []
        
        drivers = []
        
        try:
            modules = self._vol_bridge.enumerate_modules()
            
            # Safety check for None
            if modules is None:
                logger.debug("enumerate_modules returned None")
                return []
            
            for mod in modules:
                if not mod.get('base'):
                    continue
                
                # Filter for kernel modules (drivers, kernel, HAL)
                name = mod.get('name', '').lower()
                if not any(name.endswith(ext) for ext in ['.sys', '.exe', '.dll']):
                    continue
                
                driver = DriverInfo(
                    name=mod.get('name', 'unknown'),
                    base_address=mod['base'],
                    size=mod.get('size', 0),
                    driver_path=mod.get('path'),
                    enumeration_source=EnumerationSource.PSLOADED_MODULE_LIST.value,
                    found_in_pslist=True,
                )
                
                # Enrich with PE info
                self._enrich_driver_pe(driver)
                
                drivers.append(driver)
            
            logger.info(f"Volatility3 PsLoadedModuleList: {len(drivers)} drivers")
            
        except Exception as e:
            logger.error(f"Volatility3 enumeration failed: {e}")
        
        return drivers

    def enumerate_modules(self) -> List[Dict[str, Any]]:
        """
        Lightweight wrapper to expose module enumeration to other components.
        """
        if not self._volatility_working or not self._vol_bridge:
            return []

        try:
            modules = self._vol_bridge.enumerate_modules()
            if not modules:
                return []
            return modules
        except Exception as e:
            logger.debug(f"Module enumeration failed: {e}")
            return []
    
    def enumerate_drivers_scan(self) -> List[DriverInfo]:
        """
        Enumerate drivers via DRIVER_OBJECT pool scanning.
        
        This can find drivers hidden from the module list (DKOM).
        Returns drivers with MajorFunction tables populated.
        """
        if not self._volatility_working or not self._vol_bridge:
            return []
        
        drivers = []
        
        try:
            driver_objects = self._vol_bridge.enumerate_drivers()
            
            # Safety check for None
            if driver_objects is None:
                logger.debug("enumerate_drivers returned None")
                return []
            
            for obj in driver_objects:
                if not obj.driver_start:
                    continue
                
                driver = DriverInfo(
                    name=obj.driver_name or f"driver_{hex(obj.object_address)}",
                    base_address=obj.driver_start,
                    size=obj.driver_size,
                    driver_object_address=obj.object_address,
                    service_name=obj.service_key,
                    enumeration_source=EnumerationSource.DRIVER_OBJECT_SCAN.value,
                    found_in_driverscan=True,
                )
                
                # Populate MajorFunction table - THIS IS KEY
                driver.major_functions = obj.major_functions.copy()
                
                # Parse MajorFunction info for hook detection
                self._parse_major_functions(driver, obj)
                
                # Enrich with PE info
                self._enrich_driver_pe(driver)
                
                drivers.append(driver)
            
            logger.info(f"Volatility3 DriverScan: {len(drivers)} driver objects")
            
        except Exception as e:
            logger.error(f"Driver scan failed: {e}")
        
        return drivers
    
        return drivers
    
    def enumerate_threads(self) -> List[Dict[str, Any]]:
        """
        Enumerate system threads using Volatility3.
        """
        if not self._volatility_working or not self._vol_bridge:
            return []
            
        return self._vol_bridge.enumerate_threads()
    
    def _parse_major_functions(self, driver: DriverInfo, obj: DriverObjectInfo):
        """
        Parse MajorFunction table and check for hooks.
        
        A handler is "hooked" if it points outside the driver's .text section.
        """
        if not driver.text_section_start:
            # Try to get text section bounds
            self._get_text_section_bounds(driver)
        
        for idx, handler_addr in obj.major_functions.items():
            mf_info = MajorFunctionInfo(
                index=idx,
                handler_address=handler_addr,
            )
            
            # Check if handler is within driver's code section
            if driver.text_section_start and driver.text_section_end:
                mf_info.expected_range = (driver.text_section_start, driver.text_section_end)
                
                if handler_addr < driver.text_section_start or handler_addr > driver.text_section_end:
                    # Handler points outside driver's code - HOOKED!
                    mf_info.is_hooked = True
                    mf_info.hook_target = handler_addr
                    mf_info.because = (
                        f"BECAUSE: Handler at {hex(handler_addr)} is outside driver's "
                        f".text section ({hex(driver.text_section_start)}-{hex(driver.text_section_end)})"
                    )
            
            driver.major_function_info.append(mf_info)
    
    def _get_text_section_bounds(self, driver: DriverInfo):
        """Get the bounds of the .text section for hook detection."""
        if driver.base_address == 0:
            return
        
        header = self.read_memory(driver.base_address, 0x1000)
        if not header or not self._validate_pe(header):
            return
        
        try:
            if HAS_PEFILE:
                pe = pefile.PE(data=header, fast_load=True)
                
                for section in pe.sections:
                    name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                    if name.lower() in ['.text', 'code', '.code']:
                        driver.text_section_start = driver.base_address + section.VirtualAddress
                        driver.text_section_end = driver.text_section_start + section.Misc_VirtualSize
                        break
            else:
                # Manual parsing fallback
                pe_offset = struct.unpack('<I', header[0x3C:0x40])[0]
                num_sections = struct.unpack('<H', header[pe_offset+6:pe_offset+8])[0]
                opt_header_size = struct.unpack('<H', header[pe_offset+20:pe_offset+22])[0]
                
                section_offset = pe_offset + 24 + opt_header_size
                
                for i in range(min(num_sections, 16)):
                    sect_start = section_offset + (i * 40)
                    if sect_start + 40 > len(header):
                        break
                    
                    name = header[sect_start:sect_start+8].decode('utf-8', errors='ignore').rstrip('\x00')
                    if name.lower() in ['.text', 'code', '.code']:
                        vsize = struct.unpack('<I', header[sect_start+8:sect_start+12])[0]
                        va = struct.unpack('<I', header[sect_start+12:sect_start+16])[0]
                        driver.text_section_start = driver.base_address + va
                        driver.text_section_end = driver.text_section_start + vsize
                        break
        except Exception as e:
            logger.debug(f"Failed to get text section bounds: {e}")
    
    # =========================================================================
    # DRIVER ENUMERATION - PE CARVING (FALLBACK)
    # =========================================================================
    
    def enumerate_drivers_carving(self) -> List[DriverInfo]:
        """
        Enumerate drivers via PE carving from raw memory.
        
        This is the fallback method when Volatility3 fails.
        Only returns kernel-mode drivers (subsystem = NATIVE).
        """
        logger.info("Enumerating drivers via PE carving")
        drivers = []
        
        try:
            chunk_size = 1024 * 1024  # 1MB chunks
            pe_count = 0
            driver_count = 0
            max_pes = 3000
            max_drivers = 300
            
            with open(self.memory_path, 'rb') as f:
                offset = 0
                
                while offset < self._file_size and pe_count < max_pes and driver_count < max_drivers:
                    f.seek(offset)
                    chunk = f.read(chunk_size)
                    
                    if not chunk:
                        break
                    
                    pos = 0
                    while pos < len(chunk) - 0x200:
                        mz_pos = chunk.find(DOS_SIGNATURE, pos)
                        if mz_pos == -1 or mz_pos > len(chunk) - 0x200:
                            break
                        
                        pe_offset = offset + mz_pos
                        
                        f.seek(pe_offset)
                        header = f.read(0x1000)
                        
                        if self._validate_pe(header):
                            pe_count += 1
                            
                            # Check subsystem
                            subsystem = self._get_pe_subsystem(header)
                            
                            # Only kernel drivers (NATIVE = 1, UNKNOWN = 0)
                            if subsystem in [0, 1]:
                                pe_size = self._get_pe_image_size(header)
                                
                                if 0x1000 <= pe_size < 0x10000000:
                                    name = self._extract_pe_name(header, pe_offset)
                                    
                                    # Skip obvious non-drivers
                                    if any(x in name.lower() for x in ['.dll', '.exe', '.tlb', '.ocx', '.scr']):
                                        pos = mz_pos + 2
                                        continue
                                    
                                    driver = DriverInfo(
                                        name=name,
                                        base_address=pe_offset,
                                        size=pe_size,
                                        enumeration_source=EnumerationSource.PE_CARVING.value,
                                        found_in_carving=True,
                                    )
                                    
                                    # Enrich with PE info
                                    self._enrich_from_header(driver, header)
                                    
                                    drivers.append(driver)
                                    driver_count += 1
                        
                        pos = mz_pos + 2
                    
                    # Overlap to catch boundary MZs
                    offset += chunk_size - 0x1000
            
            logger.info(f"PE carving: {len(drivers)} kernel drivers (scanned {pe_count} PEs)")
            
        except Exception as e:
            logger.error(f"PE carving failed: {e}")
        
        return drivers
    
    # =========================================================================
    # PE PARSING HELPERS
    # =========================================================================
    
    def _validate_pe(self, data: bytes) -> bool:
        """Validate PE header structure."""
        if not data or len(data) < 0x100:
            return False
        
        if data[0:2] != DOS_SIGNATURE:
            return False
        
        try:
            pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
            
            if pe_off > len(data) - 4 or pe_off > 0x1000:
                return False
            
            if data[pe_off:pe_off+4] != PE_SIGNATURE:
                return False
            
            machine = struct.unpack('<H', data[pe_off+4:pe_off+6])[0]
            if machine not in [0x14C, 0x8664, 0x1C4, 0xAA64]:
                return False
            
            return True
        except:
            return False
    
    def _get_pe_subsystem(self, data: bytes) -> int:
        """Get PE subsystem from optional header."""
        try:
            pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
            
            # Check if PE32 or PE32+
            magic_offset = pe_off + 24
            if magic_offset + 2 > len(data):
                return 0
            
            magic = struct.unpack('<H', data[magic_offset:magic_offset+2])[0]
            
            if magic == 0x20B:  # PE32+
                subsystem_offset = pe_off + 24 + 68
            else:  # PE32
                subsystem_offset = pe_off + 24 + 68
            
            if subsystem_offset + 2 <= len(data):
                return struct.unpack('<H', data[subsystem_offset:subsystem_offset+2])[0]
        except:
            pass
        return 0
    
    def _get_pe_image_size(self, data: bytes) -> int:
        """Get PE image size from optional header."""
        try:
            pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
            size_offset = pe_off + 24 + 56  # SizeOfImage offset
            
            if size_offset + 4 <= len(data):
                return struct.unpack('<I', data[size_offset:size_offset+4])[0]
        except:
            pass
        return 0
    
    def _extract_pe_name(self, header: bytes, offset: int) -> str:
        """Extract PE name from export directory or version info."""
        if HAS_PEFILE:
            try:
                pe = pefile.PE(data=header, fast_load=True)
                
                # Try export name
                try:
                    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
                    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
                        if pe.DIRECTORY_ENTRY_EXPORT.name:
                            name = pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8', errors='ignore')
                            if name and len(name) > 1:
                                return name
                except:
                    pass
                
                # Try version info
                try:
                    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
                    if hasattr(pe, 'FileInfo') and pe.FileInfo:
                        for fi in pe.FileInfo:
                            if hasattr(fi, '__iter__'):
                                for entry in fi:
                                    if hasattr(entry, 'StringTable'):
                                        for st in entry.StringTable:
                                            for key in [b'OriginalFilename', b'InternalName']:
                                                if key in st.entries:
                                                    name = st.entries[key].decode('utf-8', errors='ignore').strip()
                                                    if name:
                                                        return name
                except:
                    pass
            except:
                pass
        
        return f"carved_{hex(offset)}.sys"
    
    def _enrich_driver_pe(self, driver: DriverInfo):
        """Enrich driver info from PE header in memory."""
        if driver.base_address == 0:
            return
        
        header = self.read_memory(driver.base_address, 0x1000)
        if header:
            self._enrich_from_header(driver, header)
    
    def _enrich_from_header(self, driver: DriverInfo, header: bytes):
        """Enrich driver info from PE header bytes."""
        if not header or len(header) < 0x100:
            return
        
        try:
            pe_off = struct.unpack('<I', header[0x3C:0x40])[0]
            
            # Timestamp
            ts_offset = pe_off + 8
            if ts_offset + 4 <= len(header):
                driver.pe_timestamp = struct.unpack('<I', header[ts_offset:ts_offset+4])[0]
                try:
                    driver.pe_timestamp_datetime = datetime.fromtimestamp(driver.pe_timestamp)
                except:
                    pass
            
            # Machine type
            if pe_off + 6 <= len(header):
                driver.pe_machine = struct.unpack('<H', header[pe_off+4:pe_off+6])[0]
            
            # Entry point and image size
            magic_off = pe_off + 24
            if magic_off + 2 <= len(header):
                magic = struct.unpack('<H', header[magic_off:magic_off+2])[0]
                
                ep_off = pe_off + 24 + 16
                if ep_off + 4 <= len(header):
                    driver.entry_point = struct.unpack('<I', header[ep_off:ep_off+4])[0]
                
                size_off = pe_off + 24 + 56
                if size_off + 4 <= len(header):
                    driver.image_size = struct.unpack('<I', header[size_off:size_off+4])[0]
            
            # Hashes
            driver.md5_hash = hashlib.md5(header).hexdigest()
            driver.sha256_hash = hashlib.sha256(header).hexdigest()
            
            if HAS_PEFILE:
                try:
                    pe = pefile.PE(data=header, fast_load=True)
                    driver.imphash = pe.get_imphash()
                except:
                    pass
            
            # Get text section bounds for hook detection
            self._get_text_section_bounds(driver)
            
            driver.is_valid_pe = True
            
        except Exception as e:
            driver.is_valid_pe = False
            driver.pe_validation_errors.append(str(e))
    
    # =========================================================================
    # IOCTL HANDLER EXTRACTION
    # =========================================================================
    
    def extract_ioctl_handler(self, driver: DriverInfo, code_size: int = 512) -> Optional[IOCTLHandler]:
        """Extract IOCTL dispatch handler code from driver."""
        
        # Try to get handler from MajorFunction table first
        ioctl_addr = driver.major_functions.get(IRP_MJ_DEVICE_CONTROL)
        
        if not ioctl_addr:
            # Fall back to entry point
            return self._extract_from_entry(driver, code_size)
        
        raw_code = self.read_memory(ioctl_addr, code_size)
        if not raw_code:
            return None
        
        return IOCTLHandler(
            major_function=IRP_MJ_DEVICE_CONTROL,
            handler_address=ioctl_addr,
            handler_offset=ioctl_addr - driver.base_address if driver.base_address else 0,
            code_size=code_size,
            raw_code=raw_code,
            disassembly=self._disassemble(raw_code, ioctl_addr),
        )
    
    def _extract_from_entry(self, driver: DriverInfo, code_size: int) -> Optional[IOCTLHandler]:
        """Extract code from driver entry point as fallback."""
        if driver.base_address == 0:
            return None
        
        header = self.read_memory(driver.base_address, 0x400)
        if not header or not self._validate_pe(header):
            return None
        
        try:
            pe_off = struct.unpack('<I', header[0x3C:0x40])[0]
            entry_rva = struct.unpack('<I', header[pe_off+0x28:pe_off+0x2C])[0]
            
            addr = driver.base_address + entry_rva
            raw_code = self.read_memory(addr, code_size)
            
            if raw_code:
                return IOCTLHandler(
                    major_function=IRP_MJ_DEVICE_CONTROL,
                    handler_address=addr,
                    handler_offset=entry_rva,
                    code_size=code_size,
                    raw_code=raw_code,
                    disassembly=self._disassemble(raw_code, addr),
                )
        except:
            pass
        
        return None
    
    def extract_all_handlers(self, driver: DriverInfo, code_size: int = 256) -> List[IOCTLHandler]:
        """Extract all MajorFunction handlers from a driver."""
        handlers = []
        
        if not driver.major_functions:
            return handlers
        
        for idx, handler_addr in driver.major_functions.items():
            if handler_addr == 0:
                continue
            
            raw_code = self.read_memory(handler_addr, code_size)
            if not raw_code:
                continue
            
            handlers.append(IOCTLHandler(
                major_function=idx,
                handler_address=handler_addr,
                handler_offset=handler_addr - driver.base_address if driver.base_address else 0,
                code_size=code_size,
                raw_code=raw_code,
                disassembly=self._disassemble(raw_code, handler_addr),
            ))
        
        return handlers
    
    def _disassemble(self, code: bytes, addr: int) -> List[str]:
        """Disassemble code bytes."""
        result = []
        if self._disassembler and code:
            try:
                for insn in self._disassembler.disasm(code, addr):
                    result.append(f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
                    if len(result) >= 100:
                        break
            except:
                pass
        return result
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def get_memory_hash(self) -> str:
        """Compute SHA256 hash of the memory image."""
        sha256 = hashlib.sha256()
        try:
            with open(self.memory_path, 'rb') as f:
                while True:
                    data = f.read(0x100000)
                    if not data:
                        break
                    sha256.update(data)
        except:
            return "error"
        return sha256.hexdigest()
    
    def get_memory_size(self) -> int:
        """Get memory image size."""
        return self._file_size
    
    def close(self):
        """Clean up resources."""
        self._memory_cache.clear()
        if self._vol_bridge:
            self._vol_bridge.close()
        logger.info("MemoryParser closed")
