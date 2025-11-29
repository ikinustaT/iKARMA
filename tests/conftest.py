"""
iKARMA Test Suite - Fixtures and Configuration

Production-ready test fixtures for all components.
"""

import pytest
import struct
import tempfile
import os
from pathlib import Path
from typing import Generator

# PE structure helpers
DOS_SIGNATURE = b'MZ'
PE_SIGNATURE = b'PE\x00\x00'


def create_minimal_pe(
    subsystem: int = 1,  # NATIVE
    timestamp: int = 0x5F000000,
    machine: int = 0x8664,  # x64
    entry_point: int = 0x1000,
    image_size: int = 0x10000,
    text_section: bool = True,
    code_bytes: bytes = b''
) -> bytes:
    """Create a minimal valid PE for testing."""
    
    # DOS Header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:2] = DOS_SIGNATURE
    dos_header[0x3C:0x40] = struct.pack('<I', 64)  # e_lfanew
    
    # PE Header
    pe_header = bytearray()
    pe_header += PE_SIGNATURE
    pe_header += struct.pack('<H', machine)  # Machine
    pe_header += struct.pack('<H', 1 if text_section else 0)  # NumberOfSections
    pe_header += struct.pack('<I', timestamp)  # TimeDateStamp
    pe_header += struct.pack('<I', 0)  # PointerToSymbolTable
    pe_header += struct.pack('<I', 0)  # NumberOfSymbols
    pe_header += struct.pack('<H', 240 if machine == 0x8664 else 224)  # SizeOfOptionalHeader
    pe_header += struct.pack('<H', 0x22)  # Characteristics (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)
    
    # Optional Header (PE32+ for x64)
    opt_header = bytearray()
    opt_header += struct.pack('<H', 0x20B if machine == 0x8664 else 0x10B)  # Magic
    opt_header += struct.pack('<B', 14)  # MajorLinkerVersion
    opt_header += struct.pack('<B', 0)   # MinorLinkerVersion
    opt_header += struct.pack('<I', len(code_bytes) if code_bytes else 0x1000)  # SizeOfCode
    opt_header += struct.pack('<I', 0)   # SizeOfInitializedData
    opt_header += struct.pack('<I', 0)   # SizeOfUninitializedData
    opt_header += struct.pack('<I', entry_point)  # AddressOfEntryPoint
    opt_header += struct.pack('<I', 0x1000)  # BaseOfCode
    
    if machine == 0x8664:
        opt_header += struct.pack('<Q', 0xFFFFF80000000000)  # ImageBase
    else:
        opt_header += struct.pack('<I', 0)  # BaseOfData
        opt_header += struct.pack('<I', 0x10000)  # ImageBase
    
    opt_header += struct.pack('<I', 0x1000)  # SectionAlignment
    opt_header += struct.pack('<I', 0x200)   # FileAlignment
    opt_header += struct.pack('<H', 6)       # MajorOperatingSystemVersion
    opt_header += struct.pack('<H', 0)       # MinorOperatingSystemVersion
    opt_header += struct.pack('<H', 0)       # MajorImageVersion
    opt_header += struct.pack('<H', 0)       # MinorImageVersion
    opt_header += struct.pack('<H', 6)       # MajorSubsystemVersion
    opt_header += struct.pack('<H', 0)       # MinorSubsystemVersion
    opt_header += struct.pack('<I', 0)       # Win32VersionValue
    opt_header += struct.pack('<I', image_size)  # SizeOfImage
    opt_header += struct.pack('<I', 0x200)   # SizeOfHeaders
    opt_header += struct.pack('<I', 0)       # CheckSum
    opt_header += struct.pack('<H', subsystem)  # Subsystem
    opt_header += struct.pack('<H', 0)       # DllCharacteristics
    
    # Stack/Heap sizes
    if machine == 0x8664:
        opt_header += struct.pack('<Q', 0x100000)  # SizeOfStackReserve
        opt_header += struct.pack('<Q', 0x1000)    # SizeOfStackCommit
        opt_header += struct.pack('<Q', 0x100000)  # SizeOfHeapReserve
        opt_header += struct.pack('<Q', 0x1000)    # SizeOfHeapCommit
    else:
        opt_header += struct.pack('<I', 0x100000)  # SizeOfStackReserve
        opt_header += struct.pack('<I', 0x1000)    # SizeOfStackCommit
        opt_header += struct.pack('<I', 0x100000)  # SizeOfHeapReserve
        opt_header += struct.pack('<I', 0x1000)    # SizeOfHeapCommit
    
    opt_header += struct.pack('<I', 0)  # LoaderFlags
    opt_header += struct.pack('<I', 16)  # NumberOfRvaAndSizes
    
    # Data directories (16 entries, all zero for minimal PE)
    for _ in range(16):
        opt_header += struct.pack('<I', 0)  # VirtualAddress
        opt_header += struct.pack('<I', 0)  # Size
    
    # Section header (.text)
    section = bytearray()
    if text_section:
        section += b'.text\x00\x00\x00'  # Name
        section += struct.pack('<I', len(code_bytes) if code_bytes else 0x1000)  # VirtualSize
        section += struct.pack('<I', 0x1000)  # VirtualAddress
        section += struct.pack('<I', len(code_bytes) if code_bytes else 0x200)  # SizeOfRawData
        section += struct.pack('<I', 0x200)   # PointerToRawData
        section += struct.pack('<I', 0)       # PointerToRelocations
        section += struct.pack('<I', 0)       # PointerToLinenumbers
        section += struct.pack('<H', 0)       # NumberOfRelocations
        section += struct.pack('<H', 0)       # NumberOfLinenumbers
        section += struct.pack('<I', 0x60000020)  # Characteristics (CODE|EXECUTE|READ)
    
    # Combine headers
    headers = bytes(dos_header) + bytes(pe_header) + bytes(opt_header) + bytes(section)
    
    # Pad to 0x200 (file alignment)
    headers = headers.ljust(0x200, b'\x00')
    
    # Add code section
    if code_bytes:
        code_section = code_bytes.ljust(0x200, b'\x00')
    else:
        code_section = b'\x00' * 0x200
    
    return headers + code_section


@pytest.fixture
def minimal_driver_pe() -> bytes:
    """Create a minimal kernel driver PE."""
    return create_minimal_pe(subsystem=1)


@pytest.fixture
def driver_with_dangerous_opcodes() -> bytes:
    """Create a driver PE with dangerous opcodes."""
    # IN AL, DX (0xEC) - Port I/O read
    # OUT DX, AL (0xEE) - Port I/O write  
    # RDMSR (0x0F 0x32) - MSR read
    # WRMSR (0x0F 0x30) - MSR write
    code = bytes([
        0xEC,        # IN AL, DX
        0xEE,        # OUT DX, AL
        0x0F, 0x32,  # RDMSR
        0x0F, 0x30,  # WRMSR
        0x0F, 0x20, 0xC0,  # MOV RAX, CR0
        0x0F, 0x01, 0x08,  # SIDT [RAX]
        0xC3,        # RET
    ])
    return create_minimal_pe(code_bytes=code)


@pytest.fixture
def memory_dump_path(tmp_path: Path) -> Generator[str, None, None]:
    """Create a temporary memory dump file with embedded drivers."""
    dump_path = tmp_path / "test_memory.dmp"
    
    # Create a memory dump with embedded PE
    driver_pe = create_minimal_pe(subsystem=1)
    
    # Pad to simulate memory dump
    padding_before = b'\x00' * 0x1000
    padding_after = b'\x00' * 0x10000
    
    with open(dump_path, 'wb') as f:
        f.write(padding_before)
        f.write(driver_pe)
        f.write(padding_after)
    
    yield str(dump_path)
    
    # Cleanup
    if dump_path.exists():
        dump_path.unlink()


@pytest.fixture
def memory_dump_with_dangerous_driver(tmp_path: Path) -> Generator[str, None, None]:
    """Create memory dump with dangerous driver."""
    dump_path = tmp_path / "dangerous_memory.dmp"
    
    code = bytes([
        0xEC,        # IN AL, DX
        0x0F, 0x32,  # RDMSR
        0x0F, 0x30,  # WRMSR
        0xC3,        # RET
    ])
    
    driver_pe = create_minimal_pe(subsystem=1, code_bytes=code)
    
    padding = b'\x00' * 0x1000
    
    with open(dump_path, 'wb') as f:
        f.write(padding)
        f.write(driver_pe)
        f.write(padding * 10)
    
    yield str(dump_path)
    
    if dump_path.exists():
        dump_path.unlink()


@pytest.fixture
def sample_driver_info():
    """Create a sample DriverInfo for testing."""
    from ikarma.core import DriverInfo, SignatureInfo
    
    driver = DriverInfo(
        name="test_driver.sys",
        base_address=0xFFFFF80012340000,
        size=0x10000,
        driver_path="\\SystemRoot\\System32\\drivers\\test_driver.sys",
        pe_timestamp=0x5F000000,
        enumeration_source="PsLoadedModuleList",
    )
    driver.signature_info = SignatureInfo()
    
    return driver


@pytest.fixture
def sample_driver_with_capabilities():
    """Create a driver with pre-populated capabilities."""
    from ikarma.core import (
        DriverInfo, DriverCapability, CapabilityType, ConfidenceLevel
    )
    
    driver = DriverInfo(
        name="vulnerable_driver.sys",
        base_address=0xFFFFF80012340000,
        size=0x10000,
    )
    
    driver.add_capability(DriverCapability(
        capability_type=CapabilityType.MSR_READ,
        confidence=0.95,
        confidence_level=ConfidenceLevel.HIGH,
        description="RDMSR instruction detected",
        evidence="BECAUSE: Found RDMSR (0x0F32) at offset 0x100",
    ))
    
    driver.add_capability(DriverCapability(
        capability_type=CapabilityType.PORT_IO_WRITE,
        confidence=0.90,
        confidence_level=ConfidenceLevel.HIGH,
        description="OUT instruction detected",
        evidence="BECAUSE: Found OUT (0xEE) at offset 0x110",
    ))
    
    return driver
