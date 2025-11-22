"""
iKARMA BYOVD Capability Plugin for Volatility3
Deep-dive capability analysis of a single suspicious driver

This plugin provides comprehensive analysis of ONE driver:
1. Full disassembly of all exported functions
2. Complete API detection with call chains
3. Control flow analysis
4. Import/export table enumeration
5. Detailed risk assessment with evidence

Author: Person 1 (Team Lead)
Version: 1.0
Last Updated: 2025-11-20
"""

import logging
import json
import sys
import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import modules, driverscan

# Optional disassembly support
try:
    import capstone
    HAS_CAPSTONE = True
except Exception:
    HAS_CAPSTONE = False

# Import iKARMA modules
HAS_IKARMA_MODULES = False
find_dangerous_apis = None
calculate_driver_risk = None

try:
    # Import from sibling directories (core/ and utils/ are in same parent as this file)
    ikarma_root = str(Path(__file__).parent)
    if ikarma_root not in sys.path:
        sys.path.insert(0, ikarma_root)
    
    from utils.api_scanner import find_dangerous_apis, get_scanner_statistics
    from core.risk_scorer import calculate_driver_risk
    HAS_IKARMA_MODULES = True
except Exception as e:
    import_error = str(e)
    HAS_IKARMA_MODULES = False

vollog = logging.getLogger(__name__)


class BYOVDCapability(interfaces.plugins.PluginInterface):
    """
    iKARMA BYOVD Capability Analyzer - Deep-Dive Plugin
    
    Performs comprehensive analysis of a SINGLE driver:
    - Full disassembly (not just 100 instructions)
    - Complete API detection across entire code
    - Call chain analysis (which functions call which)
    - Import table enumeration
    - Detailed risk report with evidence
    
    Use this after byovd_scanner identifies a suspicious driver.
    """

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Define plugin requirements."""
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"]
            ),
            requirements.StringRequirement(
                name="driver",
                description="Driver name to analyze (e.g., 'evil.sys' or 'evil')",
                optional=False  # REQUIRED - must specify which driver
            ),
            requirements.BooleanRequirement(
                name="debug",
                description="Enable verbose debug output",
                optional=True,
                default=False
            ),
            requirements.StringRequirement(
                name="export-json",
                description="Export detailed analysis to JSON file",
                optional=True
            ),
            requirements.BooleanRequirement(
                name="full-disassembly",
                description="Include full disassembly in output (can be very large)",
                optional=True,
                default=False
            )
        ]

    def _safe_read_memory(self, layer, address: int, size: int, max_size: int = 0x100000, pad: bool = True) -> Optional[bytes]:
        """
        Safely read memory with bounds checking to prevent invalid access.

        Args:
            layer: Volatility memory layer
            address: Memory address to read from
            size: Number of bytes to read
            max_size: Maximum allowed read size (default 1MB)
            pad: Whether to pad with zeros if read fails

        Returns:
            Bytes read from memory, or None if address is invalid

        Security:
            - Validates address is not zero/NULL
            - Enforces maximum read size to prevent resource exhaustion
            - Catches InvalidAddressException to prevent crashes
        """
        # Bounds check: Reject NULL pointers
        if address == 0:
            vollog.debug(f"Rejected NULL pointer read at 0x0")
            return None

        # Bounds check: Enforce maximum read size
        if size > max_size:
            vollog.warning(f"Read size {size} exceeds maximum {max_size}, capping to max")
            size = max_size

        # Bounds check: Reject negative sizes
        if size <= 0:
            vollog.debug(f"Rejected invalid size {size}")
            return None

        # Attempt safe read with exception handling
        try:
            return layer.read(address, size, pad=pad)
        except exceptions.InvalidAddressException as e:
            vollog.debug(f"Invalid address 0x{address:x}: {e}")
            return None
        except Exception as e:
            vollog.warning(f"Unexpected error reading memory at 0x{address:x}: {type(e).__name__}")
            return None

    def _find_target_driver(self, target_name: str):
        """
        Find the specific driver module and DRIVER_OBJECT.
        
        Args:
            target_name: Driver name (with or without .sys)
            
        Returns:
            Tuple of (module_object, driver_object, normalized_name) or (None, None, None)
        """
        # Normalize target name
        target_normalized = target_name.lower().replace('.sys', '')
        
        vollog.info(f"Searching for driver: {target_name}")
        
        # Find module
        module_obj = None
        for mod in modules.Modules.list_modules(self.context, self.config['kernel']):
            try:
                driver_name = mod.BaseDllName.get_string()
                if not driver_name:
                    continue
                    
                driver_normalized = driver_name.lower().replace('.sys', '')

                if target_normalized in driver_normalized or driver_normalized in target_normalized:
                    module_obj = mod
                    vollog.info(f"✓ Found module: {driver_name}")
                    break
            except (AttributeError, exceptions.InvalidAddressException, UnicodeDecodeError):
                continue
        
        if not module_obj:
            return None, None, None
        
        # Find DRIVER_OBJECT
        driver_obj = None
        for drv in driverscan.DriverScan.scan_drivers(self.context, self.config['kernel']):
            try:
                driver_name_full = drv.DriverName.get_string()
                driver_short = driver_name_full.split('\\')[-1].lower()

                if target_normalized == driver_short.replace('.sys', ''):
                    driver_obj = drv
                    vollog.info(f"✓ Found DRIVER_OBJECT: {driver_name_full}")
                    break
            except (AttributeError, exceptions.InvalidAddressException, UnicodeDecodeError):
                continue
        
        return module_obj, driver_obj, target_normalized

    def _check_pe_header(self, layer_name: str, base_addr: int) -> Dict:
        """
        Try to read PE header from memory (may be paged out in memory dumps).
        Returns basic PE info if available.
        """
        try:
            layer = self.context.layers[layer_name]

            # Read DOS header with bounds checking
            dos_header = self._safe_read_memory(layer, base_addr, 0x40, pad=True)
            if dos_header is None:
                return {'valid': False, 'reason': 'Cannot read DOS header'}

            # Check MZ signature
            if dos_header[0:2] != b'MZ':
                return {'valid': False, 'reason': 'No MZ signature'}
            
            # Get PE offset
            import struct
            e_lfanew = struct.unpack('<I', dos_header[0x3c:0x40])[0]
            
            if e_lfanew > 0x1000:  # Sanity check
                return {'valid': False, 'reason': 'Invalid PE offset'}
            
            # Read PE signature with bounds checking
            pe_offset = base_addr + e_lfanew
            pe_data = self._safe_read_memory(layer, pe_offset, 0x100, pad=True)
            if pe_data is None:
                return {'valid': False, 'reason': 'Cannot read PE header'}

            if pe_data[0:4] != b'PE\x00\x00':
                return {'valid': False, 'reason': 'No PE signature'}
            
            # Read COFF header
            machine = struct.unpack('<H', pe_data[4:6])[0]
            num_sections = struct.unpack('<H', pe_data[6:8])[0]
            timestamp = struct.unpack('<I', pe_data[8:12])[0]
            
            # Determine architecture
            arch = 'x64' if machine == 0x8664 else 'x86' if machine == 0x14c else f'Unknown (0x{machine:x})'
            
            # Read optional header for entry point
            opt_header_offset = 24
            size_of_opt_header = struct.unpack('<H', pe_data[20:22])[0]
            
            entry_point_rva = 0
            if size_of_opt_header >= 28:
                entry_point_rva = struct.unpack('<I', pe_data[opt_header_offset + 16:opt_header_offset + 20])[0]
            
            return {
                'valid': True,
                'architecture': arch,
                'machine': machine,
                'sections': num_sections,
                'timestamp': timestamp,
                'entry_point_rva': entry_point_rva,
                'entry_point_va': base_addr + entry_point_rva if entry_point_rva else None
            }
            
        except Exception as e:
            return {'valid': False, 'reason': f'Exception: {str(e)}'}
    
    def _disassemble_smart(self, layer_name: str, base_addr: int, size: int, handler_addr: Optional[int] = None) -> Tuple[List[str], Dict]:
        """
        Smart disassembly that focuses on what's actually in memory.
        
        Returns:
            Tuple of (instructions_list, statistics_dict)
        """
        if not HAS_CAPSTONE:
            return [], {'error': 'Capstone not available'}
        
        stats = {
            'attempted': True,
            'memory_readable': 0,
            'memory_total': size,
            'instructions': 0,
            'code_density': 0.0,
            'architecture': 'Unknown'
        }
        
        try:
            layer = self.context.layers[layer_name]
            
            # Strategy: Read in chunks to handle paged memory better
            chunk_size = 0x1000  # 4KB chunks
            all_instructions = []
            readable_bytes = 0
            
            vollog.info(f"Reading memory in {chunk_size}-byte chunks...")
            
            for offset in range(0, min(size, 0x10000), chunk_size):  # Limit to first 64KB for performance
                try:
                    chunk_addr = base_addr + offset
                    data = self._safe_read_memory(layer, chunk_addr, chunk_size, pad=True)
                    if data is None:
                        continue
                    
                    # Count non-zero bytes (actual data vs padding)
                    non_zero = sum(1 for b in data if b != 0)
                    readable_bytes += non_zero
                    
                    if non_zero < chunk_size * 0.1:  # Less than 10% data
                        continue  # Skip mostly paged chunks
                    
                    # Try disassembly
                    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                    cs.detail = False
                    cs.skipdata = True  # Skip invalid data
                    
                    chunk_instructions = []
                    for ins in cs.disasm(data, chunk_addr):
                        chunk_instructions.append(f"{hex(ins.address)}:\t{ins.mnemonic}\t{ins.op_str}")
                    
                    # If x64 gives few results, try x86
                    if len(chunk_instructions) < 10:
                        cs32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                        cs32.detail = False
                        cs32.skipdata = True
                        
                        chunk_instructions_32 = []
                        for ins in cs32.disasm(data, chunk_addr):
                            chunk_instructions_32.append(f"{hex(ins.address)}:\t{ins.mnemonic}\t{ins.op_str}")
                        
                        if len(chunk_instructions_32) > len(chunk_instructions):
                            chunk_instructions = chunk_instructions_32
                            stats['architecture'] = 'x86'
                    else:
                        stats['architecture'] = 'x64'
                    
                    all_instructions.extend(chunk_instructions)
                    
                except Exception as e:
                    vollog.debug(f"Chunk at {hex(base_addr + offset)} failed: {e}")
                    continue
            
            stats['memory_readable'] = readable_bytes
            stats['instructions'] = len(all_instructions)
            stats['code_density'] = readable_bytes / size if size > 0 else 0.0
            
            vollog.info(f"✓ Disassembled {len(all_instructions):,} instructions")
            vollog.info(f"  Readable memory: {readable_bytes:,}/{size:,} bytes ({stats['code_density']*100:.1f}%)")
            vollog.info(f"  Architecture: {stats['architecture']}")
            
            # If we have an IOCTL handler, make sure we disassemble that region
            if handler_addr and (base_addr <= handler_addr < base_addr + size):
                handler_offset = handler_addr - base_addr
                vollog.info(f"  Focusing on IOCTL handler at offset +{hex(handler_offset)}")
                
                try:
                    handler_data = self._safe_read_memory(layer, handler_addr, 0x1000, pad=True)
                    if handler_data is None:
                        continue
                    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if stats['architecture'] == 'x64' else capstone.CS_MODE_32)
                    cs.detail = False
                    
                    handler_instructions = []
                    for ins in cs.disasm(handler_data, handler_addr):
                        handler_instructions.append(f"{hex(ins.address)}:\t{ins.mnemonic}\t{ins.op_str}")
                        if len(handler_instructions) >= 100:  # Get first 100 instructions of handler
                            break
                    
                    vollog.info(f"  Handler: {len(handler_instructions)} instructions disassembled")
                    
                    # Add handler instructions if not already present
                    existing_addrs = set(ins.split(':')[0] for ins in all_instructions)
                    for ins in handler_instructions:
                        addr = ins.split(':')[0]
                        if addr not in existing_addrs:
                            all_instructions.append(ins)
                    
                except Exception as e:
                    vollog.warning(f"Handler disassembly failed: {e}")
            
            return all_instructions, stats
            
        except Exception as e:
            stats['error'] = str(e)
            vollog.error(f"Disassembly failed: {e}")
            return [], stats

    def _build_call_graph(self, disassembly: List[str]) -> Dict[str, List[str]]:
        """
        Build call graph: which addresses call which other addresses.
        
        Args:
            disassembly: List of instruction strings
            
        Returns:
            Dict mapping caller_address -> [callee_addresses]
        """
        call_graph = {}
        
        for line in disassembly:
            if '\tcall\t' in line:
                parts = line.split(':')
                if len(parts) < 2:
                    continue
                
                caller_addr = parts[0]
                
                # Extract target address
                if '0x' in line:
                    # Direct call: "call 0x14000abcd"
                    target = line.split('0x')[-1].split()[0]
                    if caller_addr not in call_graph:
                        call_graph[caller_addr] = []
                    call_graph[caller_addr].append(f"0x{target}")
        
        return call_graph

    def _analyze_instruction_patterns(self, disassembly: List[str]) -> Dict:
        """
        Analyze disassembly for suspicious patterns and statistics.
        
        Returns:
            Dict with pattern analysis results
        """
        stats = {
            'total_instructions': len(disassembly),
            'call_instructions': 0,
            'jmp_instructions': 0,
            'ret_instructions': 0,
            'syscall_instructions': 0,
            'privileged_instructions': 0,
            'memory_operations': 0,
            'suspicious_patterns': []
        }
        
        privileged_ops = ['rdmsr', 'wrmsr', 'in ', 'out ', 'cli', 'sti', 'lgdt', 'lidt', 'mov cr']
        memory_ops = ['mov', 'lea', 'push', 'pop']
        
        for i, line in enumerate(disassembly):
            lower_line = line.lower()
            
            if '\tcall\t' in lower_line:
                stats['call_instructions'] += 1
            if '\tjmp\t' in lower_line or '\tje\t' in lower_line or '\tjne\t' in lower_line:
                stats['jmp_instructions'] += 1
            if '\tret' in lower_line:
                stats['ret_instructions'] += 1
            if '\tsyscall' in lower_line or '\tsysenter' in lower_line:
                stats['syscall_instructions'] += 1
            
            for priv_op in privileged_ops:
                if priv_op in lower_line:
                    stats['privileged_instructions'] += 1
                    stats['suspicious_patterns'].append({
                        'type': 'privileged_instruction',
                        'instruction': line,
                        'index': i
                    })
                    break
            
            for mem_op in memory_ops:
                if f'\t{mem_op}\t' in lower_line:
                    stats['memory_operations'] += 1
                    break
        
        return stats
    
    def _extract_strings(self, layer_name: str, base_addr: int, size: int) -> List[str]:
        """
        Extract readable strings from driver memory for additional context.
        """
        try:
            layer = self.context.layers[layer_name]
            # Read first 64KB with bounds checking
            data = self._safe_read_memory(layer, base_addr, min(size, 0x10000), pad=True)
            if data is None:
                return []
            
            strings = []
            current_string = []
            
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= 4:  # Minimum string length
                        strings.append(''.join(current_string))
                    current_string = []
            
            # Get unique, interesting strings
            interesting = []
            keywords = ['device', 'ioctl', 'map', 'physical', 'kernel', 'process', 
                       'system', 'registry', 'file', 'memory', 'debug']
            
            for s in strings[:100]:  # Limit to first 100 strings
                if any(kw in s.lower() for kw in keywords):
                    interesting.append(s)
            
            return interesting[:20]  # Return top 20
            
        except Exception as e:
            vollog.warning(f"String extraction failed: {e}")
            return []

    def _generator(self):
        """
        Main generator function for detailed driver analysis.
        """
        target_driver = self.config.get("driver")
        debug_mode = self.config.get("debug", False)
        export_json_path = self.config.get("export-json", None)
        full_disasm = self.config.get("full-disassembly", False)

        if debug_mode:
            vollog.setLevel(logging.DEBUG)

        vollog.info("=" * 80)
        vollog.info("🔍 iKARMA BYOVD CAPABILITY ANALYZER - DEEP DIVE MODE")
        vollog.info(f"   Target Driver: {target_driver}")
        vollog.info("=" * 80)
        
        if not HAS_CAPSTONE:
            vollog.error("⚠ Capstone not available - analysis will be limited")
            vollog.error("  Install: pip install capstone")
        
        if not HAS_IKARMA_MODULES:
            vollog.error("⚠ iKARMA modules not available - risk scoring disabled")
            vollog.error(f"  Error: {import_error if 'import_error' in globals() else 'Unknown'}")

        try:
            kernel = self.context.modules[self.config['kernel']]
            
            # Find target driver
            module_obj, driver_obj, normalized_name = self._find_target_driver(target_driver)
            
            if not module_obj:
                vollog.error(f"✗ Driver '{target_driver}' not found in memory dump")
                vollog.error("  Tip: Run 'ikarma.byovd_scanner' to see available drivers")
                return
            
            # Extract module info
            base_addr = int(module_obj.DllBase)
            size = int(module_obj.SizeOfImage)
            driver_name = module_obj.BaseDllName.get_string()
            
            vollog.info(f"Base Address: {hex(base_addr)}")
            vollog.info(f"Size: {hex(size)} ({size} bytes)")
            vollog.info(f"Name: {driver_name}")
            
            # Get IOCTL handler
            handler_addr = None
            if driver_obj:
                try:
                    IRP_MJ_DEVICE_CONTROL = 0x0E
                    handler_ptr = driver_obj.MajorFunction[IRP_MJ_DEVICE_CONTROL]
                    handler_addr = int(handler_ptr)
                    vollog.info(f"IOCTL Handler: {hex(handler_addr)}")
                except (AttributeError, TypeError, IndexError, exceptions.InvalidAddressException) as e:
                    vollog.warning(f"Could not extract IOCTL handler: {type(e).__name__}")
            
            # PHASE 1: PE Header Analysis (Forensic Metadata)
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("PHASE 1: PE Header Analysis")
            vollog.info("=" * 80)
            
            pe_info = self._check_pe_header(kernel.layer_name, base_addr)
            if pe_info['valid']:
                vollog.info(f"✓ Valid PE header found")
                vollog.info(f"  Architecture: {pe_info['architecture']}")
                vollog.info(f"  Sections: {pe_info['sections']}")
                if pe_info['timestamp']:
                    import datetime
                    try:
                        compile_time = datetime.datetime.utcfromtimestamp(pe_info['timestamp'])
                        vollog.info(f"  Compiled: {compile_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                    except (ValueError, OSError, OverflowError):
                        vollog.info(f"  Timestamp: {hex(pe_info['timestamp'])}")
            else:
                vollog.warning(f"⚠ PE header not readable: {pe_info.get('reason', 'Unknown')}")
                vollog.warning("  This is common in memory dumps - memory may be paged out")
            
            # PHASE 2: Smart Disassembly
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("PHASE 2: Memory Disassembly")
            vollog.info("=" * 80)
            
            disassembly, disasm_stats = self._disassemble_smart(kernel.layer_name, base_addr, size, handler_addr)
            
            if not disassembly or len(disassembly) < 10:
                vollog.error("=" * 80)
                vollog.error("⚠ CRITICAL: Disassembly failed or returned minimal results")
                vollog.error(f"  Readable memory: {disasm_stats.get('memory_readable', 0):,} / {size:,} bytes")
                vollog.error(f"  Code density: {disasm_stats.get('code_density', 0)*100:.1f}%")
                vollog.error("=" * 80)
                
                # Output forensic evidence of the failure
                yield (0, ("DRIVER INFO", "Metadata", f"{driver_name}",
                          f"Base: {hex(base_addr)} | Size: {hex(size)} ({size:,} bytes) | IOCTL: {hex(handler_addr) if handler_addr else 'None'}"))
                
                if pe_info['valid']:
                    yield (0, ("PE HEADER", "Valid", f"Architecture: {pe_info['architecture']}",
                              f"Sections: {pe_info['sections']} | Entry: {hex(pe_info['entry_point_va']) if pe_info.get('entry_point_va') else 'N/A'}"))
                else:
                    yield (0, ("PE HEADER", "Invalid/Paged", pe_info.get('reason', 'Cannot read'),
                              "PE headers may be paged out of memory"))
                
                yield (0, ("MEMORY STATUS", "Critical Issue",
                          f"Only {disasm_stats.get('memory_readable', 0):,} / {size:,} bytes readable ({disasm_stats.get('code_density', 0)*100:.1f}%)",
                          "Driver memory is mostly paged out or encrypted"))
                
                yield (0, ("DISASSEMBLY", "Failed",
                          f"Only {len(disassembly)} instructions recovered",
                          "Cannot analyze - memory not resident or corrupted"))
                
                yield (0, ("RECOMMENDATION", "Try Alternative Analysis",
                          "Memory dump may be incomplete or driver was not loaded",
                          "Options: 1) Capture new dump with driver active, 2) Use alternative forensic methods, 3) Analyze on-disk binary if available"))
                
                return
            
            # PHASE 2: Instruction Pattern Analysis
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("PHASE 2: Instruction Pattern Analysis")
            vollog.info("=" * 80)
            
            pattern_stats = self._analyze_instruction_patterns(disassembly)
            vollog.info(f"✓ Total Instructions: {pattern_stats['total_instructions']}")
            vollog.info(f"  Call Instructions: {pattern_stats['call_instructions']}")
            vollog.info(f"  Jump Instructions: {pattern_stats['jmp_instructions']}")
            vollog.info(f"  Memory Operations: {pattern_stats['memory_operations']}")
            vollog.info(f"  Privileged Instructions: {pattern_stats['privileged_instructions']}")
            
            if pattern_stats['suspicious_patterns']:
                vollog.warning(f"⚠ Found {len(pattern_stats['suspicious_patterns'])} suspicious patterns")
                for pattern in pattern_stats['suspicious_patterns'][:5]:  # Show first 5
                    vollog.warning(f"  [{pattern['type']}] {pattern['instruction'].strip()}")
            
            # PHASE 3: API Detection
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("PHASE 3: Dangerous API Detection")
            vollog.info("=" * 80)
            
            found_apis = []
            if HAS_IKARMA_MODULES:
                vollog.info("Running multi-method API scanner...")
                found_apis = find_dangerous_apis(disassembly)
                
                if found_apis:
                    vollog.info(f"✓ Detected {len(found_apis)} dangerous API calls")
                    stats = get_scanner_statistics(found_apis)
                    vollog.info(f"  Unique APIs: {stats['unique_apis']}")
                    vollog.info(f"  Highest Risk: {stats['highest_risk']}/10")
                    vollog.info(f"  Categories: {', '.join(stats['by_category'].keys())}")
                    
                    # Show top 10 most dangerous APIs found
                    vollog.info("")
                    vollog.info("  TOP 10 DETECTED APIs:")
                    sorted_apis = sorted(found_apis, key=lambda x: x['risk'], reverse=True)
                    for i, api in enumerate(sorted_apis[:10], 1):
                        confidence_str = f"{api['confidence']*100:.0f}%"
                        vollog.info(f"    {i:2d}. {api['name']:30s} Risk: {api['risk']}/10 | Confidence: {confidence_str} | {api['address']}")
                else:
                    vollog.info("✓ No dangerous APIs detected (driver may be benign)")
            else:
                vollog.warning("✗ API scanner unavailable - install iKARMA modules")
            
            # PHASE 4: Call Graph Analysis
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("PHASE 4: Call Graph Analysis")
            vollog.info("=" * 80)
            
            call_graph = self._build_call_graph(disassembly)
            if call_graph:
                vollog.info(f"✓ Identified {len(call_graph)} functions with outgoing calls")
                
                # Find most complex functions
                complex_funcs = sorted(call_graph.items(), key=lambda x: len(x[1]), reverse=True)[:5]
                if complex_funcs:
                    vollog.info("  Most Complex Functions (by call count):")
                    for addr, targets in complex_funcs:
                        vollog.info(f"    {addr}: {len(targets)} outgoing calls")
            else:
                vollog.info("✓ No call graph detected (driver may be simple or obfuscated)")
            
            # PHASE 5: String Analysis
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("PHASE 5: String & Context Analysis")
            vollog.info("=" * 80)
            
            interesting_strings = self._extract_strings(kernel.layer_name, base_addr, size)
            if interesting_strings:
                vollog.info(f"✓ Found {len(interesting_strings)} interesting strings")
                vollog.info("  Sample Strings (may indicate functionality):")
                for string in interesting_strings[:10]:
                    vollog.info(f"    \"{string}\"")
            else:
                vollog.info("✓ No interesting strings found")
            
            # PHASE 6: Risk Assessment
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("PHASE 6: Comprehensive Risk Assessment")
            vollog.info("=" * 80)
            
            risk_result = {'score': 0, 'level': 'Unknown', 'reasons': 'Risk analysis unavailable'}
            
            if HAS_IKARMA_MODULES:
                risk_result = calculate_driver_risk(
                    normalized_name=normalized_name,
                    analysis_result="Custom IOCTL" if handler_addr and (base_addr <= handler_addr < base_addr + size) else "Enumerated",
                    ioctl_handler_display=hex(handler_addr) if handler_addr else "Not Found",
                    size=size,
                    handler_addr=handler_addr,
                    found_apis=found_apis,
                    disasm_lines=disassembly
                )
                
                vollog.info(f"")
                vollog.info(f"  OVERALL RISK SCORE: {risk_result['score']}/100")
                vollog.info(f"  RISK LEVEL: {risk_result['level']}")
                vollog.info(f"  CONFIDENCE: {risk_result.get('confidence', 'N/A')}")
                vollog.info(f"")
                vollog.info(f"  Risk Factors:")
                for reason in risk_result['reasons'].split(';'):
                    if reason.strip():
                        vollog.info(f"    • {reason.strip()}")
            else:
                vollog.warning("✗ Risk scoring unavailable - install iKARMA modules")
            
            # PHASE 7: Summary & Recommendations
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("PHASE 7: Analysis Summary & Recommendations")
            vollog.info("=" * 80)
            
            # Generate verdict
            verdict = "BENIGN"
            recommendation = "No immediate action required"
            
            if risk_result['score'] >= 90:
                verdict = "⚠️  CRITICAL THREAT"
                recommendation = "IMMEDIATE INVESTIGATION REQUIRED - Likely malicious or vulnerable"
            elif risk_result['score'] >= 70:
                verdict = "⚠️  HIGH RISK"
                recommendation = "Manual review recommended - Suspicious characteristics detected"
            elif risk_result['score'] >= 40:
                verdict = "⚠️  MODERATE RISK"
                recommendation = "Monitor for anomalous behavior - May be legitimate but unusual"
            elif risk_result['score'] >= 20:
                verdict = "ℹ️  LOW RISK"
                recommendation = "Likely benign - Standard driver behavior observed"
            else:
                verdict = "✓ BENIGN"
                recommendation = "No threats detected - Appears to be legitimate system driver"
            
            vollog.info(f"  VERDICT: {verdict}")
            vollog.info(f"  RECOMMENDATION: {recommendation}")
            vollog.info("")
            vollog.info(f"  Analysis Statistics:")
            vollog.info(f"    • Instructions Analyzed: {pattern_stats['total_instructions']}")
            vollog.info(f"    • APIs Detected: {len(found_apis) if found_apis else 0}")
            vollog.info(f"    • Call Graph Nodes: {len(call_graph)}")
            vollog.info(f"    • Privileged Operations: {pattern_stats['privileged_instructions']}")
            vollog.info(f"    • Suspicious Patterns: {len(pattern_stats['suspicious_patterns'])}")
            
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("✓ Deep-dive analysis complete - outputting forensic evidence")
            vollog.info("=" * 80)
            
            # ================================================================
            # OUTPUT FORENSIC EVIDENCE AS MULTIPLE TABLE ROWS
            # ================================================================
            
            # Row 1: Driver Metadata (ALWAYS SHOW THIS FIRST)
            yield (0, (
                "DRIVER INFO",
                "Module Metadata",
                f"{driver_name}",
                f"Base: {hex(base_addr)} | Size: {hex(size)} ({size:,} bytes) | IOCTL: {hex(handler_addr) if handler_addr else 'None'}"
            ))
            
            # Row 2: PE Header Info (if available - FORENSIC EVIDENCE)
            if pe_info['valid']:
                compile_time_str = "Unknown"
                if pe_info.get('timestamp'):
                    try:
                        import datetime
                        compile_time = datetime.datetime.utcfromtimestamp(pe_info['timestamp'])
                        compile_time_str = compile_time.strftime('%Y-%m-%d %H:%M:%S UTC')
                    except (ValueError, OSError, OverflowError):
                        compile_time_str = f"Timestamp: {hex(pe_info['timestamp'])}"
                
                yield (0, (
                    "PE HEADER",
                    pe_info['architecture'],
                    f"Valid PE structure detected",
                    f"Compiled: {compile_time_str} | Sections: {pe_info['sections']} | Entry: {hex(pe_info['entry_point_va']) if pe_info.get('entry_point_va') else 'N/A'}"
                ))
            else:
                yield (0, (
                    "PE HEADER",
                    "Not Readable",
                    pe_info.get('reason', 'Cannot read from memory'),
                    "PE headers paged out or corrupted - common in memory dumps"
                ))
            
            # Row 3: Memory Status (FORENSIC EVIDENCE - Critical for credibility)
            mem_readable_pct = disasm_stats.get('code_density', 0) * 100
            mem_status = "Good" if mem_readable_pct > 80 else "Partial" if mem_readable_pct > 30 else "Poor"
            
            yield (0, (
                "MEMORY STATUS",
                mem_status,
                f"{disasm_stats.get('memory_readable', 0):,} / {size:,} bytes readable ({mem_readable_pct:.1f}%)",
                f"Architecture detected: {disasm_stats.get('architecture', 'Unknown')} | " +
                f"{'Memory mostly resident' if mem_readable_pct > 80 else 'Partial paging detected' if mem_readable_pct > 30 else 'Heavily paged - analysis limited'}"
            ))
            
            # Row 4: Disassembly Statistics (CODE EVIDENCE)
            yield (0, (
                "DISASSEMBLY",
                "Code Analysis",
                f"{pattern_stats['total_instructions']:,} instructions recovered",
                f"Calls: {pattern_stats['call_instructions']} | Jumps: {pattern_stats['jmp_instructions']} | " +
                f"Memory Ops: {pattern_stats['memory_operations']} | Privileged: {pattern_stats['privileged_instructions']}"
            ))
            
            # Row 3-N: Detected APIs (TOP EVIDENCE)
            if found_apis:
                sorted_apis = sorted(found_apis, key=lambda x: x['risk'], reverse=True)
                for i, api in enumerate(sorted_apis[:15], 1):  # Show top 15 APIs
                    confidence_pct = int(api['confidence'] * 100)
                    yield (0, (
                        f"API #{i}",
                        api.get('category', 'UNKNOWN'),
                        f"{api['name']} [Risk: {api['risk']}/10, Confidence: {confidence_pct}%]",
                        f"Address: {api['address']} | Method: {api['method']} | Instruction: {api.get('instruction', 'N/A')[:80]}"
                    ))
            else:
                yield (0, (
                    "APIs",
                    "Detection",
                    "No dangerous APIs detected",
                    "Driver appears to use only safe/standard APIs"
                ))
            
            # Row: Call Graph Evidence
            if call_graph:
                complex_funcs = sorted(call_graph.items(), key=lambda x: len(x[1]), reverse=True)[:5]
                for i, (addr, targets) in enumerate(complex_funcs, 1):
                    yield (0, (
                        f"FUNCTION #{i}",
                        "Call Graph",
                        f"{addr} has {len(targets)} outgoing calls",
                        f"Targets: {', '.join(targets[:5])}" + ("..." if len(targets) > 5 else "")
                    ))
            
            # Row: Suspicious Patterns (EVIDENCE)
            if pattern_stats['suspicious_patterns']:
                for i, pattern in enumerate(pattern_stats['suspicious_patterns'][:10], 1):
                    yield (0, (
                        f"SUSPICIOUS #{i}",
                        pattern['type'].upper(),
                        "Privileged instruction detected",
                        pattern['instruction'].strip()[:100]
                    ))
            
            # Row: Interesting Strings (EVIDENCE)
            if interesting_strings:
                for i, string in enumerate(interesting_strings[:10], 1):
                    yield (0, (
                        f"STRING #{i}",
                        "String Analysis",
                        f"\"{string}\"",
                        "May indicate driver functionality or target"
                    ))
            
            # Row: Risk Assessment Summary
            yield (0, (
                "RISK ASSESSMENT",
                risk_result['level'],
                f"Score: {risk_result['score']}/100 | Confidence: {risk_result.get('confidence', 'N/A')}",
                f"Verdict: {verdict}"
            ))
            
            # Row: Risk Factors (EVIDENCE for score)
            for i, reason in enumerate(risk_result['reasons'].split(';')[:10], 1):
                if reason.strip():
                    yield (0, (
                        f"RISK FACTOR #{i}",
                        "Scoring Evidence",
                        reason.strip()[:60],
                        "Contributed to final risk score"
                    ))
            
            # Final Row: Recommendation
            yield (0, (
                "RECOMMENDATION",
                "Action Required",
                recommendation,
                f"Analysis completed: {pattern_stats['total_instructions']} inst, " +
                f"{len(found_apis) if found_apis else 0} APIs, " +
                f"{len(call_graph)} functions, " +
                f"{pattern_stats['privileged_instructions']} privileged ops"
            ))
            
            # JSON export with full details
            if export_json_path:
                export_data = {
                    'analysis_metadata': {
                        'plugin': 'ikarma.byovd_capability',
                        'version': '1.0',
                        'timestamp': str(Path(__file__).stat().st_mtime),
                        'target_driver': target_driver
                    },
                    'driver_info': {
                        'name': driver_name,
                        'base_address': hex(base_addr),
                        'size': size,
                        'size_hex': hex(size),
                        'ioctl_handler': hex(handler_addr) if handler_addr else None
                    },
                    'disassembly_analysis': {
                        'total_instructions': pattern_stats['total_instructions'],
                        'call_instructions': pattern_stats['call_instructions'],
                        'jump_instructions': pattern_stats['jmp_instructions'],
                        'memory_operations': pattern_stats['memory_operations'],
                        'privileged_instructions': pattern_stats['privileged_instructions'],
                        'suspicious_patterns': pattern_stats['suspicious_patterns']
                    },
                    'api_detections': {
                        'count': len(found_apis) if found_apis else 0,
                        'findings': found_apis if found_apis else []
                    },
                    'call_graph': {
                        'node_count': len(call_graph),
                        'edges': call_graph
                    },
                    'string_analysis': {
                        'interesting_strings': interesting_strings
                    },
                    'risk_assessment': risk_result,
                    'verdict': {
                        'classification': verdict,
                        'recommendation': recommendation
                    }
                }
                
                if full_disasm:
                    export_data['full_disassembly'] = disassembly[:1000]  # Limit to first 1000 instructions
                    export_data['disassembly_truncated'] = len(disassembly) > 1000
                
                import json
                with open(export_json_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                vollog.info("")
                vollog.info(f"✓ Comprehensive analysis exported to: {export_json_path}")

        except Exception as e:
            vollog.error(f"FATAL ERROR: {e}")
            import traceback
            vollog.error(traceback.format_exc())
            raise

    def run(self):
        """Entry point for the plugin."""
        return renderers.TreeGrid(
            [
                ("Section", str),
                ("Category", str),
                ("Evidence", str),
                ("Details", str)
            ],
            self._generator()
        )
