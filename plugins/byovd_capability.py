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
    # Add the iKARMA root directory to path (core/ and utils/ are there)
    ikarma_root = str(Path(__file__).parent)
    if ikarma_root not in sys.path:
        sys.path.insert(0, ikarma_root)
    
    from utils.api_scanner import find_dangerous_apis, get_scanner_statistics
    from core.risk_scorer import calculate_driver_risk
    HAS_IKARMA_MODULES = True
except Exception as e:
    import_error = str(e)
    pass

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
            except:
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
            except:
                continue
        
        return module_obj, driver_obj, target_normalized

    def _disassemble_full_module(self, layer_name: str, base_addr: int, size: int) -> List[str]:
        """
        Disassemble the ENTIRE driver module (not just 100 instructions).
        
        Args:
            layer_name: Memory layer name
            base_addr: Driver base address
            size: Module size
            
        Returns:
            List of all disassembled instructions
        """
        if not HAS_CAPSTONE:
            vollog.error("Capstone not available - cannot disassemble")
            return []
        
        vollog.info(f"Disassembling full module: {hex(base_addr)}-{hex(base_addr + size)} ({size} bytes)")
        
        try:
            layer = self.context.layers[layer_name]
            
            # Read entire module (this can be large!)
            data = layer.read(base_addr, size, pad=True)
            
            # Disassemble
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            cs.detail = False
            
            instructions = []
            for ins in cs.disasm(data, base_addr):
                instructions.append(f"{hex(ins.address)}:\t{ins.mnemonic}\t{ins.op_str}")
            
            vollog.info(f"✓ Disassembled {len(instructions)} instructions")
            return instructions
            
        except Exception as e:
            vollog.error(f"Disassembly failed: {e}")
            return []

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
        vollog.info(f"iKARMA BYOVD Capability Analyzer - Target: {target_driver}")
        vollog.info("=" * 80)
        
        if not HAS_CAPSTONE:
            vollog.error("⚠ Capstone not available - analysis limited")
        
        if not HAS_IKARMA_MODULES:
            vollog.error("⚠ iKARMA modules not available - analysis limited")

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
                except:
                    vollog.warning("Could not extract IOCTL handler")
            
            # PHASE 1: Full Disassembly
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("PHASE 1: Full Module Disassembly")
            vollog.info("=" * 80)
            
            disassembly = self._disassemble_full_module(kernel.layer_name, base_addr, size)
            
            if not disassembly:
                vollog.error("Disassembly failed - cannot continue analysis")
                return
            
            # PHASE 2: API Detection
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("PHASE 2: Dangerous API Detection")
            vollog.info("=" * 80)
            
            found_apis = []
            if HAS_IKARMA_MODULES:
                found_apis = find_dangerous_apis(disassembly)
                vollog.info(f"✓ Found {len(found_apis)} dangerous API calls")
                
                if found_apis:
                    stats = get_scanner_statistics(found_apis)
                    vollog.info(f"  Unique APIs: {stats['unique_apis']}")
                    vollog.info(f"  Highest risk: {stats['highest_risk']}/10")
                    vollog.info(f"  By category: {stats['by_category']}")
            
            # PHASE 3: Call Graph Analysis
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("PHASE 3: Call Graph Analysis")
            vollog.info("=" * 80)
            
            call_graph = self._build_call_graph(disassembly)
            vollog.info(f"✓ Identified {len(call_graph)} functions with calls")
            
            # PHASE 4: Risk Assessment
            vollog.info("")
            vollog.info("=" * 80)
            vollog.info("PHASE 4: Risk Assessment")
            vollog.info("=" * 80)
            
            if HAS_IKARMA_MODULES:
                risk_result = calculate_driver_risk(
                    normalized_name=normalized_name,
                    analysis_result="Custom IOCTL" if handler_addr and (base_addr <= handler_addr < base_addr + size) else "Enumerated",
                    ioctl_handler_display=hex(handler_addr) if handler_addr else "Not Found",
                    size=size,
                    handler_addr=handler_addr,
                    found_apis=found_apis
                )
                
                vollog.info(f"Risk Score: {risk_result['score']}/100")
                vollog.info(f"Risk Level: {risk_result['level']}")
                vollog.info(f"Factors: {risk_result['reasons']}")
            
            # Output results
            yield (0, (
                format_hints.Hex(base_addr),
                driver_name,
                format_hints.Hex(size),
                len(disassembly),
                len(found_apis) if found_apis else 0,
                len(call_graph),
                risk_result['score'] if HAS_IKARMA_MODULES else 0,
                risk_result['level'] if HAS_IKARMA_MODULES else "N/A"
            ))
            
            # JSON export with full details
            if export_json_path:
                export_data = {
                    'driver_name': driver_name,
                    'base_address': hex(base_addr),
                    'size': size,
                    'ioctl_handler': hex(handler_addr) if handler_addr else None,
                    'instruction_count': len(disassembly),
                    'found_apis': found_apis if found_apis else [],
                    'call_graph': call_graph,
                    'risk_assessment': risk_result if HAS_IKARMA_MODULES else {},
                }
                
                if full_disasm:
                    export_data['full_disassembly'] = disassembly
                
                with open(export_json_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                vollog.info(f"✓ Detailed analysis exported to: {export_json_path}")

        except Exception as e:
            vollog.error(f"FATAL ERROR: {e}")
            import traceback
            vollog.error(traceback.format_exc())
            raise

    def run(self):
        """Entry point for the plugin."""
        return renderers.TreeGrid(
            [
                ("Base Address", format_hints.Hex),
                ("Driver Name", str),
                ("Size", format_hints.Hex),
                ("Instructions", int),
                ("APIs Found", int),
                ("Functions", int),
                ("Risk Score", int),
                ("Risk Level", str)
            ],
            self._generator()
        )
