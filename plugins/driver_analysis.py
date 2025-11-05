"""
iKARMA Driver Analysis Plugin for Volatility3
Extends driver enumeration with IOCTL handler extraction and capability analysis
"""

import logging
from typing import List, Tuple, Iterator

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import modules, driverscan

# Capstone for disassembly
try:
    from capstone import *
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logging.warning("Capstone not available. Disassembly features will be disabled.")

vollog = logging.getLogger(__name__)


class DriverAnalysis(interfaces.plugins.PluginInterface):
    """
    Analyzes Windows kernel drivers with focus on IOCTL handlers
    
    This plugin extends basic driver enumeration by:
    - Extracting MajorFunction dispatch tables
    - Identifying IOCTL handlers (IRP_MJ_DEVICE_CONTROL)
    - Disassembling handler code for capability analysis
    """
    
    _required_framework_version = (2, 0, 0)
    
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns the requirements for this plugin"""
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"]
            ),
            requirements.PluginRequirement(
                name="modules",
                plugin=modules.Modules,
                version=(1, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="disassemble",
                description="Enable disassembly of IOCTL handlers",
                default=True,
                optional=True
            ),
            requirements.IntRequirement(
                name="handler_bytes",
                description="Number of bytes to extract from handler (default 128)",
                default=128,
                optional=True
            )
        ]
    
    def _generator(self, data):
        """
        Generates output for each analyzed driver
        
        Yields tuples of:
        (driver_name, base_address, size, ioctl_handler, handler_info, risk_score)
        """
        kernel = self.context.modules[self.config["kernel"]]
        
        # Get configuration
        do_disassemble = self.config.get("disassemble", True)
        handler_bytes = self.config.get("handler_bytes", 128)
        
        if do_disassemble and not CAPSTONE_AVAILABLE:
            vollog.warning("Disassembly requested but Capstone not available")
            do_disassemble = False
        
        # Enumerate drivers using base Volatility3 modules plugin
        for driver in modules.Modules.list_modules(
            self.context,
            kernel.layer_name,
            kernel.symbol_table_name
        ):
            try:
                # Extract basic driver info
                driver_name = driver.get_name()
                base_addr = driver.DllBase
                driver_size = driver.SizeOfImage
                
                # Parse DRIVER_OBJECT for this driver
                driver_obj = self._find_driver_object(kernel, base_addr, driver_name)
                
                if driver_obj:
                    # Extract IOCTL handler (MajorFunction[0x0E])
                    ioctl_handler = self._get_ioctl_handler(driver_obj)
                    
                    if ioctl_handler and ioctl_handler != 0:
                        # Extract handler code from memory
                        handler_code = self._read_handler_code(
                            kernel.layer_name,
                            ioctl_handler,
                            handler_bytes
                        )
                        
                        # Analyze handler
                        if handler_code and do_disassemble:
                            analysis = self._analyze_handler(
                                handler_code,
                                ioctl_handler
                            )
                        else:
                            analysis = "Code unavailable or disassembly disabled"
                        
                        # Basic risk scoring (placeholder for Phase 2)
                        risk = self._calculate_basic_risk(handler_code, analysis)
                        
                        yield (
                            0,
                            (
                                format_hints.Hex(base_addr),
                                driver_name,
                                format_hints.Hex(driver_size),
                                format_hints.Hex(ioctl_handler),
                                str(analysis)[:100],  # Truncate for display
                                risk
                            )
                        )
                    else:
                        # No IOCTL handler found
                        yield (
                            0,
                            (
                                format_hints.Hex(base_addr),
                                driver_name,
                                format_hints.Hex(driver_size),
                                "N/A",
                                "No IOCTL handler",
                                "Low"
                            )
                        )
            except Exception as e:
                vollog.warning(f"Error analyzing driver {driver_name}: {str(e)}")
                continue
    
    def _find_driver_object(self, kernel, base_addr, driver_name):
        """
        Locate DRIVER_OBJECT structure for a given driver
        
        TODO Phase 1: Implement proper DRIVER_OBJECT lookup
        This is a placeholder - you'll need to traverse kernel structures
        to find the DRIVER_OBJECT associated with this driver module.
        
        Approaches:
        1. Search for DRIVER_OBJECT structures in memory
        2. Follow object manager namespace (\\Driver\\DriverName)
        3. Use known driver object addresses if available
        """
        # Placeholder - implement in Phase 1
        return None
    
    def _get_ioctl_handler(self, driver_obj):
        """
        Extract IOCTL handler address from DRIVER_OBJECT
        
        The MajorFunction table is an array of 28 function pointers.
        IRP_MJ_DEVICE_CONTROL (IOCTL) is at index 0x0E (14).
        """
        try:
            # Access MajorFunction array
            # Structure: DRIVER_OBJECT.MajorFunction[0x0E]
            major_functions = driver_obj.MajorFunction
            ioctl_handler = major_functions[0x0E]  # IRP_MJ_DEVICE_CONTROL
            
            return int(ioctl_handler)
        except Exception as e:
            vollog.debug(f"Failed to extract IOCTL handler: {e}")
            return None
    
    def _read_handler_code(self, layer_name, address, size):
        """
        Read handler code from memory
        
        Handles errors gracefully (paged out memory, invalid addresses)
        """
        try:
            layer = self.context.layers[layer_name]
            code_bytes = layer.read(address, size, pad=True)
            return code_bytes
        except exceptions.InvalidAddressException:
            vollog.debug(f"Invalid address when reading handler: 0x{address:x}")
            return None
        except Exception as e:
            vollog.debug(f"Error reading handler code: {e}")
            return None
    
    def _analyze_handler(self, code_bytes, address):
        """
        Disassemble and analyze handler code
        
        Phase 1: Basic disassembly
        Phase 2: Pattern matching for dangerous capabilities
        """
        if not CAPSTONE_AVAILABLE:
            return "Capstone not available"
        
        try:
            # Initialize Capstone for x64
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            
            instructions = []
            for insn in md.disasm(code_bytes, address):
                instructions.append(f"{insn.mnemonic} {insn.op_str}")
                
                # Limit output for Phase 1
                if len(instructions) >= 20:
                    break
            
            if instructions:
                return f"Disassembled {len(instructions)} instructions"
            else:
                return "Failed to disassemble"
                
        except Exception as e:
            return f"Disassembly error: {str(e)}"
    
    def _calculate_basic_risk(self, code_bytes, analysis):
        """
        Basic risk scoring (placeholder for Phase 2)
        
        Phase 2 will implement:
        - Pattern matching for dangerous APIs
        - Opcode analysis
        - Weighted scoring
        - Confidence levels
        """
        if not code_bytes:
            return "Unknown"
        
        # Placeholder logic
        if "error" in str(analysis).lower():
            return "Unknown"
        
        return "Low"  # Default for Phase 1
    
    def run(self):
        """Main entry point"""
        return renderers.TreeGrid(
            [
                ("Base Address", format_hints.Hex),
                ("Driver Name", str),
                ("Size", format_hints.Hex),
                ("IOCTL Handler", str),
                ("Analysis", str),
                ("Risk", str)
            ],
            self._generator(
                self.config
            )
        )


# Import format_hints at module level
from volatility3.framework.renderers import format_hints
