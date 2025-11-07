"""
iKARMA Driver Analysis Plugin for Volatility3
Analyzes kernel drivers for BYOVD (Bring Your Own Vulnerable Driver) risk indicators

MVP Phase 1: Enumerate kernel drivers from memory dump
"""

import logging
from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import modules

vollog = logging.getLogger(__name__)


class DriverAnalysis(interfaces.plugins.PluginInterface):
    """
    iKARMA Driver Analysis Plugin
    
    Phase 1 (MVP): Enumerate all kernel drivers (.sys files) from memory
    Future phases: IOCTL handler analysis, dangerous API detection, risk scoring
    """
    
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
    
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """
        Define plugin requirements.
        """
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"]
            ),
            requirements.ListRequirement(
                name="drivers",
                element_type=str,
                description="Filter output by driver name (optional)",
                optional=True
            ),
            requirements.BooleanRequirement(
                name="debug",
                description="Enable verbose debug output",
                optional=True,
                default=False
            )
        ]
    
    def _generator(self):
        """
        Main generator function that yields driver information.
        This is called by Volatility's rendering engine.
        """
        try:
            driver_filter = self.config.get("drivers", None)
            debug_mode = self.config.get("debug", False)
            
            if debug_mode:
                vollog.setLevel(logging.DEBUG)
            
            vollog.info("=" * 60)
            vollog.info("STARTING DRIVER ENUMERATION")
            vollog.info("=" * 60)
            
            # Get the kernel module object
            kernel = self.context.modules[self.config['kernel']]
            vollog.info(f"✓ Kernel module obtained: {kernel.symbol_table_name}")
            vollog.info(f"✓ Layer name: {kernel.layer_name}")
            
            # Debug: Check what methods are available on Modules class
            if debug_mode:
                vollog.debug(f"Available methods on Modules class: {dir(modules.Modules)}")
            
            count = 0
            driver_count = 0
            sys_file_count = 0
            
            vollog.info("Calling Modules.list_modules()...")
            vollog.info(f"  - Context: {self.context}")
            vollog.info(f"  - Kernel module name: {self.config['kernel']}")
            
            # CORRECT signature: list_modules(context, kernel_module_name)
            # The kernel_module_name is the string "kernel" from our config
            try:
                module_iterator = modules.Modules.list_modules(
                    self.context,
                    self.config['kernel']  # This is the string "kernel", not the module object!
                )
                vollog.info("✓ Module iterator created successfully")
            except Exception as e:
                vollog.error(f"Failed to create module iterator: {e}")
                import inspect
                sig = inspect.signature(modules.Modules.list_modules)
                vollog.error(f"Expected signature: {sig}")
                raise
            
            vollog.info("Beginning module iteration...")
            
            # Iterate through all kernel modules
            for mod in module_iterator:
                count += 1
                
                if debug_mode and count <= 5:
                    vollog.debug(f"\n{'='*50}")
                    vollog.debug(f"MODULE #{count}")
                    vollog.debug(f"Module object type: {type(mod)}")
                    vollog.debug(f"Module object: {mod}")
                
                try:
                    # Extract basic module information from the kernel structure
                    base_addr = mod.DllBase
                    size = mod.SizeOfImage
                    
                    if debug_mode and count <= 5:
                        vollog.debug(f"  ✓ Base address: {hex(base_addr)}")
                        vollog.debug(f"  ✓ Size: {hex(size)} ({size} bytes)")
                    
                    # Get the module name - try BaseDllName first, then FullDllName
                    driver_name = None
                    try:
                        # BaseDllName is a UNICODE_STRING structure
                        driver_name = mod.BaseDllName.get_string()
                        if debug_mode and count <= 5:
                            vollog.debug(f"  ✓ BaseDllName: {driver_name}")
                    except Exception as e:
                        if debug_mode and count <= 5:
                            vollog.debug(f"  ✗ Couldn't get BaseDllName: {e}")
                        try:
                            driver_name = mod.FullDllName.get_string()
                            if debug_mode and count <= 5:
                                vollog.debug(f"  ✓ FullDllName: {driver_name}")
                        except Exception as e2:
                            if debug_mode and count <= 5:
                                vollog.debug(f"  ✗ Couldn't get FullDllName either: {e2}")
                            continue
                    
                    # Skip if no valid name
                    if not driver_name:
                        vollog.debug(f"Module #{count} - empty name, skipping")
                        continue
                    
                    # FILTER 1: Only show .sys files (kernel drivers)
                    if driver_name.lower().endswith('.sys'):
                        sys_file_count += 1
                        if debug_mode:
                            vollog.debug(f"  ✓ Is .sys file: {driver_name}")
                    else:
                        if debug_mode and count <= 10:
                            vollog.debug(f"  ✗ Not a .sys file: {driver_name}")
                        continue
                    
                    # FILTER 2: Apply user-specified filter if provided
                    if driver_filter:
                        if not any(filt.lower() in driver_name.lower() for filt in driver_filter):
                            if debug_mode:
                                vollog.debug(f"  ✗ Doesn't match filter: {driver_name}")
                            continue
                        else:
                            if debug_mode:
                                vollog.debug(f"  ✓ Matches filter!")
                    
                    driver_count += 1
                    vollog.info(f"[{driver_count}] Found driver: {driver_name} at {hex(base_addr)} (size: {hex(size)})")
                    
                    # For Phase 1: Just basic enumeration
                    # Phase 2 will add: IOCTL handler extraction
                    # Phase 3 will add: Disassembly and API scanning
                    # Phase 4 will add: Risk scoring
                    
                    analysis_result = "Enumerated"
                    risk_level = "N/A"
                    
                    # Yield the row data for this driver
                    yield (
                        0,  # Tree depth level (0 = root)
                        (
                            format_hints.Hex(base_addr),
                            driver_name,
                            format_hints.Hex(size),
                            analysis_result,
                            risk_level
                        )
                    )
                    
                except Exception as e:
                    vollog.error(f"Error processing module #{count}: {e}")
                    if debug_mode:
                        import traceback
                        traceback.print_exc()
                    continue
            
            vollog.info("=" * 60)
            vollog.info(f"ENUMERATION COMPLETE")
            vollog.info(f"Total modules processed: {count}")
            vollog.info(f".sys files found: {sys_file_count}")
            vollog.info(f"Drivers yielded (after filters): {driver_count}")
            vollog.info("=" * 60)
            
        except Exception as e:
            vollog.error(f"FATAL ERROR in _generator: {e}")
            import traceback
            traceback.print_exc()
            # Re-raise to make it visible
            raise
    
    def run(self):
        """
        Entry point for the plugin.
        Returns a TreeGrid with our column definitions and data.
        """
        vollog.info("Plugin run() method called")
        return renderers.TreeGrid(
            [
                ("Base Address", format_hints.Hex),
                ("Driver Name", str),
                ("Size (bytes)", format_hints.Hex),
                ("Analysis", str),
                ("Risk Level", str)
            ],
            self._generator()
        )