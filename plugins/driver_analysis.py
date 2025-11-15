"""
iKARMA Driver Analysis Plugin for Volatility3
Enumerates kernel drivers and finds IOCTL handlers (MVP Phase 1)

FIXED: Using correct DriverScan.scan_drivers() - it needs context + kernel_module_name
"""

import logging
from typing import List, Dict

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import modules, driverscan

vollog = logging.getLogger(__name__)


class DriverAnalysis(interfaces.plugins.PluginInterface):
    """
    iKARMA Driver Analysis Plugin

    Phase 1 (MVP): Enumerate all kernel drivers (.sys files) from memory
    and extract IOCTL handler addresses from their DRIVER_OBJECT structures
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

    def _build_driver_object_map(self, debug_mode: bool) -> Dict[str, object]:
        """
        Build a mapping of driver names to DRIVER_OBJECT structures.
        
        Returns:
            Dict mapping normalized driver names (e.g., "ntfs") to DRIVER_OBJECT instances
        """
        driver_map = {}
        
        try:
            vollog.info("Scanning for DRIVER_OBJECTs with driverscan...")
            
            # CORRECT API: scan_drivers(context, kernel_module_name)
            # The kernel_module_name is the STRING "kernel" from our config
            # NOT the kernel object itself!
            driver_obj_count = 0
            
            for driver_obj in driverscan.DriverScan.scan_drivers(
                self.context,
                self.config['kernel']  # This is the string "kernel", same as modules.list_modules
            ):
                driver_obj_count += 1
                try:
                    # Get the driver name from the DRIVER_OBJECT.DriverName UNICODE_STRING
                    driver_name_full = driver_obj.DriverName.get_string()
                    
                    if debug_mode and driver_obj_count <= 10:
                        vollog.info(f"  DEBUG: DRIVER_OBJECT #{driver_obj_count}")
                        vollog.info(f"    Offset: {hex(driver_obj.vol.offset)}")
                        vollog.info(f"    DriverName (full): '{driver_name_full}'")
                        try:
                            vollog.info(f"    DriverStart: {hex(driver_obj.DriverStart)}")
                        except:
                            vollog.info(f"    DriverStart: <unavailable>")
                    
                    # Driver names in DRIVER_OBJECT are like "\\Driver\\Ntfs" or "\\FileSystem\\Npfs"
                    # Extract the last component and normalize
                    if driver_name_full:
                        if '\\' in driver_name_full:
                            driver_name_short = driver_name_full.split('\\')[-1].lower()
                        else:
                            driver_name_short = driver_name_full.lower()
                        
                        # Store the mapping
                        driver_map[driver_name_short] = driver_obj
                        
                        if debug_mode and driver_obj_count <= 10:
                            vollog.info(f"    Normalized name: '{driver_name_short}'")
                    
                except Exception as e:
                    if debug_mode:
                        vollog.debug(f"  Error reading DRIVER_OBJECT #{driver_obj_count}: {e}")
                    continue
            
            vollog.info(f"✓ Scanned {driver_obj_count} DRIVER_OBJECTs")
            vollog.info(f"✓ Successfully mapped {len(driver_map)} driver names")
            
            if debug_mode:
                vollog.info(f"  DEBUG: First 20 mapped names: {list(driver_map.keys())[:20]}")
            
        except Exception as e:
            vollog.warning(f"driverscan failed: {e}")
            if debug_mode:
                import traceback
                vollog.error(traceback.format_exc())
        
        return driver_map

    def _generator(self):
        """
        Main generator function that yields driver information.
        """
        driver_filter = self.config.get("drivers", None)
        debug_mode = self.config.get("debug", False)

        if debug_mode:
            vollog.setLevel(logging.DEBUG)
            vollog.info("=" * 80)
            vollog.info("DEBUG MODE ENABLED")
            vollog.info("=" * 80)

        vollog.info("=" * 80)
        vollog.info("iKARMA Driver Analysis - MVP Phase 1")
        vollog.info("=" * 80)
        try:
            import capstone
        except Exception:
            capstone = None

        try:
            # Get the kernel module object
            kernel = self.context.modules[self.config['kernel']]
            vollog.info(f"✓ Kernel symbol table: {kernel.symbol_table_name}")
            vollog.info(f"✓ Layer name: {kernel.layer_name}")

            # Build the DRIVER_OBJECT map
            driver_object_map = self._build_driver_object_map(debug_mode)

            if not driver_object_map:
                vollog.warning("⚠ No DRIVER_OBJECTs found - IOCTL detection will fail")
                vollog.warning("  This may indicate an issue with symbol resolution")

            count = 0
            driver_count = 0
            sys_file_count = 0
            ioctl_found_count = 0
            ioctl_generic_count = 0

            vollog.info("=" * 80)
            vollog.info("Enumerating loaded kernel modules...")
            vollog.info("=" * 80)
            
            module_iterator = modules.Modules.list_modules(
                self.context,
                self.config['kernel']
            )

            # Iterate through all kernel modules
            for mod in module_iterator:
                count += 1

                try:
                    # Extract basic module information
                    base_addr = int(mod.DllBase)
                    size = int(mod.SizeOfImage)

                    # Get the module name
                    driver_name = None
                    try:
                        driver_name = mod.BaseDllName.get_string()
                    except:
                        try:
                            driver_name = mod.FullDllName.get_string()
                        except:
                            continue

                    if not driver_name:
                        continue

                    # FILTER 1: Only .sys files (kernel drivers)
                    if not driver_name.lower().endswith('.sys'):
                        continue
                    
                    sys_file_count += 1

                    # FILTER 2: Apply user-specified filter
                    if driver_filter:
                        if not any(filt.lower() in driver_name.lower() for filt in driver_filter):
                            continue

                    driver_count += 1

                    # Normalize driver name for lookup (remove .sys extension)
                    driver_name_normalized = driver_name.lower().replace('.sys', '')
                    
                    if debug_mode and driver_count <= 10:
                        vollog.info("")
                        vollog.info(f"=" * 70)
                        vollog.info(f"[{driver_count}] MODULE: {driver_name}")
                        vollog.info(f"  Base: {hex(base_addr)}, Size: {hex(size)}")
                        vollog.info(f"  Lookup key: '{driver_name_normalized}'")

                    # Default values
                    analysis_result = "Enumerated"
                    risk_level = "N/A"
                    ioctl_handler_display = "Not Found"

                    # Look up the DRIVER_OBJECT by normalized name
                    driver_obj = driver_object_map.get(driver_name_normalized)

                    if driver_obj:
                        if debug_mode and driver_count <= 10:
                            vollog.info(f"  ✓ Matched DRIVER_OBJECT at {hex(driver_obj.vol.offset)}")
                        
                        # Extract IOCTL handler (MajorFunction[0x0E])
                        IRP_MJ_DEVICE_CONTROL = 0x0E
                        
                        try:
                            # MajorFunction is an array of function pointers
                            handler_ptr = driver_obj.MajorFunction[IRP_MJ_DEVICE_CONTROL]
                            
                            # Convert to integer
                            handler_int = None
                            try:
                                handler_int = int(handler_ptr)
                            except:
                                try:
                                    handler_int = int(handler_ptr.dereference())
                                except:
                                    handler_int = 0

                            if debug_mode and driver_count <= 10:
                                vollog.info(f"  Handler pointer value: {hex(handler_int) if handler_int else 'NULL'}")

                            if handler_int and handler_int != 0:
                                # Check if handler is inside the driver's image
                                if base_addr <= handler_int < (base_addr + size):
                                    ioctl_handler_display = hex(handler_int)
                                    analysis_result = "Custom IOCTL"
                                    ioctl_found_count += 1
                                    vollog.info(f"✓ [{driver_count}] {driver_name}: Custom IOCTL at {hex(handler_int)}")
                                else:
                                    # Handler is outside driver (generic/shared handler)
                                    ioctl_handler_display = f"Generic ({hex(handler_int)})"
                                    analysis_result = "Generic IOCTL"
                                    ioctl_generic_count += 1
                                    if debug_mode and driver_count <= 10:
                                        vollog.info(f"  Generic handler at {hex(handler_int)} (outside module range)")
                            else:
                                if debug_mode and driver_count <= 10:
                                    vollog.info(f"  Handler pointer is null/invalid")
                                
                        except Exception as e:
                            if debug_mode:
                                vollog.error(f"  Error reading MajorFunction: {e}")
                            ioctl_handler_display = "Error"
                    else:
                        if debug_mode and driver_count <= 10:
                            vollog.info(f"  ✗ No DRIVER_OBJECT match for '{driver_name_normalized}'")

                    # Yield result
                    yield (
                        0,
                        (
                            format_hints.Hex(base_addr),
                            driver_name,
                            format_hints.Hex(size),
                            ioctl_handler_display,
                            analysis_result,
                            risk_level
                        )
                    )

                except Exception as e:
                    vollog.error(f"Error processing module: {e}")
                    if debug_mode:
                        import traceback
                        vollog.error(traceback.format_exc())
                    continue

            vollog.info("=" * 80)
            vollog.info("ENUMERATION COMPLETE")
            vollog.info("=" * 80)
            vollog.info(f"Total modules processed: {count}")
            vollog.info(f".sys files found: {sys_file_count}")
            vollog.info(f"Drivers analyzed: {driver_count}")
            vollog.info(f"Custom IOCTL handlers: {ioctl_found_count}")
            vollog.info(f"Generic IOCTL handlers: {ioctl_generic_count}")
            if driver_count > 0:
                detection_rate = (ioctl_found_count + ioctl_generic_count) * 100 // driver_count
                vollog.info(f"Detection rate: {ioctl_found_count + ioctl_generic_count}/{driver_count} ({detection_rate}%)")
            vollog.info("=" * 80)

        except Exception as e:
            vollog.error(f"FATAL ERROR: {e}")
            import traceback
            vollog.error(traceback.format_exc())
            raise

    def disassemble_function(self, layer_name: str, address: int, size: int = 0x1000, max_instructions: int = 30):
        """
        Read memory from the given layer and address, then disassemble using Capstone.

        Returns a list of human-readable instruction strings (up to max_instructions).
        If Capstone is not available, returns None.
        """
        try:
            # Local import so plugin still loads if capstone is missing
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        except Exception:
            vollog.warning("Capstone not available: disassembly will be skipped")
            return None

        try:
            layer = self.context.layers[layer_name]
            data = layer.read(address, size, pad=True)
        except Exception as e:
            vollog.error(f"Failed to read memory at {hex(address)}: {e}")
            return None

        # Try 64-bit first, fall back to 32-bit if needed
        instructions = []
        for mode in (CS_MODE_64, ):  # keep single-mode to reduce false assumptions; expand later if needed
            try:
                cs = Cs(CS_ARCH_X86, mode)
                cs.detail = False
                for i, ins in enumerate(cs.disasm(data, address)):
                    instructions.append(f"{hex(ins.address)}:\t{ins.mnemonic}\t{ins.op_str}")
                    if i + 1 >= max_instructions:
                        break
                if instructions:
                    return instructions
            except Exception:
                continue

        # If we reach here, disassembly failed or returned nothing
        return None

    def analyze_for_apis(self, disassembly_lines):
        """
        Placeholder that will call the API scanner module. For now returns an empty list.

        Expected input: list of disassembled instruction strings.
        Expected output: list of found API descriptors (name, address, reason)
        """
        # Future: from utils.api_scanner import find_dangerous_apis
        # return find_dangerous_apis(disassembly_lines)
        return []

    def calculate_risk(self, found_apis_list):
        """
        Placeholder risk calculation function.

        Expected input: list returned from analyze_for_apis
        Expected output: dict with keys: score (int), level (str), reasons (list)
        """
        # Future: from core.risk_scorer import calculate_risk
        # return calculate_risk(found_apis_list)
        return {"score": 0, "level": "N/A", "reasons": []}

    def run(self):
        """Entry point for the plugin."""
        return renderers.TreeGrid(
            [
                ("Base Address", format_hints.Hex),
                ("Driver Name", str),
                ("Size (bytes)", format_hints.Hex),
                ("IOCTL Handler", str),
                ("Analysis", str),
                ("Risk Level", str)
            ],
            self._generator()
        )