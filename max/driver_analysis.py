"""
iKARMA Driver Analysis Plugin for Volatility3
Enumerates kernel drivers and finds IOCTL handlers (MVP Phase 1)

FIXED: Using correct DriverScan.scan_drivers() - it needs context + kernel_module_name
"""

import logging
from typing import List, Dict, Tuple, Optional

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

    # --- Scoring helpers -------------------------------------------------
    _SYSTEM_DRIVER_WHITELIST = {
        # Common Microsoft / known system drivers (normalized names, without .sys)
        "msrpc", "ksecdd", "werkernel", "clfs", "tm", "fltmgr", "clipsp",
        "cmimcext", "ntosext", "cng", "wdfldr", "acpiex", "mssecflt",
        "acpi", "wmilib", "intelpep", "pcw", "msisadrv", "pci", "vdrvroot",
        "pdc", "partmgr", "intelide", "pciidex", "volmgr", "volmgrx",
        "mountmgr", "atapi", "ataport", "ehstorclass", "fileinfo", "wof",
        "ntfs", "vboxguest", "ndis", "netio", "tcpip", "fvevol", "volume",
        "volsnap", "rdyboost", "mup", "disk", "win32k", "win32kfull",
        "win32kbase", "usb", "dxgkrnl", "kbdclass", "mouclass", "usbxhci",
        "http", "afd", "ndiswan", "storqosflt", "mrxsmb", "srvnet",
    }

    def _is_system_driver(self, normalized_name: str) -> bool:
        """Return True if driver is a common system driver (heuristic).

        normalized_name: driver name already lower-cased and without ".sys".
        """
        if not normalized_name:
            return False

        # Exact match
        if normalized_name in self._SYSTEM_DRIVER_WHITELIST:
            return True

        # Prefix matches for very common prefixes
        prefixes = ("microsoft", "win", "nt", "ms", "pci", "vbox", " VBox")
        for p in prefixes:
            if normalized_name.startswith(p):
                return True

        return False

    # Small database of expected sizes for some common system drivers (approximate)
    _EXPECTED_DRIVER_SIZES = {
        # name: expected_size (bytes) -- approximate reference values
        "tcpip": 0x2db000,
        "ntfs": 0x28d000,
        "ntoskrnl": 0x400000,
        "wdfldr": 0xd1000,
        "vboxguest": 0x5f000,
    }

    def _score_driver(self, normalized_name: str, analysis_result: str, ioctl_handler_display: str,
                      size: int, handler_addr: Optional[int] = None,
                      module_name: Optional[str] = None, driver_obj_name: Optional[str] = None,
                      module_ranges: Optional[List[Tuple[int, int, str]]] = None,
                      layer_name: Optional[str] = None) -> str:
        """Compute a simple, explainable risk score and label for a driver.

        Returns a compact string like: "Medium (45%)". Also logs reasons at debug level.
        """
        score = 0
        reasons = []

        # IOCTL surface
        if analysis_result == "Custom IOCTL":
            score += 40
            reasons.append("Custom IOCTL +40")
        elif analysis_result == "Generic IOCTL":
            score += 10
            reasons.append("Generic IOCTL +10")
        else:
            reasons.append("No handler +0")

        # Module size (complexity proxy)
        try:
            if size and size > 0x40000:
                score += 10
                reasons.append("Large module +10")
            elif size and size > 0x20000:
                score += 5
                reasons.append("Medium module +5")
        except Exception:
            pass

        # System driver reduction to lower false positives
        try:
            if self._is_system_driver(normalized_name):
                score -= 15
                reasons.append("Known system driver -15")
        except Exception:
            pass

        # Small heuristic: drivers that report a Generic handler outside module are less risky
        if isinstance(ioctl_handler_display, str) and ioctl_handler_display.startswith("Generic"):
            # already awarded Generic points above; slightly reduce risk
            score -= 3
            reasons.append("Generic handler outside module -3")

        # --- Phase 1.5: Anti-rename detection -------------------------------
        try:
            if driver_obj_name and module_name:
                # Normalize both
                obj_short = driver_obj_name.lower().split('\\')[-1].replace('.sys', '')
                mod_short = module_name.lower().replace('.sys', '').split('\\')[-1]

                if obj_short != mod_short:
                    # Names diverged; potential rename/spoof
                    score += 20
                    reasons.append("Name mismatch (renamed?) +20")

                    # If the driver was in the system whitelist, block applying whitelist reduction
                    if self._is_system_driver(obj_short):
                        reasons.append("Whitelist override due to mismatch")
        except Exception:
            pass

        # --- Size anomaly (compare expected sizes when available) ----------
        try:
            if normalized_name in self._EXPECTED_DRIVER_SIZES:
                expected = self._EXPECTED_DRIVER_SIZES[normalized_name]
                # Flag if differs by >30%
                if size and abs(size - expected) > (expected * 0.30):
                    score += 15
                    reasons.append("Size anomaly vs expected +15")
        except Exception:
            pass

        # --- Handler address anomaly: handler not inside any known module ---
        try:
            if handler_addr and module_ranges is not None:
                in_some_module = False
                for (mstart, mend, mname) in module_ranges:
                    if mstart <= handler_addr < mend:
                        in_some_module = True
                        break

                if not in_some_module:
                    # Handler points to unmapped or injected memory
                    score += 15
                    reasons.append("Handler in unexpected memory +15")
        except Exception:
            pass

        # --- Basic Capstone-based signals (optional) ------------------------
        try:
            if HAS_CAPSTONE and handler_addr and layer_name:
                # Attempt to read and disassemble a small window at handler_addr
                layer = self.context.layers[layer_name]
                max_read = 0x800
                raw = None
                try:
                    raw = layer.read(handler_addr, max_read, pad=True)
                except Exception:
                    raw = None

                if raw:
                    # Determine mode based on kernel architecture (assume 64-bit by default)
                    mode = capstone.CS_MODE_64
                    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
                    call_count = 0
                    rep_movs = 0
                    instr_count = 0
                    for ins in md.disasm(raw, handler_addr):
                        instr_count += 1
                        mnem = ins.mnemonic.lower()
                        op = ins.op_str.lower()
                        if mnem == 'call':
                            call_count += 1
                        if 'rep' in mnem or 'rep' in op or 'movs' in mnem or 'movs' in op:
                            rep_movs += 1

                    if call_count > 8:
                        score += 10
                        reasons.append(f"High call density +10 (calls={call_count})")
                    if rep_movs > 2:
                        score += 12
                        reasons.append(f"REP/MOV patterns +12 (rep_movs={rep_movs})")
        except Exception:
            pass

        # Normalize, clamp
        score = max(0, min(100, int(score)))

        # Label mapping
        if score < 30:
            label = "Low"
        elif score < 70:
            label = "Medium"
        else:
            label = "High"

        # Build final string and log debug explanation
        result_str = f"{label} ({score}%)"
        if self.config.get("debug", False):
            vollog.debug(f"Scoring: {normalized_name} -> {result_str}; reasons={reasons}")

        return result_str


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

            # Materialize module list and build quick module ranges for handler checks
            module_list = list(module_iterator)
            module_ranges: List[Tuple[int, int, str]] = []
            for m in module_list:
                try:
                    mstart = int(m.DllBase)
                    mend = mstart + int(m.SizeOfImage)
                    try:
                        mname = m.BaseDllName.get_string()
                    except Exception:
                        try:
                            mname = m.FullDllName.get_string()
                        except Exception:
                            mname = ""
                    module_ranges.append((mstart, mend, mname or ""))
                except Exception:
                    continue

            # Iterate through all kernel modules
            for mod in module_list:
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
                    ioctl_handler_display = "Not Found"

                    # Look up the DRIVER_OBJECT by normalized name
                    driver_obj = driver_object_map.get(driver_name_normalized)

                    # Prepare handler address placeholder
                    handler_int = None

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

                    # Determine DRIVER_OBJECT reported name (if available)
                    driver_obj_name = None
                    if driver_obj:
                        try:
                            driver_obj_name = driver_obj.DriverName.get_string()
                        except Exception:
                            driver_obj_name = None

                    # Compute risk level using the checklist/scorer (pass additional context)
                    try:
                        risk_level = self._score_driver(
                            driver_name_normalized,
                            analysis_result,
                            ioctl_handler_display,
                            size,
                            handler_addr=handler_int,
                            module_name=driver_name,
                            driver_obj_name=driver_obj_name,
                            module_ranges=module_ranges,
                            layer_name=kernel.layer_name,
                        )
                    except Exception:
                        risk_level = "N/A"

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