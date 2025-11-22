"""
iKARMA BYOVD Scanner Plugin for Volatility3
Fast triage of all kernel drivers for BYOVD (Bring Your Own Vulnerable Driver) indicators

This plugin:
1. Enumerates all kernel drivers (.sys files)
2. Extracts IOCTL handlers from DRIVER_OBJECT structures
3. Disassembles handlers and scans for dangerous API calls (Person 2's work)
4. Computes risk scores with explainable reasons (Person 3's work)
5. Supports JSON export for pipeline integration

Author: Person 1 (Team Lead) with Person 2 & 3 integration
Version: 2.0 (Advanced)
Last Updated: 2025-11-19
"""

import logging
import json
import sys
import os
from pathlib import Path
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

# Import iKARMA modules - they should be in the same directory
HAS_IKARMA_MODULES = False
HAS_FORENSIC_MODULES = False
find_dangerous_apis = None
calculate_driver_risk = None
ChainOfCustody = None
calculate_file_hashes = None

try:
    # Import from sibling directories (core/ and utils/ are in same parent as this file)
    ikarma_root = str(Path(__file__).parent)
    if ikarma_root not in sys.path:
        sys.path.insert(0, ikarma_root)

    from utils.api_scanner import find_dangerous_apis
    from core.risk_scorer import calculate_driver_risk
    HAS_IKARMA_MODULES = True

    # Import forensic compliance modules
    try:
        from core.chain_of_custody import ChainOfCustody, AnalystInfo
        from utils.forensic_integrity import calculate_file_hashes, verify_file_integrity
        HAS_FORENSIC_MODULES = True
    except Exception:
        HAS_FORENSIC_MODULES = False

except Exception as e:
    # Store error for debug output
    import_error = str(e)
    HAS_IKARMA_MODULES = False

vollog = logging.getLogger(__name__)


class BYOVDScanner(interfaces.plugins.PluginInterface):
    """
    iKARMA BYOVD Scanner - Fast Triage Plugin
    
    Scans all kernel drivers for BYOVD attack indicators:
    - Custom IOCTL handlers (attack surface)
    - Dangerous API calls (MmMapIoSpace, ZwMapViewOfSection, etc.)
    - Anti-rename detection (DKOM indicator)
    - Anomalous handler locations
    - Risk scoring with explainable reasons
    """

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

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
            ),
            requirements.StringRequirement(
                name="tier",
                description="Filter level: all, medium (40+), high (70+), critical (90+)",
                optional=True,
                default="all"
            ),
            requirements.StringRequirement(
                name="export-json",
                description="Export results to JSON file (provide path)",
                optional=True
            ),
            requirements.BooleanRequirement(
                name="detailed",
                description="Include detailed API findings in output",
                optional=True,
                default=False
            ),
            requirements.StringRequirement(
                name="coc-analyst",
                description="Analyst name for chain of custody (enables forensic mode)",
                optional=True
            ),
            requirements.StringRequirement(
                name="coc-analyst-id",
                description="Analyst ID for chain of custody",
                optional=True
            ),
            requirements.StringRequirement(
                name="coc-case-id",
                description="Case ID for chain of custody",
                optional=True
            ),
            requirements.StringRequirement(
                name="output-dir",
                description="Output directory for forensic reports (chain of custody JSON)",
                optional=True
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

    def _build_driver_object_map(self, debug_mode: bool) -> Dict[str, object]:
        """
        Build a mapping of driver names to DRIVER_OBJECT structures.
        
        Returns:
            Dict mapping normalized driver names (e.g., "ntfs") to DRIVER_OBJECT instances
        """
        driver_map = {}
        
        try:
            vollog.info("Scanning for DRIVER_OBJECTs with driverscan...")
            
            driver_obj_count = 0
            
            for driver_obj in driverscan.DriverScan.scan_drivers(
                self.context,
                self.config['kernel']
            ):
                driver_obj_count += 1
                try:
                    driver_name_full = driver_obj.DriverName.get_string()
                    
                    if debug_mode and driver_obj_count <= 10:
                        vollog.info(f"  DEBUG: DRIVER_OBJECT #{driver_obj_count}")
                        vollog.info(f"    Offset: {hex(driver_obj.vol.offset)}")
                        vollog.info(f"    DriverName (full): '{driver_name_full}'")
                    
                    # Extract the last component and normalize
                    if driver_name_full:
                        if '\\' in driver_name_full:
                            driver_name_short = driver_name_full.split('\\')[-1].lower()
                        else:
                            driver_name_short = driver_name_full.lower()
                        
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

    def _disassemble_handler(self, layer_name: str, address: int, size: int = 0x1000, 
                            max_instructions: int = 100) -> Optional[List[str]]:
        """
        Disassemble IOCTL handler code for API detection.
        
        Args:
            layer_name: Memory layer name
            address: Handler start address
            size: Bytes to read (default 4KB)
            max_instructions: Maximum instructions to disassemble
            
        Returns:
            List of disassembly strings or None if failed
        """
        if not HAS_CAPSTONE:
            return None
            
        try:
            layer = self.context.layers[layer_name]
            data = self._safe_read_memory(layer, address, size, pad=True)
            if data is None:
                return []
            
            # Try 64-bit disassembly
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            cs.detail = False
            
            instructions = []
            for i, ins in enumerate(cs.disasm(data, address)):
                instructions.append(f"{hex(ins.address)}:\t{ins.mnemonic}\t{ins.op_str}")
                if i + 1 >= max_instructions:
                    break
                    
            return instructions if instructions else None
            
        except Exception as e:
            if self.config.get("debug", False):
                vollog.debug(f"Disassembly failed at {hex(address)}: {e}")
            return None

    def _generator(self):
        """
        Main generator function that yields driver information.
        """
        driver_filter = self.config.get("drivers", None)
        debug_mode = self.config.get("debug", False)
        tier_mode = self.config.get("tier", "all").lower()
        detailed_mode = self.config.get("detailed", False)
        export_json_path = self.config.get("export-json", None)

        # Forensic Mode: Chain of Custody
        coc_analyst = self.config.get("coc-analyst", None)
        coc_analyst_id = self.config.get("coc-analyst-id", None)
        coc_case_id = self.config.get("coc-case-id", None)
        output_dir = self.config.get("output-dir", None)

        chain_of_custody = None
        forensic_mode = False

        if coc_analyst and HAS_FORENSIC_MODULES:
            forensic_mode = True
            try:
                analyst_info = AnalystInfo(
                    name=coc_analyst,
                    id=coc_analyst_id or "N/A",
                    organization=None,
                    certification=None
                )
                chain_of_custody = ChainOfCustody(
                    analyst=analyst_info,
                    case_id=coc_case_id or "N/A",
                    output_dir=output_dir or "."
                )
                # Start forensic session
                session_id = chain_of_custody.start_analysis(
                    evidence_file=f"Memory Dump (Volatility Context)",
                    evidence_hashes={},  # Memory dumps analyzed in-place
                    command_line=" ".join(sys.argv) if hasattr(sys, 'argv') else "N/A"
                )
                vollog.info("=" * 80)
                vollog.info("FORENSIC MODE ENABLED")
                vollog.info(f"Session ID: {session_id}")
                vollog.info(f"Analyst: {coc_analyst} ({coc_analyst_id})")
                vollog.info(f"Case ID: {coc_case_id or 'N/A'}")
                vollog.info("=" * 80)
                chain_of_custody.log_action(
                    "scan_start",
                    "Started BYOVD driver scan",
                    details={"tier_mode": tier_mode, "detailed": detailed_mode},
                    severity="info"
                )
            except Exception as e:
                vollog.warning(f"Chain of custody initialization failed: {e}")
                forensic_mode = False
        elif coc_analyst and not HAS_FORENSIC_MODULES:
            vollog.warning("Forensic mode requested but modules not available")
            vollog.warning("Install forensic modules: core/chain_of_custody.py")

        if debug_mode:
            vollog.setLevel(logging.DEBUG)
            vollog.info("=" * 80)
            vollog.info("DEBUG MODE ENABLED")
            vollog.info("=" * 80)

        vollog.info("=" * 80)
        vollog.info("iKARMA BYOVD Scanner v2.0 - Advanced Triage")
        vollog.info("=" * 80)
        
        if not HAS_CAPSTONE:
            vollog.warning("⚠ Capstone not available - disassembly disabled")
        
        if not HAS_IKARMA_MODULES:
            vollog.warning("⚠ iKARMA modules not available - using basic scoring")
            if debug_mode:
                vollog.warning(f"  Plugin directory: {Path(__file__).parent}")
                vollog.warning(f"  Import error: {globals().get('import_error', 'Unknown')}")
                vollog.warning(f"  Looking for: {Path(__file__).parent / 'utils' / 'api_scanner.py'}")
                vollog.warning(f"  File exists: {(Path(__file__).parent / 'utils' / 'api_scanner.py').exists()}")

        # JSON export accumulator
        json_results = []

        try:
            # Get the kernel module object
            kernel = self.context.modules[self.config['kernel']]
            vollog.info(f"✓ Kernel symbol table: {kernel.symbol_table_name}")
            vollog.info(f"✓ Layer name: {kernel.layer_name}")

            # Build the DRIVER_OBJECT map
            driver_object_map = self._build_driver_object_map(debug_mode)

            if not driver_object_map:
                vollog.warning("⚠ No DRIVER_OBJECTs found - IOCTL detection will fail")

            count = 0
            driver_count = 0
            sys_file_count = 0
            ioctl_found_count = 0
            ioctl_generic_count = 0
            api_detections = 0

            vollog.info("=" * 80)
            vollog.info("Enumerating loaded kernel modules...")
            vollog.info("=" * 80)
            
            module_iterator = modules.Modules.list_modules(
                self.context,
                self.config['kernel']
            )

            # Materialize module list and build module ranges for validation
            module_list = list(module_iterator)
            module_ranges: List[Tuple[int, int, str]] = []
            all_load_times: List[int] = []  # Collect all load times for temporal analysis
            
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
                    
                    # Collect load time for temporal analysis
                    try:
                        if hasattr(m, 'LoadTime'):
                            lt = m.LoadTime
                            if lt and lt > 0:
                                all_load_times.append(lt)
                    except (AttributeError, TypeError, exceptions.InvalidAddressException):
                        pass
                except Exception:
                    continue
            
            if debug_mode:
                vollog.info(f"Collected {len(all_load_times)} load times for temporal analysis")

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
                    except (AttributeError, exceptions.InvalidAddressException):
                        try:
                            driver_name = mod.FullDllName.get_string()
                        except (AttributeError, exceptions.InvalidAddressException):
                            continue

                    if not driver_name:
                        continue
                    
                    # Extract load time (if available)
                    load_time = None
                    load_time_str = "Unknown"
                    try:
                        # Try to get LoadTime from _LDR_DATA_TABLE_ENTRY
                        if hasattr(mod, 'LoadTime'):
                            load_time = mod.LoadTime
                            # Convert Windows FILETIME to readable format
                            if load_time and load_time != 0:
                                import datetime
                                # Windows FILETIME: 100-nanosecond intervals since 1601-01-01
                                timestamp = (load_time - 116444736000000000) / 10000000
                                load_time_dt = datetime.datetime.utcfromtimestamp(timestamp)
                                load_time_str = load_time_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                        
                        if debug_mode and driver_count <= 5:
                            vollog.info(f"  Load time: {load_time_str}")
                    except Exception as e:
                        if debug_mode:
                            vollog.debug(f"  Could not extract load time: {e}")

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

                    # Default values
                    analysis_result = "Enumerated"
                    ioctl_handler_display = "Not Found"
                    handler_int = None
                    found_apis = []

                    # Look up the DRIVER_OBJECT by normalized name
                    driver_obj = driver_object_map.get(driver_name_normalized)

                    if driver_obj:
                        if debug_mode and driver_count <= 10:
                            vollog.info(f"  ✓ Matched DRIVER_OBJECT at {hex(driver_obj.vol.offset)}")
                        
                        # Extract IOCTL handler (MajorFunction[0x0E])
                        IRP_MJ_DEVICE_CONTROL = 0x0E
                        
                        try:
                            handler_ptr = driver_obj.MajorFunction[IRP_MJ_DEVICE_CONTROL]
                            
                            # Convert to integer
                            try:
                                handler_int = int(handler_ptr)
                            except (TypeError, ValueError, AttributeError):
                                try:
                                    handler_int = int(handler_ptr.dereference())
                                except (TypeError, ValueError, AttributeError, exceptions.InvalidAddressException):
                                    handler_int = 0

                            if debug_mode and driver_count <= 10:
                                vollog.info(f"  Handler pointer value: {hex(handler_int) if handler_int else 'NULL'}")

                            if handler_int and handler_int != 0:
                                # Check if handler is inside the driver's image
                                if base_addr <= handler_int < (base_addr + size):
                                    ioctl_handler_display = hex(handler_int)
                                    analysis_result = "Custom IOCTL"
                                    ioctl_found_count += 1
                                    
                                    # 🔥 INTEGRATION: Disassemble and scan for APIs (Person 2's work)
                                    if HAS_CAPSTONE and HAS_IKARMA_MODULES:
                                        disasm = self._disassemble_handler(kernel.layer_name, handler_int)
                                        if disasm:
                                            found_apis = find_dangerous_apis(disasm)
                                            if found_apis:
                                                api_detections += 1
                                                if debug_mode:
                                                    vollog.info(f"  🎯 Detected {len(found_apis)} dangerous APIs")
                                    
                                    vollog.info(f"✓ [{driver_count}] {driver_name}: Custom IOCTL at {hex(handler_int)}")
                                else:
                                    # Handler is outside driver (generic/shared handler)
                                    ioctl_handler_display = f"Generic ({hex(handler_int)})"
                                    analysis_result = "Generic IOCTL"
                                    ioctl_generic_count += 1
                                
                        except Exception as e:
                            if debug_mode:
                                vollog.error(f"  Error reading MajorFunction: {e}")
                            ioctl_handler_display = "Error"

                    # Get DRIVER_OBJECT reported name (for anti-rename detection)
                    driver_obj_name = None
                    if driver_obj:
                        try:
                            driver_obj_name = driver_obj.DriverName.get_string()
                        except Exception:
                            pass

                    # 🔥 INTEGRATION: Compute risk score (Person 3's work)
                    try:
                        if HAS_IKARMA_MODULES:
                            risk_result = calculate_driver_risk(
                                normalized_name=driver_name_normalized,
                                analysis_result=analysis_result,
                                ioctl_handler_display=ioctl_handler_display,
                                size=size,
                                handler_addr=handler_int,
                                module_name=driver_name,
                                driver_obj_name=driver_obj_name,
                                module_ranges=module_ranges,
                                found_apis=found_apis,
                                disasm_lines=disasm,  # Pass pre-disassembled lines
                                context_layers=self.context.layers,  # Pass layer dict for Capstone
                                layer_name=kernel.layer_name,  # Pass layer name
                                load_time=load_time,  # 🆕 TEMPORAL: Driver load timestamp
                                all_load_times=all_load_times  # 🆕 TEMPORAL: All driver load times for comparison
                            )
                            risk_level = risk_result['level']
                            score_details = risk_result['reasons']
                            score_num = risk_result['score']
                            confidence = risk_result.get('confidence', 0.0)
                            confidence_reasons = risk_result.get('confidence_reasons', '')
                        else:
                            # Fallback basic scoring
                            score_num = 40 if analysis_result == "Custom IOCTL" else 10 if analysis_result == "Generic IOCTL" else 0
                            risk_level = "High" if score_num >= 70 else "Medium" if score_num >= 30 else "Low"
                            score_details = f"{analysis_result}"
                            confidence = 0.5
                            confidence_reasons = "Basic scoring (no iKARMA modules)"
                    except Exception as e:
                        if debug_mode:
                            vollog.error(f"Risk scoring failed: {e}")
                        risk_level = "N/A"
                        score_details = ""
                        score_num = 0
                        confidence = 0.0
                        confidence_reasons = "Scoring error"

                    # FILTER 3: Tier-based filtering
                    if tier_mode == "critical" and score_num < 90:
                        continue
                    elif tier_mode == "high" and score_num < 70:
                        continue
                    elif tier_mode == "medium" and score_num < 40:
                        continue
                    # "all" shows everything

                    # Format output fields
                    
                    # Risk display: "High (75)"
                    risk_display = f"{risk_level} ({score_num})"
                    
                    # Confidence display: "87%" or "N/A"
                    confidence_display = f"{int(confidence * 100)}%" if confidence > 0 else "N/A"
                    
                    # APIs display: "3 APIs" or specific names in detailed mode
                    if found_apis:
                        if detailed_mode:
                            api_names = [api['name'] for api in found_apis[:2]]
                            apis_display = ', '.join(api_names)
                            if len(found_apis) > 2:
                                apis_display += f" (+{len(found_apis)-2})"
                        else:
                            apis_display = f"{len(found_apis)} APIs"
                    else:
                        apis_display = "-"
                    
                    # Evidence: Shortened reasons (max 80 chars for readability)
                    evidence = score_details[:80] + "..." if len(score_details) > 80 else score_details

                    # JSON export accumulation
                    if export_json_path:
                        json_results.append({
                            'base_address': hex(base_addr),
                            'driver_name': driver_name,
                            'size': size,
                            'ioctl_handler': ioctl_handler_display,
                            'analysis': analysis_result,
                            'score': score_num,
                            'risk_level': risk_level,
                            'confidence': confidence,
                            'score_details': score_details,
                            'found_apis': found_apis if found_apis else []
                        })

                    # Yield result with new column order
                    yield (
                        0,
                        (
                            driver_name,
                            risk_display,
                            confidence_display,
                            apis_display,
                            ioctl_handler_display,
                            format_hints.Hex(base_addr),
                            evidence
                        )
                    )

                except Exception as e:
                    vollog.error(f"Error processing module: {e}")
                    if debug_mode:
                        import traceback
                        vollog.error(traceback.format_exc())
                    continue

            vollog.info("=" * 80)
            vollog.info("SCAN COMPLETE")
            vollog.info("=" * 80)
            vollog.info(f"Total modules processed: {count}")
            vollog.info(f".sys files found: {sys_file_count}")
            vollog.info(f"Drivers analyzed: {driver_count}")
            vollog.info(f"Custom IOCTL handlers: {ioctl_found_count}")
            vollog.info(f"Generic IOCTL handlers: {ioctl_generic_count}")
            if HAS_IKARMA_MODULES:
                vollog.info(f"Drivers with dangerous APIs: {api_detections}")
            if driver_count > 0:
                detection_rate = (ioctl_found_count + ioctl_generic_count) * 100 // driver_count
                vollog.info(f"Detection rate: {ioctl_found_count + ioctl_generic_count}/{driver_count} ({detection_rate}%)")
            vollog.info("=" * 80)

            # Export to JSON if requested
            if export_json_path and json_results:
                try:
                    with open(export_json_path, 'w') as f:
                        json.dump({
                            'scan_summary': {
                                'total_modules': count,
                                'sys_files': sys_file_count,
                                'drivers_analyzed': driver_count,
                                'custom_ioctl': ioctl_found_count,
                                'generic_ioctl': ioctl_generic_count,
                                'api_detections': api_detections
                            },
                            'drivers': json_results
                        }, f, indent=2)
                    vollog.info(f"✓ Results exported to: {export_json_path}")
                    if forensic_mode and chain_of_custody:
                        chain_of_custody.log_action(
                            "json_export",
                            f"Exported results to JSON: {export_json_path}",
                            details={"file_path": export_json_path},
                            severity="info"
                        )
                except Exception as e:
                    vollog.error(f"JSON export failed: {e}")
                    if forensic_mode and chain_of_custody:
                        chain_of_custody.log_action(
                            "json_export_error",
                            f"JSON export failed: {e}",
                            details={"error": str(e)},
                            severity="error"
                        )

            # Finalize chain of custody
            if forensic_mode and chain_of_custody:
                results_summary = {
                    'total_modules': count,
                    'drivers_analyzed': driver_count,
                    'custom_ioctl': ioctl_found_count,
                    'api_detections': api_detections,
                    'high_risk_drivers': sum(1 for d in json_results if d.get('risk_score', 0) >= 70)
                }
                coc_path = chain_of_custody.complete_analysis(
                    results_summary=results_summary,
                    status="completed"
                )
                vollog.info("=" * 80)
                vollog.info(f"FORENSIC CHAIN OF CUSTODY: {coc_path}")
                vollog.info("=" * 80)

        except Exception as e:
            # Log error to chain of custody before re-raising
            if forensic_mode and chain_of_custody:
                chain_of_custody.log_action(
                    "fatal_error",
                    f"Fatal error during analysis: {e}",
                    details={"error": str(e), "traceback": str(traceback.format_exc())},
                    severity="critical"
                )
                chain_of_custody.complete_analysis(status="error")

            vollog.error(f"FATAL ERROR: {e}")
            import traceback
            vollog.error(traceback.format_exc())
            raise

    def run(self):
        """Entry point for the plugin."""
        return renderers.TreeGrid(
            [
                ("Driver Name", str),
                ("Risk", str),  # Combines level + score
                ("Confidence", str),  # Percentage
                ("APIs", str),  # Count or names
                ("IOCTL Handler", str),
                ("Base Address", format_hints.Hex),
                ("Evidence", str)  # Shortened reasons
            ],
            self._generator()
        )
