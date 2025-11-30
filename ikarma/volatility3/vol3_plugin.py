"""
iKARMA Volatility3 Plugin - DRIVER_OBJECT Enumeration

This is a proper Volatility3 plugin that extends PluginInterface
to enumerate DRIVER_OBJECT structures and extract MajorFunction tables.

The MajorFunction table contains runtime pointers that show what code
the kernel actually executes for each IRP type - this is the "source of truth"
for capability analysis and hook detection.
"""

import logging
from typing import List, Generator, Tuple, Optional, Dict, Any, Callable

logger = logging.getLogger(__name__)

# Volatility3 imports with comprehensive error handling
HAS_VOLATILITY = False
VOLATILITY_VERSION = None

try:
    import volatility3
    from volatility3.framework import interfaces, renderers, constants, exceptions
    from volatility3.framework.configuration import requirements
    from volatility3.framework.interfaces import plugins
    from volatility3.framework.renderers import format_hints
    from volatility3.framework.symbols import intermed
    from volatility3.framework.objects import utility
    from volatility3.plugins.windows import pslist, modules, driverscan
    
    HAS_VOLATILITY = True
    VOLATILITY_VERSION = getattr(volatility3, '__version__', 'unknown')
    logger.info(f"Volatility3 {VOLATILITY_VERSION} loaded successfully")
except ImportError as e:
    logger.warning(f"Volatility3 not available: {e}")
except Exception as e:
    logger.warning(f"Volatility3 initialization error: {e}")


# Windows structure constants
IRP_MJ_MAXIMUM_FUNCTION = 28

# MajorFunction names for reference
MAJOR_FUNCTION_NAMES = {
    0: "IRP_MJ_CREATE",
    1: "IRP_MJ_CREATE_NAMED_PIPE",
    2: "IRP_MJ_CLOSE",
    3: "IRP_MJ_READ",
    4: "IRP_MJ_WRITE",
    5: "IRP_MJ_QUERY_INFORMATION",
    6: "IRP_MJ_SET_INFORMATION",
    7: "IRP_MJ_QUERY_EA",
    8: "IRP_MJ_SET_EA",
    9: "IRP_MJ_FLUSH_BUFFERS",
    10: "IRP_MJ_QUERY_VOLUME_INFORMATION",
    11: "IRP_MJ_SET_VOLUME_INFORMATION",
    12: "IRP_MJ_DIRECTORY_CONTROL",
    13: "IRP_MJ_FILE_SYSTEM_CONTROL",
    14: "IRP_MJ_DEVICE_CONTROL",
    15: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    16: "IRP_MJ_SHUTDOWN",
    17: "IRP_MJ_LOCK_CONTROL",
    18: "IRP_MJ_CLEANUP",
    19: "IRP_MJ_CREATE_MAILSLOT",
    20: "IRP_MJ_QUERY_SECURITY",
    21: "IRP_MJ_SET_SECURITY",
    22: "IRP_MJ_POWER",
    23: "IRP_MJ_SYSTEM_CONTROL",
    24: "IRP_MJ_DEVICE_CHANGE",
    25: "IRP_MJ_QUERY_QUOTA",
    26: "IRP_MJ_SET_QUOTA",
    27: "IRP_MJ_PNP",
}


class DriverObjectInfo:
    """Container for DRIVER_OBJECT information."""
    
    def __init__(self):
        self.object_address: int = 0
        self.driver_start: int = 0
        self.driver_size: int = 0
        self.driver_name: str = ""
        self.driver_path: str = ""
        self.service_key: str = ""
        self.driver_init: int = 0
        self.driver_unload: int = 0
        self.device_object: int = 0
        self.major_functions: Dict[int, int] = {}
        self.found_in_list: bool = True


if HAS_VOLATILITY:
    
    class IKarmaDrivers(plugins.PluginInterface):
        """
        Volatility3 plugin to enumerate DRIVER_OBJECTs with MajorFunction tables.
        
        This plugin provides the "source of truth" for what code the kernel
        executes for each driver's IRP handlers.
        """
        
        _required_framework_version = (2, 0, 0)
        _version = (1, 0, 0)
        
        @classmethod
        def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
            """Define plugin requirements."""
            return [
                requirements.ModuleRequirement(
                    name='kernel',
                    description='Windows kernel module',
                    architectures=['Intel32', 'Intel64']
                ),
                requirements.PluginRequirement(
                    name='pslist',
                    plugin=pslist.PsList,
                    version=(2, 0, 0)
                ),
            ]
        
        def _generator(self) -> Generator[Tuple[int, Tuple], None, None]:
            """Generate DRIVER_OBJECT information."""
            
            kernel = self.context.modules[self.config['kernel']]
            layer_name = kernel.layer_name
            symbol_table = kernel.symbol_table_name
            
            # Get pointer size
            if self.context.symbol_space.get_type(
                symbol_table + constants.BANG + "pointer"
            ).size == 4:
                is_64bit = False
            else:
                is_64bit = True
            
            # Enumerate via driverscan
            try:
                scan_results = driverscan.DriverScan.scan_drivers(
                    self.context, layer_name, symbol_table
                )
                
                # Handle None return from scan_drivers
                if scan_results is None:
                    logger.debug("DriverScan.scan_drivers returned None")
                    return
                
                for driver_obj in scan_results:
                    try:
                        info = self._parse_driver_object(
                            driver_obj, layer_name, symbol_table, is_64bit
                        )
                        if info:
                            yield (0, (
                                format_hints.Hex(info.object_address),
                                format_hints.Hex(info.driver_start),
                                info.driver_size,
                                info.driver_name,
                                info.service_key,
                                format_hints.Hex(info.driver_init),
                                format_hints.Hex(info.driver_unload),
                                str(info.major_functions),
                            ))
                    except Exception as e:
                        logger.debug(f"Error parsing driver object: {e}")
                        continue
            except Exception as e:
                logger.error(f"Driver scan failed: {e}")
        
        def _parse_driver_object(
            self, driver_obj, layer_name: str, symbol_table: str, is_64bit: bool
        ) -> Optional[DriverObjectInfo]:
            """Parse a DRIVER_OBJECT structure."""
            
            info = DriverObjectInfo()
            
            try:
                info.object_address = driver_obj.vol.offset
                
                # Driver base and size
                if hasattr(driver_obj, 'DriverStart'):
                    info.driver_start = int(driver_obj.DriverStart)
                if hasattr(driver_obj, 'DriverSize'):
                    info.driver_size = int(driver_obj.DriverSize)
                
                # Driver name
                if hasattr(driver_obj, 'DriverName'):
                    try:
                        name_obj = driver_obj.DriverName
                        if hasattr(name_obj, 'String'):
                            info.driver_name = str(name_obj.String)
                        elif hasattr(name_obj, 'get_string'):
                            info.driver_name = name_obj.get_string()
                        else:
                            info.driver_name = str(name_obj)
                    except:
                        info.driver_name = "unknown"
                
                # Service key
                if hasattr(driver_obj, 'DriverExtension'):
                    try:
                        ext = driver_obj.DriverExtension
                        if hasattr(ext, 'ServiceKeyName'):
                            info.service_key = str(ext.ServiceKeyName.String)
                    except:
                        pass
                
                # Init and Unload routines
                if hasattr(driver_obj, 'DriverInit'):
                    info.driver_init = int(driver_obj.DriverInit)
                if hasattr(driver_obj, 'DriverUnload'):
                    info.driver_unload = int(driver_obj.DriverUnload)
                
                # Device object
                if hasattr(driver_obj, 'DeviceObject'):
                    try:
                        info.device_object = int(driver_obj.DeviceObject)
                    except:
                        pass
                
                # MajorFunction table - THE KEY DATA
                if hasattr(driver_obj, 'MajorFunction'):
                    try:
                        mf_array = driver_obj.MajorFunction
                        for i in range(IRP_MJ_MAXIMUM_FUNCTION):
                            try:
                                handler_addr = int(mf_array[i])
                                if handler_addr != 0:
                                    info.major_functions[i] = handler_addr
                            except:
                                continue
                    except Exception as e:
                        logger.debug(f"Error reading MajorFunction table: {e}")
                
                return info
                
            except Exception as e:
                logger.debug(f"Error parsing driver object at {hex(info.object_address)}: {e}")
                return None
        
        def run(self) -> renderers.TreeGrid:
            """Execute the plugin."""
            return renderers.TreeGrid(
                [
                    ("Object", format_hints.Hex),
                    ("Start", format_hints.Hex),
                    ("Size", int),
                    ("Name", str),
                    ("ServiceKey", str),
                    ("Init", format_hints.Hex),
                    ("Unload", format_hints.Hex),
                    ("MajorFunctions", str),
                ],
                self._generator()
            )


class VolatilityBridge:
    """
    Bridge class for interfacing with Volatility3.
    
    Provides a clean API for iKARMA to use Volatility3 functionality
    without exposing the complexity of the framework.
    """
    
    def __init__(self, memory_path: str):
        """Initialize the Volatility bridge."""
        self.memory_path = memory_path
        self.context = None
        self.kernel = None
        self.layer_name = None
        self.symbol_table = None
        self.is_initialized = False
        self.is_64bit = True
        self._error = None
    
    def initialize(self) -> bool:
        """Initialize Volatility3 context for the memory image."""
        if not HAS_VOLATILITY:
            self._error = "Volatility3 not available"
            return False
        
        try:
            import os
            from volatility3.framework import contexts, automagic
            from volatility3.plugins.windows import modules
            
            # Create context
            self.context = contexts.Context()
            
            # Build file URI
            file_path = os.path.abspath(self.memory_path)
            if os.name == 'nt':
                file_uri = 'file:///' + file_path.replace('\\', '/')
            else:
                file_uri = 'file://' + file_path
            
            # Configure location
            self.context.config['automagic.LayerStacker.single_location'] = file_uri
            
            # Get and run automagics
            available = automagic.available(self.context)
            automagics_list = automagic.choose_automagic(available, modules.Modules)
            
            if not automagics_list:
                self._error = "No suitable automagics found"
                return False
            
            # Run automagic
            errors = automagic.run(
                automagics_list,
                self.context,
                modules.Modules,
                'plugins.Modules',
                progress_callback=lambda *args: None
            )
            
            # Find kernel module
            for module_name in self.context.modules:
                module = self.context.modules[module_name]
                if hasattr(module, 'layer_name') and hasattr(module, 'symbol_table_name'):
                    self.kernel = module
                    self.layer_name = module.layer_name
                    self.symbol_table = module.symbol_table_name
                    break
            
            if not self.kernel:
                self._error = "Could not find kernel module"
                return False
            
            # Detect architecture
            try:
                ptr_type = self.context.symbol_space.get_type(
                    self.symbol_table + constants.BANG + "pointer"
                )
                self.is_64bit = ptr_type.size == 8
            except:
                self.is_64bit = True
            
            self.is_initialized = True
            logger.info(f"Volatility3 initialized - {'x64' if self.is_64bit else 'x86'}")
            return True
            
        except Exception as e:
            self._error = str(e)
            logger.error(f"Volatility3 initialization failed: {e}")
            return False
    
    def get_error(self) -> Optional[str]:
        """Get the last error message."""
        return self._error
    
    def enumerate_modules(self) -> List[Dict[str, Any]]:
        """
        Enumerate loaded modules via PsLoadedModuleList.

        Returns list of module info dicts.
        """
        if not self.is_initialized:
            return []

        modules_list = []

        try:
            from volatility3.plugins.windows import modules

            # Run modules plugin
            plugin_config = f"plugins.Modules"
            self.context.config[f'{plugin_config}.kernel'] = self.kernel.name

            plugin = modules.Modules(
                context=self.context,
                config_path=plugin_config
            )

            # Use the plugin's _generator() directly instead of populate()
            # This avoids the None return issue when populate() fails
            try:
                for level, values in plugin._generator():
                    try:
                        if len(values) >= 4:
                            modules_list.append({
                                'offset': int(values[0]) if values[0] else 0,
                                'base': int(values[1]) if values[1] else 0,
                                'size': int(values[2]) if values[2] else 0,
                                'name': str(values[3]) if values[3] else '',
                                'path': str(values[4]) if len(values) > 4 and values[4] else '',
                                'source': 'PsLoadedModuleList',
                            })
                    except Exception as e:
                        logger.debug(f"Error parsing module row: {e}")
                        continue
            except Exception as e:
                logger.debug(f"Error iterating modules generator: {e}")

        except Exception as e:
            logger.warning(f"Module enumeration failed: {e}")

        return modules_list
    
    def enumerate_drivers(self) -> List[DriverObjectInfo]:
        """
        Enumerate DRIVER_OBJECTs via pool scanning.

        Returns list of DriverObjectInfo with MajorFunction tables.
        """
        if not self.is_initialized:
            return []

        drivers = []

        try:
            from volatility3.plugins.windows import driverscan

            # Run driverscan
            plugin_config = f"plugins.DriverScan"
            self.context.config[f'{plugin_config}.kernel'] = self.kernel.name

            plugin = driverscan.DriverScan(
                context=self.context,
                config_path=plugin_config
            )

            # Use the plugin's _generator() directly instead of populate()
            # This avoids the None return issue when populate() fails
            try:
                for level, values in plugin._generator():
                    try:
                        if len(values) >= 6:
                            info = DriverObjectInfo()
                            info.object_address = int(values[0]) if values[0] else 0
                            info.driver_start = int(values[1]) if values[1] else 0
                            info.driver_size = int(values[2]) if values[2] else 0
                            info.service_key = str(values[3]) if values[3] else ''
                            info.driver_name = str(values[4]) if values[4] else ''

                            # Parse MajorFunction table from raw memory
                            if info.object_address:
                                mf_table = self._read_major_function_table(info.object_address)
                                info.major_functions = mf_table

                            drivers.append(info)
                    except Exception as e:
                        logger.debug(f"Error parsing driverscan row: {e}")
                        continue
            except Exception as e:
                logger.debug(f"Error iterating driverscan generator: {e}")

        except Exception as e:
            logger.warning(f"Driver scan failed: {e}")

        return drivers
    
    def enumerate_threads(self) -> List[Dict[str, Any]]:
        """
        Enumerate system threads.
        
        Returns list of thread info dicts.
        """
        if not self.is_initialized or not self.layer_name:
            return []
            
        threads = []
        
        try:
            from volatility3.plugins.windows import pslist
            
            # Use PsList.list_processes class method directly to avoid instance config issues
            # We don't need to instantiate the plugin if we just use the static/class method
            
            ethread_type = self.symbol_table + constants.BANG + "_ETHREAD"
            
            # Log layer name for debugging
            logger.debug(f"Enumerating threads using kernel module: {self.kernel.name}")
            
            # Use kernel_module_name instead of layer_name as per signature inspection
            # symbol_table is not a valid argument in this version
            for proc in pslist.PsList.list_processes(context=self.context, kernel_module_name=self.kernel.name):
                try:
                    # Filter for System process (PID 4)
                    if proc.UniqueProcessId != 4:
                        continue
                        
                    # Iterate threads
                    # Use the standard Volatility way to walk the list
                    for thread in proc.ThreadListHead.to_list(ethread_type, "ThreadListEntry"):
                        try:
                            tid = int(thread.Cid.UniqueThread)
                            start_addr = int(thread.StartAddress)
                            
                            # Win10+ might use Win32StartAddress
                            win32_start = 0
                            if hasattr(thread, 'Win32StartAddress'):
                                win32_start = int(thread.Win32StartAddress)
                                
                            threads.append({
                                'tid': tid,
                                'start_address': start_addr,
                                'win32_start_address': win32_start,
                                'process_id': 4,
                                'process_name': 'System'
                            })
                        except:
                            continue
                            
                except Exception as e:
                    logger.debug(f"Error processing process {proc.UniqueProcessId}: {e}")
                    continue
            
            logger.info(f"Enumerated {len(threads)} system threads")
            
        except Exception as e:
            logger.warning(f"Thread enumeration failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            
        return threads
    
    def resolve_symbol(self, symbol_name: str) -> Optional[int]:
        """
        Resolve a kernel symbol to an address.
        """
        if not self.is_initialized or not self.kernel:
            return None
            
        try:
            # Volatility3 symbols are usually accessed via context.symbol_space
            # Format: module!symbol
            full_name = self.symbol_table + constants.BANG + symbol_name
            
            # Get symbol address
            # This might return a Symbol object or address
            sym = self.context.symbol_space.get_symbol(full_name)
            if sym:
                return int(sym.address)
                
        except Exception as e:
            logger.debug(f"Symbol resolution failed for {symbol_name}: {e}")
            
        return None
    
    def _read_major_function_table(self, driver_object_addr: int) -> Dict[int, int]:
        """Read MajorFunction table from a DRIVER_OBJECT."""
        mf_table = {}
        
        try:
            layer = self.context.layers[self.layer_name]
            
            # MajorFunction offset in DRIVER_OBJECT
            # x64: offset 0x70, x86: offset 0x38
            mf_offset = 0x70 if self.is_64bit else 0x38
            ptr_size = 8 if self.is_64bit else 4
            
            mf_base = driver_object_addr + mf_offset
            
            for i in range(IRP_MJ_MAXIMUM_FUNCTION):
                try:
                    addr = mf_base + (i * ptr_size)
                    data = layer.read(addr, ptr_size, pad=True)
                    
                    if data:
                        if ptr_size == 8:
                            handler = int.from_bytes(data, 'little')
                        else:
                            handler = int.from_bytes(data, 'little')
                        
                        if handler != 0 and handler < 0xFFFFFFFFFFFFFFFF:
                            mf_table[i] = handler
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Error reading MajorFunction table: {e}")
        
        return mf_table
    
    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """Read memory from the dump."""
        if not self.is_initialized:
            return None
        
        try:
            layer = self.context.layers[self.layer_name]
            return layer.read(address, size, pad=True)
        except:
            return None
    
    def close(self):
        """Clean up resources."""
        self.context = None
        self.kernel = None
        self.is_initialized = False


def is_volatility_available() -> bool:
    """Check if Volatility3 is available."""
    return HAS_VOLATILITY


def get_volatility_version() -> Optional[str]:
    """Get Volatility3 version."""
    return VOLATILITY_VERSION
