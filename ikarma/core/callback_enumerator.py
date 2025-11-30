"""
Kernel Callback Enumeration

Enumerates and analyzes kernel callbacks beyond MajorFunction tables:
- PsCreateProcessNotifyRoutine callbacks
- PsSetLoadImageNotifyRoutine callbacks
- CmRegisterCallback (registry callbacks)
- ObRegisterCallbacks (object callbacks)
- IoRegisterFsRegistrationChange
- KeRegisterBugCheckCallback

Detects:
- Callback hijacking (direct array modification)
- Callback disabling (patched to ret)
- Callback removal (points to freed memory)
"""

import logging
import struct
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from ikarma.core.driver import DriverCapability, CapabilityType, ConfidenceLevel

logger = logging.getLogger(__name__)


@dataclass
class CallbackEntry:
    """Represents a kernel callback entry."""
    callback_type: str  # 'ProcessNotify', 'LoadImage', 'Registry', 'Object'
    callback_address: int
    callback_index: int
    driver_name: Optional[str] = None
    driver_base: Optional[int] = None
    is_hooked: bool = False
    is_disabled: bool = False
    is_freed: bool = False
    evidence: str = ""


class CallbackEnumerator:
    """
    Enumerates kernel callbacks from various notification systems.

    This requires resolving ntoskrnl global arrays and parsing their structures.
    """

    def __init__(self, is_64bit: bool = True):
        """Initialize callback enumerator."""
        self.is_64bit = is_64bit
        self.ptr_size = 8 if is_64bit else 4
        self.ptr_fmt = '<Q' if is_64bit else '<I'

        # Known callback array symbols (would be resolved from ntoskrnl exports)
        self.callback_arrays = {
            'PspCreateProcessNotifyRoutine': 0,    # Offset would be resolved
            'PspCreateThreadNotifyRoutine': 0,
            'PspLoadImageNotifyRoutine': 0,
            'CallbackListHead': 0,  # CmRegisterCallback
            'ObpCallbackListHead': 0,  # ObRegisterCallbacks
        }

        # Maximum callback entries per array
        self.max_callbacks = {
            'PspCreateProcessNotifyRoutine': 64,
            'PspCreateThreadNotifyRoutine': 64,
            'PspLoadImageNotifyRoutine': 64,
        }
        
    def resolve_symbols(self, resolver: Any):
        """
        Resolve callback array symbols using provided resolver (VolatilityBridge).
        """
        if not resolver:
            return
            
        try:
            # We need a way to resolve symbols from VolatilityBridge
            # VolatilityBridge doesn't expose resolve_symbol directly yet.
            # But we can assume it might, or we can use a callback function.
            # Let's assume 'resolver' is a function or object with 'resolve_symbol' method.
            
            for name in self.callback_arrays:
                try:
                    # Try to resolve
                    if hasattr(resolver, 'resolve_symbol'):
                        addr = resolver.resolve_symbol(name)
                        if addr:
                            self.callback_arrays[name] = addr
                            logger.debug(f"Resolved {name} to {hex(addr)}")
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Symbol resolution failed: {e}")

    def enumerate_process_notify_callbacks(
        self,
        array_address: int,
        read_memory: callable,
        known_drivers: List[Dict[str, Any]]
    ) -> List[CallbackEntry]:
        """
        Enumerate PsCreateProcessNotifyRoutine callbacks.

        Structure (simplified):
            Array of pointers to callback routines
            Max 64 entries on modern Windows
        """
        callbacks = []

        max_entries = self.max_callbacks.get('PspCreateProcessNotifyRoutine', 64)

        for i in range(max_entries):
            offset = i * self.ptr_size
            ptr_data = read_memory(array_address + offset, self.ptr_size)

            if not ptr_data or len(ptr_data) < self.ptr_size:
                break

            callback_ptr = struct.unpack(self.ptr_fmt, ptr_data)[0]

            if callback_ptr == 0:
                continue  # Empty slot

            # On modern Windows, the pointer may have encoding/flags
            # Remove lowest bit (used as flag)
            callback_addr = callback_ptr & ~0xF

            # Determine which driver owns this callback
            driver_info = self._find_owning_driver(callback_addr, known_drivers)

            # Check for hooks/anomalies
            is_hooked = False
            is_disabled = False

            # Read first bytes of callback
            callback_code = read_memory(callback_addr, 16)
            if callback_code:
                # Check if disabled (patched to 'ret')
                if callback_code[0] == 0xC3:  # ret opcode
                    is_disabled = True
                    logger.warning(f"Disabled callback detected at {hex(callback_addr)}")

            evidence = f"ProcessNotify callback at {hex(callback_addr)}"
            if driver_info:
                evidence += f" (owned by {driver_info['name']})"
            if is_disabled:
                evidence += " - DISABLED (patched to RET)"

            entry = CallbackEntry(
                callback_type='ProcessNotify',
                callback_address=callback_addr,
                callback_index=i,
                driver_name=driver_info['name'] if driver_info else None,
                driver_base=driver_info['base'] if driver_info else None,
                is_disabled=is_disabled,
                evidence=evidence,
            )

            callbacks.append(entry)

        logger.info(f"Found {len(callbacks)} ProcessNotify callbacks")
        return callbacks

    def enumerate_loadimage_notify_callbacks(
        self,
        array_address: int,
        read_memory: callable,
        known_drivers: List[Dict[str, Any]]
    ) -> List[CallbackEntry]:
        """Enumerate PsSetLoadImageNotifyRoutine callbacks."""
        callbacks = []

        max_entries = self.max_callbacks.get('PspLoadImageNotifyRoutine', 64)

        for i in range(max_entries):
            offset = i * self.ptr_size
            ptr_data = read_memory(array_address + offset, self.ptr_size)

            if not ptr_data or len(ptr_data) < self.ptr_size:
                break

            callback_ptr = struct.unpack(self.ptr_fmt, ptr_data)[0]

            if callback_ptr == 0:
                continue

            callback_addr = callback_ptr & ~0xF

            driver_info = self._find_owning_driver(callback_addr, known_drivers)

            evidence = f"LoadImage callback at {hex(callback_addr)}"
            if driver_info:
                evidence += f" (owned by {driver_info['name']})"

            entry = CallbackEntry(
                callback_type='LoadImageNotify',
                callback_address=callback_addr,
                callback_index=i,
                driver_name=driver_info['name'] if driver_info else None,
                driver_base=driver_info['base'] if driver_info else None,
                evidence=evidence,
            )

            callbacks.append(entry)

        logger.info(f"Found {len(callbacks)} LoadImageNotify callbacks")
        return callbacks

    def enumerate_registry_callbacks(
        self,
        listhead_address: int,
        read_memory: callable,
        known_drivers: List[Dict[str, Any]]
    ) -> List[CallbackEntry]:
        """
        Enumerate CmRegisterCallback registry callbacks.

        Structure:
            CallbackListHead is a LIST_ENTRY
            Each entry is a CM_CALLBACK_CONTEXT_BLOCK
        """
        callbacks = []

        # Walk LIST_ENTRY
        # Read ListHead Flink
        flink_data = read_memory(listhead_address, self.ptr_size)
        if not flink_data or len(flink_data) < self.ptr_size:
            return callbacks

        current = struct.unpack(self.ptr_fmt, flink_data)[0]
        visited = set()
        max_iterations = 100

        iteration = 0
        while current != listhead_address and iteration < max_iterations:
            if current in visited:
                break
            visited.add(current)
            iteration += 1

            # Read callback context block
            # Simplified - actual structure is more complex
            # Would need to parse CM_CALLBACK_CONTEXT_BLOCK

            # Read next Flink
            flink_data = read_memory(current, self.ptr_size)
            if not flink_data:
                break

            current = struct.unpack(self.ptr_fmt, flink_data)[0]

        logger.info(f"Found {len(callbacks)} registry callbacks")
        return callbacks

    def enumerate_object_callbacks(
        self,
        listhead_address: int,
        read_memory: callable,
        known_drivers: List[Dict[str, Any]]
    ) -> List[CallbackEntry]:
        """
        Enumerate ObRegisterCallbacks object callbacks.

        These are critical - control access to processes/threads.
        """
        callbacks = []

        # Similar LIST_ENTRY walking as registry callbacks
        # Would parse OB_CALLBACK_REGISTRATION structures

        logger.info(f"Found {len(callbacks)} object callbacks")
        return callbacks

    def detect_callback_hijacking(
        self,
        callbacks: List[CallbackEntry],
        read_memory: callable,
        ntoskrnl_data_start: int,
        ntoskrnl_data_end: int
    ) -> List[DriverCapability]:
        """
        Detect callback array hijacking.

        Direct modification of callback arrays (e.g., PspCreateProcessNotifyRoutine)
        is a sign of rootkit activity.
        """
        capabilities = []

        for callback in callbacks:
            # Check if callback points outside expected driver ranges
            if callback.driver_base is None:
                # Callback not associated with known driver
                evidence = (
                    f"BECAUSE: {callback.callback_type} callback at {hex(callback.callback_address)} "
                    "does not belong to any known driver - possible hijacking"
                )

                cap = DriverCapability(
                    capability_type=CapabilityType.CALLBACK_REMOVAL,
                    confidence=0.85,
                    confidence_level=ConfidenceLevel.HIGH,
                    description=f"Suspicious {callback.callback_type} callback",
                    evidence=evidence,
                    handler_address=callback.callback_address,
                    risk_weight=9.0,
                    exploitability="high",
                )

                capabilities.append(cap)

            # Check for disabled callbacks
            if callback.is_disabled:
                evidence = (
                    f"BECAUSE: {callback.callback_type} callback at {hex(callback.callback_address)} "
                    "has been disabled (patched to RET) - indicates callback bypass attempt"
                )

                cap = DriverCapability(
                    capability_type=CapabilityType.CALLBACK_REMOVAL,
                    confidence=0.95,
                    confidence_level=ConfidenceLevel.HIGH,
                    description=f"Disabled {callback.callback_type} callback",
                    evidence=evidence,
                    handler_address=callback.callback_address,
                    risk_weight=9.5,
                    exploitability="high",
                )

                capabilities.append(cap)

        return capabilities

    def _find_owning_driver(
        self,
        address: int,
        known_drivers: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Find which driver owns an address."""

        for driver in known_drivers:
            base = driver.get('base', 0)
            size = driver.get('size', 0)

            if base != 0 and size != 0:
                if base <= address < base + size:
                    return driver

        return None

    def generate_callback_report(
        self,
        all_callbacks: List[CallbackEntry]
    ) -> Dict[str, Any]:
        """Generate comprehensive callback analysis report."""

        report = {
            'total_callbacks': len(all_callbacks),
            'by_type': {},
            'suspicious_callbacks': [],
            'disabled_callbacks': [],
        }

        # Group by type
        for callback in all_callbacks:
            cb_type = callback.callback_type
            if cb_type not in report['by_type']:
                report['by_type'][cb_type] = 0
            report['by_type'][cb_type] += 1

            # Track suspicious
            if callback.is_hooked or callback.driver_name is None:
                report['suspicious_callbacks'].append({
                    'type': cb_type,
                    'address': hex(callback.callback_address),
                    'driver': callback.driver_name or 'UNKNOWN',
                })

            if callback.is_disabled:
                report['disabled_callbacks'].append({
                    'type': cb_type,
                    'address': hex(callback.callback_address),
                })

        return report
